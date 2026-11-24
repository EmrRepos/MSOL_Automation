import hashlib
import json
import struct
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone

from core.cip import parse_rr_data
from core.connection import EIPConnection, EncapsulationStatus
from core.session import SessionManager
from modules.discovery import validate_target


FUZZ_CASES = (
    ('FUZ-01', 'CIP class boundary', bytes.fromhex('0e042100ffff24013001')),
    ('FUZ-02', 'CIP instance boundary', bytes.fromhex('0e0420012500ffff3001')),
    ('FUZ-03', 'CIP attribute boundary', bytes.fromhex('0e04200124013100ffff')),
    ('FUZ-04', 'CIP path length mismatch', bytes.fromhex('0e04200124013001')),
)


class FuzzStopped(Exception):
    pass


class FuzzTestRunner:
    def __init__(self, timeout: float = 3.0) -> None:
        if not 0.2 <= timeout <= 5.0:
            raise ValueError('Timeout must be between 0.2 and 5 seconds.')
        self.timeout = timeout

    def run(self, target: str, operator: str, authorized: bool = False,
            cancel: threading.Event | None = None, *, fuzz_authorized: bool = False,
            progress: Callable[[str], None] | None = None, case_id: str | None = None,
            case_ids: tuple[str, ...] | None = None) -> dict:
        target = validate_target(target)
        if not authorized or not fuzz_authorized or not operator.strip():
            raise ValueError('Fuzz tests require separate fuzz authorization and an operator/scope reference.')
        if case_id is not None and case_ids is not None:
            raise ValueError('Specify either case_id or case_ids, not both.')
        selected = (case_id,) if case_id is not None else case_ids
        if selected is not None:
            valid = {identifier for identifier, _, _ in FUZZ_CASES}
            if not selected or len(set(selected)) != len(selected) or not set(selected).issubset(valid):
                raise ValueError('Select one or more distinct executable fuzz tests.')
        selected_set = set(selected) if selected is not None else None
        if len(FUZZ_CASES) + 2 > 30:
            raise ValueError('Fuzz suite exceeds the 30-request limit including session setup and cleanup.')
        cancel = cancel if cancel is not None else threading.Event()
        started = time.monotonic()
        deadline = started + 60.0
        connection = EIPConnection(target, self.timeout)
        session = SessionManager(connection)
        results = [{'id': identifier, 'title': title, 'status': 'not_run',
                    'detail': 'Not reached.', 'exchange_indices': []}
                   for identifier, title, _ in FUZZ_CASES]
        run = {
            'suite': 'bounded-cip-fuzz-v1', 'target': target, 'operator': operator.strip(),
            'authorization_attested': True, 'fuzz_authorization_attested': True,
            'selected_case': selected[0] if selected and len(selected) == 1 else None,
            'selected_cases': list(selected) if selected is not None else None,
            'started_at_utc': datetime.now(timezone.utc).isoformat(),
            'outcome': 'completed', 'stop_reason': None,
            'limits': {'max_requests': 30, 'max_sessions': 1, 'max_payload_bytes': 16384,
                       'request_timeout_seconds': self.timeout, 'minimum_request_interval_seconds': 1.0,
                       'work_budget_seconds': 60, 'cleanup_send_budget_seconds': self.timeout,
                       'automatic_retries': 0},
        }
        last_request = None

        def before_request() -> None:
            if cancel.is_set():
                raise FuzzStopped('Cancelled by operator; no further test requests sent.')
            now = time.monotonic()
            delay = 0 if last_request is None else max(0.0, 1.0 - (now - last_request))
            if now + delay >= deadline:
                raise FuzzStopped('60-second work budget reached.')
            if delay and cancel.wait(delay):
                raise FuzzStopped('Cancelled by operator; no further test requests sent.')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FuzzStopped('60-second work budget reached.')
            connection.timeout = min(self.timeout, remaining)

        try:
            if cancel.is_set():
                raise FuzzStopped('Cancelled before connecting.')
            with connection:
                try:
                    before_request()
                    if progress:
                        progress('Registering session for fuzz tests.')
                    try:
                        session.register()
                    finally:
                        last_request = time.monotonic()
                    for result, (_, _, request) in zip(results, FUZZ_CASES):
                        if selected_set is not None and result['id'] not in selected_set:
                            continue
                        before_request()
                        if progress:
                            progress(f"{result['id']}: starting {result['title']}")
                        index = len(connection.exchanges)
                        try:
                            payload = struct.pack('<IHHHHHH', 0, 0, 2, 0, 0, 0x00B2, len(request)) + request
                            _, response = connection.exchange(0x006F, payload, session.handle)
                            cip = parse_rr_data(response)
                            result.update(
                                status='observed',
                                detail='Response observed; compare status and device behavior with its specification.',
                                general_status=f'0x{cip.general_status:02X}',
                                additional_status=list(cip.additional_status), data_hex=cip.data.hex(),
                            )
                        except EncapsulationStatus as exc:
                            result.update(status='inconclusive', detail=str(exc))
                            raise FuzzStopped('Encapsulation rejection; subsequent cases stopped.') from exc
                        except OSError as exc:
                            result.update(status='inconclusive', detail=str(exc))
                            raise
                        except ValueError as exc:
                            result.update(status='inconclusive' if connection.broken else 'protocol_anomaly',
                                          detail=str(exc))
                            raise
                        finally:
                            last_request = time.monotonic()
                            result['exchange_indices'] = list(range(index, len(connection.exchanges)))
                            if progress:
                                progress(f"{result['id']}: {result['status']} - {result['detail']}")
                    if cancel.is_set():
                        raise FuzzStopped('Cancelled by operator; no further test requests sent.')
                finally:
                    if session.handle and not connection.broken:
                        if progress:
                            progress('Attempting session cleanup.')
                        if last_request is not None:
                            threading.Event().wait(max(0.0, 1.0 - (time.monotonic() - last_request)))
                        connection.timeout = self.timeout
                        try:
                            session.close()
                        except (OSError, ValueError) as exc:
                            run['outcome'] = 'incomplete'
                            run['stop_reason'] = f'Cleanup send failed: {exc}'
        except (FuzzStopped, OSError, ValueError) as exc:
            run['outcome'] = 'cancelled' if cancel.is_set() else 'incomplete'
            run['stop_reason'] = str(exc)
        for result in results:
            if result['status'] == 'not_run':
                result['detail'] = ('Not selected for this run.' if selected_set is not None and result['id'] not in selected_set else
                                    run['stop_reason'] or 'Dependency unavailable or no session was established.')
        evidence = connection.exchanges
        run.update(completed_at_utc=datetime.now(timezone.utc).isoformat(),
                   elapsed_ms=round((time.monotonic() - started) * 1000, 3),
                   identities=[], attribute_values={}, test_results=results, consistency_observations=[],
                   exchanges=evidence,
                   evidence_sha256=hashlib.sha256(json.dumps(evidence, sort_keys=True).encode('utf-8')).hexdigest())
        return run
