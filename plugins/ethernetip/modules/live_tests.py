import hashlib
import json
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import asdict
from datetime import datetime, timezone

from core.cip import CIPClient, decode_identity_attribute
from core.connection import EIPConnection, EncapsulationStatus, ProtocolError
from core.session import SessionManager
from modules.discovery import parse_identity_payload, validate_target
from modules.fuzz_tests import FUZZ_CASES, FuzzTestRunner
from modules.test_plan import baseline_coverage


ATTRIBUTE_NAMES = {1: 'vendor_id', 2: 'device_type', 3: 'product_code', 4: 'revision',
                   5: 'status', 6: 'serial_number', 7: 'product_name'}
LIVE_CASES = (
    ('ENIP-01', 'ListIdentity framing and metadata'),
    ('ENIP-02', 'ListServices response structure'),
    ('ENIP-03', 'ListInterfaces response structure'),
    ('ENIP-04', 'RegisterSession version, options and handle'),
    *((f'CIP-{attribute:02}', f'Identity instance 1 / {name}') for attribute, name in ATTRIBUTE_NAMES.items()),
    ('ENIP-05', 'UnregisterSession send and local socket cleanup'),
)
COVERAGE_GAPS = (
    ('UDP discovery and implicit I/O', 'not_implemented', 'Requires approved UDP/peer-specific tests.'),
    ('Connected messaging and ForwardOpen', 'not_implemented', 'Requires device ownership and connection policy.'),
    ('Routed CIP and backplane paths', 'not_implemented', 'Requires explicit approved routes and device profile.'),
    ('Vendor objects, tags and assemblies', 'requires_device_profile', 'Requires EDS/vendor service documentation.'),
    ('Authorization and negative-access assertions', 'requires_device_profile', 'Requires expected ACLs and approved client identities.'),
    ('CIP Security TLS/DTLS and certificates', 'manual_review', 'No secure transport handshake is implemented.'),
    ('Write, reset, controller mode and firmware services', 'excluded', 'Can change physical process state.'),
    ('Additional fuzzing and resource exhaustion', 'not_implemented', 'Only the separately enabled bounded CIP fuzz cases are implemented; flooding is excluded.'),
    ('CIP Safety, Motion, Sync and other profiles', 'not_implemented', 'Requires applicable device/profile specifications.'),
    ('CVE applicability and firmware matching', 'manual_review', 'Identity revision is not sufficient evidence.'),
)


class RunStopped(Exception):
    pass


def coverage_matrix() -> list[dict]:
    matrix = ([{'id': identifier, 'area': title, 'coverage': 'implemented_live_read_only',
               'limits': 'Observation or protocol anomaly, not a vulnerability/conformance verdict.'}
              for identifier, title in LIVE_CASES]
              + [{'id': identifier, 'area': title, 'coverage': 'implemented_live_fuzz',
                  'limits': 'Separate opt-in fuzz suite; a response is not a security verdict.'}
                 for identifier, title, _ in FUZZ_CASES]
              + [{'id': f'GAP-{index:02}', 'area': area, 'coverage': coverage, 'limits': limits}
                 for index, (area, coverage, limits) in enumerate(COVERAGE_GAPS, 1)])
    matrix.extend(baseline_coverage())
    return matrix


def parse_discovery_items(payload: bytes, services: bool = False) -> list[dict]:
    if len(payload) < 2:
        raise ProtocolError('Missing discovery item count.')
    count = struct.unpack_from('<H', payload)[0]
    offset = 2
    result = []
    for _ in range(count):
        if offset + 4 > len(payload):
            raise ProtocolError('Truncated discovery item header.')
        item_type, size = struct.unpack_from('<HH', payload, offset)
        offset += 4
        if offset + size > len(payload):
            raise ProtocolError('Truncated discovery item data.')
        data = payload[offset:offset + size]
        offset += size
        item = {'type': item_type, 'data_hex': data.hex()}
        if services and item_type == 0x0100:
            if len(data) != 20:
                raise ProtocolError('ListServices item length is not 20 bytes.')
            version, flags = struct.unpack_from('<HH', data)
            item.update(version=version, capability_flags=flags,
                        name=data[4:].split(b'\x00', 1)[0].decode('ascii', errors='replace'))
        result.append(item)
    if offset != len(payload):
        raise ProtocolError('Unexpected trailing discovery data.')
    return result


class LiveTestRunner:
    def __init__(self, timeout: float = 3.0) -> None:
        if not 0.2 <= timeout <= 5.0:
            raise ValueError('Timeout must be between 0.2 and 5 seconds.')
        self.timeout = timeout

    def run(self, target: str, operator: str, authorized: bool = False,
            cancel: threading.Event | None = None, *,
            progress: Callable[[str], None] | None = None, case_id: str | None = None,
            case_ids: tuple[str, ...] | None = None) -> dict:
        target = validate_target(target)
        if not authorized or not operator.strip():
            raise ValueError('Live tests require authorization and an operator/scope reference.')
        if case_id is not None and case_ids is not None:
            raise ValueError('Specify either case_id or case_ids, not both.')
        selected = (case_id,) if case_id is not None else case_ids
        if selected is not None:
            valid = {identifier for identifier, _ in LIVE_CASES}
            if not selected or len(set(selected)) != len(selected) or not set(selected).issubset(valid):
                raise ValueError('Select one or more distinct executable live tests.')
        selected_set = set(selected) if selected is not None else None
        needs_session = selected_set is None or any(
            identifier.startswith('CIP-') or identifier in ('ENIP-04', 'ENIP-05') for identifier in selected_set)
        planned_cases = (selected_set | {'ENIP-04', 'ENIP-05'} if needs_session else selected_set) if selected_set else None
        cancel = cancel if cancel is not None else threading.Event()
        started = time.monotonic()
        deadline = started + 30.0
        connection = EIPConnection(target, self.timeout)
        results = {identifier: {'id': identifier, 'title': title, 'status': 'not_run',
                                'detail': 'Not reached.', 'exchange_indices': []}
                   for identifier, title in LIVE_CASES}
        identities = []
        attribute_values = {}
        consistency = []
        session = SessionManager(connection)
        run = {'suite': 'bounded-identity-baseline-v1', 'target': target, 'operator': operator.strip(),
               'authorization_attested': True, 'started_at_utc': datetime.now(timezone.utc).isoformat(),
               'selected_case': selected[0] if selected and len(selected) == 1 else None,
               'selected_cases': list(selected) if selected is not None else None,
               'supporting_cases': sorted(planned_cases - selected_set) if planned_cases and selected_set else [],
               'outcome': 'completed', 'stop_reason': None,
               'limits': {'max_requests': 12, 'max_sessions': 1, 'max_payload_bytes': 16384,
                          'request_timeout_seconds': self.timeout,
                          'minimum_request_interval_seconds': 0.25, 'work_budget_seconds': 30,
                          'cleanup_send_budget_seconds': self.timeout, 'automatic_retries': 0}}
        last_request = None

        def before_request():
            nonlocal last_request
            if cancel.is_set():
                raise RunStopped('Cancelled by operator; no further test requests sent.')
            now = time.monotonic()
            delay = 0 if last_request is None else max(0.0, 0.25 - (now - last_request))
            if now + delay >= deadline:
                raise RunStopped('30-second work budget reached.')
            if delay and cancel.wait(delay):
                raise RunStopped('Cancelled by operator; no further test requests sent.')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RunStopped('30-second work budget reached.')
            connection.timeout = min(self.timeout, remaining)
            last_request = time.monotonic()

        def execute(identifier, operation):
            before_request()
            result = results[identifier]
            if progress:
                progress(f"{identifier}: starting {result['title']}")
            index = len(connection.exchanges)
            try:
                value = operation()
                result.update(status='observed', detail='Valid response observed; no security verdict.')
                return value
            except EncapsulationStatus as exc:
                result.update(status='unsupported' if exc.status == 1 else 'inconclusive', detail=str(exc))
                if exc.status != 1:
                    raise
            except OSError as exc:
                result.update(status='inconclusive', detail=str(exc))
                raise
            except ValueError as exc:
                result.update(status='protocol_anomaly', detail=str(exc))
                raise
            finally:
                result['exchange_indices'] = list(range(index, len(connection.exchanges)))
                if progress:
                    progress(f"{identifier}: request finished; see final result for classification.")

        try:
            if cancel.is_set():
                raise RunStopped('Cancelled before connecting.')
            with connection:
                try:
                    def identity_read():
                        _, payload = connection.exchange(0x0063)
                        return parse_identity_payload(payload)
                    if selected_set is None or 'ENIP-01' in selected_set:
                        identities = execute('ENIP-01', identity_read) or []
                        if results['ENIP-01']['status'] == 'observed' and not identities:
                            results['ENIP-01'].update(status='inconclusive', detail='No identity items returned.')
                    for identifier, command, services in (('ENIP-02', 0x0004, True), ('ENIP-03', 0x0064, False)):
                        if selected_set is not None and identifier not in selected_set:
                            continue
                        def discovery_read(command=command, services=services):
                            _, payload = connection.exchange(command)
                            return parse_discovery_items(payload, services)
                        items = execute(identifier, discovery_read)
                        if items is not None:
                            results[identifier]['items'] = items
                    handle = execute('ENIP-04', session.register) if needs_session else None
                    if handle:
                        client = CIPClient(session)
                        for attribute, name in ATTRIBUTE_NAMES.items():
                            identifier = f'CIP-{attribute:02}'
                            if selected_set is not None and identifier not in selected_set:
                                continue
                            decoded = {}
                            def cip_read(attribute=attribute):
                                response = client.read_identity_attribute(attribute)
                                if response.general_status == 0:
                                    decoded['value'] = decode_identity_attribute(attribute, response.data)
                                return response
                            response = execute(identifier, cip_read)
                            if response is None:
                                continue
                            result = results[identifier]
                            result.update(general_status=f'0x{response.general_status:02X}',
                                          additional_status=list(response.additional_status), data_hex=response.data.hex())
                            if response.general_status:
                                status = ('access_denied' if response.general_status == 0x0F else
                                          'unsupported' if response.general_status in (0x05, 0x08, 0x14, 0x16) else 'inconclusive')
                                result.update(status=status, detail='CIP rejection observed; check vendor policy and status definition.')
                            else:
                                result['value'] = decoded['value']
                                attribute_values[name] = decoded['value']
                finally:
                    if session.handle and not connection.broken:
                        result = results['ENIP-05']
                        if progress:
                            progress('ENIP-05: attempting session cleanup.')
                        index = len(connection.exchanges)
                        try:
                            if last_request is not None:
                                threading.Event().wait(max(0.0, 0.25 - (time.monotonic() - last_request)))
                            connection.timeout = self.timeout
                            session.close()
                            result.update(status='observed', detail='UnregisterSession sent; no reply is specified. '
                                          'Local socket closure does not prove remote session deletion.')
                        except (OSError, ValueError) as exc:
                            result.update(status='inconclusive', detail=f'Cleanup send failed: {exc}')
                        finally:
                            result['exchange_indices'] = list(range(index, len(connection.exchanges)))
        except (RunStopped, OSError, ValueError) as exc:
            run['outcome'] = 'cancelled' if cancel.is_set() else 'incomplete'
            run['stop_reason'] = str(exc)
        if selected_set and run['outcome'] == 'completed' and any(
            results[identifier]['status'] == 'not_run' for identifier in selected_set
        ):
            run['outcome'] = 'incomplete'
            run['stop_reason'] = 'Selected test was not run; a required session was unavailable.'
        for result in results.values():
            if result['status'] == 'not_run':
                result['detail'] = ('Not selected for this run.' if planned_cases and result['id'] not in planned_cases else
                                    run['stop_reason'] or 'Dependency unavailable or no session was established.')
            if progress:
                progress(f"{result['id']}: {result['status']} - {result['detail']}")
        if len(identities) == 1:
            identity_values = asdict(identities[0])
            for name, value in attribute_values.items():
                if name == 'status':
                    continue
                if identity_values[name] != value:
                    consistency.append({'field': name, 'list_identity_value': identity_values[name], 'cip_value': value,
                                        'classification': 'Needs developer review; a gateway or changing state may explain differences.'})
        evidence = connection.exchanges
        run.update(completed_at_utc=datetime.now(timezone.utc).isoformat(),
                   elapsed_ms=round((time.monotonic() - started) * 1000, 3),
                   identities=[asdict(identity) for identity in identities], attribute_values=attribute_values,
                   test_results=list(results.values()), consistency_observations=consistency,
                   exchanges=evidence, coverage=coverage_matrix(),
                   evidence_sha256=hashlib.sha256(json.dumps(evidence, sort_keys=True).encode('utf-8')).hexdigest())
        return run


class SelectedTestRunner:
    def __init__(self, timeout: float = 3.0) -> None:
        if not 0.2 <= timeout <= 5.0:
            raise ValueError('Timeout must be between 0.2 and 5 seconds.')
        self.timeout = timeout

    def run(self, target: str, operator: str, authorized: bool, case_ids: tuple[str, ...],
            cancel: threading.Event | None = None, *, fuzz_authorized: bool = False,
            progress: Callable[[str], None] | None = None) -> dict:
        target = validate_target(target)
        if not authorized or not operator.strip():
            raise ValueError('Selected tests require authorization and an operator/scope reference.')
        live_ids = {identifier for identifier, _ in LIVE_CASES}
        fuzz_ids = {identifier for identifier, _, _ in FUZZ_CASES}
        if not case_ids or len(set(case_ids)) != len(case_ids) or not set(case_ids).issubset(live_ids | fuzz_ids):
            raise ValueError('Select one or more distinct executable tests.')
        live = tuple(identifier for identifier in case_ids if identifier in live_ids)
        fuzz = tuple(identifier for identifier in case_ids if identifier in fuzz_ids)
        if fuzz and not fuzz_authorized:
            raise ValueError('Selected fuzz tests require separate fuzz authorization.')
        cancel = cancel if cancel is not None else threading.Event()
        if not fuzz:
            return LiveTestRunner(self.timeout).run(target, operator, authorized, cancel,
                                                     progress=progress, case_ids=live)
        if not live:
            return FuzzTestRunner(self.timeout).run(target, operator, authorized, cancel,
                                                     fuzz_authorized=True, progress=progress, case_ids=fuzz)

        started = time.monotonic()
        baseline = LiveTestRunner(self.timeout).run(target, operator, authorized, cancel,
                                                     progress=progress, case_ids=live)
        cleanup = next(result for result in baseline['test_results'] if result['id'] == 'ENIP-05')
        outcome = baseline['outcome']
        stop_reason = baseline['stop_reason']
        if outcome == 'completed' and cleanup['status'] == 'inconclusive':
            outcome = 'incomplete'
            stop_reason = 'Baseline session cleanup failed; fuzz tests were not started.'
        fuzz_run = None
        if outcome == 'completed':
            if progress:
                progress('Waiting one second before the separately authorized fuzz phase.')
            if cancel.wait(1.0) or cancel.is_set():
                outcome = 'cancelled'
                stop_reason = 'Cancelled before the fuzz phase.'
            else:
                fuzz_run = FuzzTestRunner(self.timeout).run(target, operator, authorized, cancel,
                                                            fuzz_authorized=True, progress=progress, case_ids=fuzz)
                outcome = fuzz_run['outcome']
                stop_reason = fuzz_run['stop_reason']
        offset = len(baseline['exchanges'])
        if fuzz_run:
            fuzz_results = [{**result, 'exchange_indices': [index + offset for index in result['exchange_indices']]}
                            for result in fuzz_run['test_results']]
            exchanges = baseline['exchanges'] + fuzz_run['exchanges']
        else:
            fuzz_results = [{'id': identifier, 'title': title, 'status': 'not_run',
                             'detail': ('Fuzz phase not started: ' + (stop_reason or 'baseline incomplete')
                                        if identifier in fuzz else 'Not selected for this run.'),
                             'exchange_indices': []}
                            for identifier, title, _ in FUZZ_CASES]
            exchanges = baseline['exchanges']
        return {
            'suite': 'bounded-selected-mixed-v1', 'target': target, 'operator': operator.strip(),
            'authorization_attested': True, 'fuzz_authorization_attested': True,
            'selected_case': None, 'selected_cases': list(case_ids),
            'supporting_cases': baseline['supporting_cases'],
            'started_at_utc': baseline['started_at_utc'],
            'completed_at_utc': datetime.now(timezone.utc).isoformat(),
            'elapsed_ms': round((time.monotonic() - started) * 1000, 3),
            'outcome': outcome, 'stop_reason': stop_reason,
            'limits': {'max_requests': 42, 'max_sessions': 2, 'request_timeout_seconds': self.timeout,
                       'baseline': baseline['limits'], 'fuzz': fuzz_run['limits'] if fuzz_run else None},
            'identities': baseline['identities'], 'attribute_values': baseline['attribute_values'],
            'test_results': baseline['test_results'] + fuzz_results,
            'consistency_observations': baseline['consistency_observations'], 'exchanges': exchanges,
            'coverage': coverage_matrix(),
            'evidence_sha256': hashlib.sha256(json.dumps(exchanges, sort_keys=True).encode('utf-8')).hexdigest(),
        }