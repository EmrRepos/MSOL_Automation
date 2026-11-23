"""Local, passive USBPcap analysis. Observations are not exploit verification."""

import hashlib
import os
import re
import struct
from collections import OrderedDict
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from core.firmware_capture import SNAPLEN


class AnalysisError(Exception):
    pass


class AnalysisCancelled(AnalysisError):
    pass


LIMITATIONS = (
    "Whole-hub scope: bus/address labels do not establish device identity. "
    "Addresses can change or be reused after reboot.",
    "Passive observations cannot prove authentication bypass, replay acceptance, "
    "missing firmware signature checks, downgrade acceptance or update success.",
    "No firmware/HART decoding, decryption or cross-packet message reassembly. "
    "Split, encoded, binary or encrypted credentials may not be detected.",
    "Payload rules inspect successful bulk/interrupt OUT submissions and IN completions, "
    "and control DATA-stage records only. Other control/isochronous data is not scanned.",
    "Readable text and identical payloads are observations, not proof of insecure firmware "
    "or replay. USBPcap submission/completion pairs are not independent transfers.",
    "No driver-drop statistics are available. Absence of findings is not a security pass.",
    "Credential values and raw payloads are omitted from reports. Packet hashes, offsets "
    "and frame numbers refer to the original capture; protect that file.",
)

CREDENTIAL_PATTERN = re.compile(
    rb"\b(password|passwd|pwd|api[_-]?key|access[_-]?token|secret|token)"
    rb"""["']?\s*[:=]\s*["']?([!-~]{4,256})""", re.IGNORECASE,
)
AUTH_PATTERN = re.compile(
    rb"\bauthorization\s*:\s*(basic|bearer)\s+([A-Za-z0-9._~+/=-]{4,256})",
    re.IGNORECASE,
)
TEXT_PATTERN = re.compile(rb"[\x20-\x7e]{16,}")


@dataclass(frozen=True)
class PacketEvidence:
    frame: int
    timestamp: str
    file_offset: int
    packet_sha256: str
    payload_sha256: str
    payload_length: int
    urb_id: str
    phase: str
    direction: str
    transfer_type: str
    note: str


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    verification: str
    bus: int | None
    address: int | None
    endpoint: int | None
    explanation: str
    recommendation: str
    occurrences: int = 0
    evidence: list[PacketEvidence] = field(default_factory=list)


@dataclass
class AnalysisResult:
    source: str
    sha256: str = ""
    analyzed_at: str = ""
    packets: int = 0
    payload_records_scanned: int = 0
    payload_bytes_scanned: int = 0
    skipped_payload_records: int = 0
    truncated_records: int = 0
    malformed_records: int = 0
    devices: set[tuple[int, int]] = field(default_factory=set)
    findings: list[Finding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=lambda: list(LIMITATIONS))


def analyze_capture(
    path: str,
    cancelled: Callable[[], bool] = lambda: False,
    progress: Callable[[int], None] = lambda _value: None,
) -> AnalysisResult:
    """Stream classic USBPcap PCAP with bounded finding and repeat-tracking memory."""
    source = Path(path).resolve()
    if not source.is_file():
        raise AnalysisError("Choose an existing, completed PCAP file.")
    result = AnalysisResult(str(source))
    digest = hashlib.sha256()
    groups: dict[tuple[str, int | None, int | None, int | None], Finding] = {}
    repeats: OrderedDict[tuple[int, int, int, int, bytes], PacketEvidence] = OrderedDict()
    groups_limited = False
    repeat_evictions = 0
    inventory_limited = False

    def add(rule, severity, title, verification, location, explanation, recommendation, evidence):
        nonlocal groups_limited
        key = (rule, *location)
        if key not in groups:
            if len(groups) >= 500:
                groups_limited = True
                return
            groups[key] = Finding(
                rule=rule, severity=severity, title=title, verification=verification,
                bus=location[0], address=location[1], endpoint=location[2],
                explanation=explanation, recommendation=recommendation,
            )
        finding = groups[key]
        finding.occurrences += 1
        if len(finding.evidence) < 5:
            finding.evidence.append(evidence)

    try:
        with source.open("rb") as stream:
            before = os.fstat(stream.fileno())

            def read(size):
                if cancelled():
                    raise AnalysisCancelled("Analysis cancelled; no completed result was produced.")
                data = stream.read(size)
                digest.update(data)
                return data

            header = read(24)
            formats = {
                b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
                b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
                b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
                b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
            }
            if len(header) != 24 or header[:4] not in formats:
                raise AnalysisError(
                    "Unsupported or incomplete capture header. Expected classic USBPcap PCAP; "
                    "PCAPNG and other capture formats are not supported."
                )
            endian, resolution = formats[header[:4]]
            major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
            if (major, minor) != (2, 4):
                raise AnalysisError(f"Unsupported PCAP version {major}.{minor}; expected 2.4.")
            if linktype != 249:
                raise AnalysisError(f"Unsupported PCAP link type {linktype}; expected USBPcap (249).")
            if snaplen == 0:
                raise AnalysisError("Invalid PCAP snapshot length 0; expected a positive limit.")
            while True:
                offset = stream.tell()
                record = read(16)
                if not record:
                    break
                if stream.tell() > before.st_size:
                    raise AnalysisError("Capture changed during analysis. Stop recording and analyze again.")
                if len(record) != 16:
                    raise AnalysisError(f"Incomplete PCAP record header at byte {offset}.")
                seconds, fraction, captured, original = struct.unpack(endian + "IIII", record)
                if captured > snaplen or captured > original or fraction >= resolution:
                    raise AnalysisError(f"Invalid PCAP record length/timestamp at byte {offset}.")
                if captured > SNAPLEN:
                    raise AnalysisError(
                        f"Packet at byte {offset} contains {captured} captured bytes, exceeding "
                        f"the analyzer's {SNAPLEN}-byte (1 MiB) per-packet safety limit. "
                        "A larger declared PCAP snapshot limit is supported, but not oversized packets."
                    )
                packet = read(captured)
                if len(packet) != captured:
                    raise AnalysisError(f"Incomplete packet at byte {offset}; file may still be recording.")
                result.packets += 1
                if result.packets % 250 == 0:
                    progress(min(99, int(stream.tell() * 100 / max(1, before.st_size))))
                timestamp = (
                    datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
                    + f".{fraction:0{6 if resolution == 1_000_000 else 9}d}Z"
                )
                packet_hash = hashlib.sha256(packet).hexdigest()
                location = (None, None, None)
                payload = b""
                urb_id, phase, direction, transfer_type = "Unknown", "Unknown", "Unknown", "Unknown"
                valid = len(packet) >= 27
                if valid:
                    header_len, urb, status, _, info, bus, address, endpoint, transfer, length = (
                        struct.unpack_from("<HQIHBHHBBI", packet)
                    )
                    location = (bus, address, endpoint)
                    if len(result.devices) < 4096:
                        result.devices.add((bus, address))
                    elif (bus, address) not in result.devices:
                        inventory_limited = True
                    urb_id = f"0x{urb:016x}"
                    phase = "completion" if info & 1 else "submission"
                    direction = "IN" if endpoint & 0x80 else "OUT"
                    transfer_type = {
                        0: "Isochronous", 1: "Interrupt", 2: "Control", 3: "Bulk",
                    }.get(transfer, f"Unknown ({transfer})")
                    valid = (
                        27 <= header_len <= len(packet)
                        and length >= len(packet) - header_len
                        and (captured < original or length == len(packet) - header_len)
                        and (transfer != 2 or header_len >= 28)
                    )
                    if valid:
                        payload = packet[header_len:]
                evidence = PacketEvidence(
                    result.packets, timestamp, offset, packet_hash,
                    hashlib.sha256(payload).hexdigest() if valid else "",
                    len(payload), urb_id, phase, direction, transfer_type, "",
                )
                if captured < original:
                    result.truncated_records += 1
                    add(
                        "CAPTURE_TRUNCATED", "INFO", "Snapshot-truncated packet", "OBSERVED", location,
                        "Captured length is smaller than the original record; content is incomplete.",
                        "Re-capture with sufficient snapshot length; do not treat missing bytes as safe.",
                        evidence,
                    )
                if not valid:
                    result.malformed_records += 1
                    add(
                        "MALFORMED_USBPCAP", "INFO", "USBPcap record cannot be fully parsed",
                        "OBSERVED", location, "Pseudoheader or payload length is invalid/incomplete.",
                        "Inspect the frame in Wireshark and confirm capture integrity.", evidence,
                    )
                    continue
                if status:
                    add(
                        "USB_TRANSFER_STATUS", "INFO", "Nonzero USB transfer status", "OBSERVED", location,
                        "A nonzero USBPcap status was recorded. This may be normal during reboot "
                        "or cancellation, not a confirmed security defect.",
                        "Correlate with updater logs and Windows USB status definitions.",
                        replace(evidence, note=f"USB status 0x{status:08x}"),
                    )
                canonical = bool(info & 1) == bool(endpoint & 0x80)
                supported = transfer in (1, 3) or (transfer == 2 and packet[27] == 1)
                if not payload:
                    continue
                if not canonical or not supported or status or captured < original:
                    result.skipped_payload_records += 1
                    continue
                result.payload_records_scanned += 1
                result.payload_bytes_scanned += len(payload)
                for pattern in (CREDENTIAL_PATTERN, AUTH_PATTERN):
                    match = pattern.search(payload)
                    if match:
                        label = match.group(1).decode("ascii").lower()
                        add(
                            "CREDENTIAL_PATTERN", "MEDIUM", "Credential-like plaintext pattern",
                            "NEEDS REVIEW", location,
                            "A credential/token label and value-like bytes are readable in a USB "
                            "payload. This can be test data or embedded firmware strings, not a "
                            "confirmed live credential or authentication failure.",
                            "Inspect the original frame locally, determine whether the value is "
                            "sensitive/live, and review transport protection and credential handling.",
                            replace(
                                evidence,
                                note=f"Label: {label}; payload offset: {match.start()}; value: [REDACTED]",
                            ),
                        )
                if TEXT_PATTERN.search(payload):
                    add(
                        "READABLE_TEXT", "INFO", "Readable text in USB payload", "OBSERVED", location,
                        "At least 16 consecutive printable ASCII bytes were observed. This does "
                        "not establish that firmware is unencrypted or contains sensitive data.",
                        "Identify the protocol/content and determine whether confidentiality is required.",
                        evidence,
                    )
                key = (bus, address, endpoint, transfer, hashlib.sha256(payload).digest())
                previous = repeats.get(key)
                if previous is not None and previous.urb_id != urb_id:
                    add(
                        "REPEATED_PAYLOAD", "INFO", "Identical payload in distinct USB requests",
                        "OBSERVED", location,
                        "Matching payload hashes were observed with different URB identifiers. "
                        "Polling, chunk reuse and retries are normal explanations; this is not "
                        "proof that the device accepts replay.",
                        "Compare packet timing and protocol sequence numbers before drawing conclusions.",
                        replace(
                            evidence,
                            note=f"Earlier matching frame: {previous.frame}; URB: {previous.urb_id}",
                        ),
                    )
                repeats[key] = evidence
                repeats.move_to_end(key)
                if len(repeats) > 4096:
                    repeats.popitem(last=False)
                    repeat_evictions += 1
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise AnalysisError("Capture changed during analysis. Stop recording and analyze again.")
    except OSError as error:
        raise AnalysisError(f"Cannot read capture: {error}") from error
    if cancelled():
        raise AnalysisCancelled("Analysis cancelled; no completed result was produced.")
    if groups_limited:
        result.limitations.append("Finding-group limit (500) reached; additional groups were omitted.")
    if repeat_evictions:
        result.limitations.append(
            f"Repeat tracking evicted {repeat_evictions} entries (4096-entry window); older repeats may be missed."
        )
    if inventory_limited:
        result.limitations.append("Bus/address inventory limit (4096) reached; additional pairs were omitted.")
    if result.packets == 0:
        result.limitations.append("Capture contains no packets; there is no device traffic to assess.")
    result.findings = sorted(groups.values(), key=lambda finding: finding.severity != "MEDIUM")
    result.sha256 = digest.hexdigest()
    result.analyzed_at = datetime.now(timezone.utc).isoformat()
    progress(100)
    return result
