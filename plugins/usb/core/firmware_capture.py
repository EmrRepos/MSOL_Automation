"""Passive USBPcap recording. Never opens a COM port or sends device commands."""

import ctypes
import os
import re
import shutil
import struct
from pathlib import Path

from PySide6.QtCore import QObject, QProcess, QTimer, Signal


SNAPLEN = 1048576
HUB_PATTERN = re.compile(r"^\\\\\.\\USBPcap\d+$")


class CaptureError(Exception):
    pass


def find_usbpcap():
    found = shutil.which("USBPcapCMD.exe")
    if found:
        return found
    for variable in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(variable)
        if root:
            for relative in (
                r"USBPcap\USBPcapCMD.exe",
                r"Wireshark\extcap\USBPcapCMD.exe",
            ):
                candidate = os.path.join(root, relative)
                if os.path.isfile(candidate):
                    return candidate
    return None


def is_administrator():
    return os.name == "nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())


def parse_hubs(text):
    return [
        match for match in re.findall(r"interface \{value=([^}]+)\}", text)
        if HUB_PATTERN.fullmatch(match)
    ]


def parse_topology(text):
    devices = []
    for line in text.splitlines():
        if line.startswith("value "):
            fields = dict(re.findall(r"\{([^={}]+)=([^}]*)\}", line))
            if fields.get("display"):
                devices.append(
                    f"Address {fields.get('value', '?')}: {fields['display']}"
                )
    return "\n".join(devices) or (
        "USBPcap did not report attached device details. Do not infer a hub "
        "from the COM number. Check the USB connection tree in Windows "
        "Device Manager (View -> Devices by connection)."
    )


class PcapRecorder:
    """Write only complete USBPcap records, including when the source stops mid-record."""

    def __init__(self, output):
        self.output = output
        self.buffer = bytearray()
        self.header_received = False
        self.packets = 0
        self.bytes_written = 0
        self.truncated_packets = 0
        self.preview = ""
        self.endian = "<"
        self.snaplen = 0

    def feed(self, data):
        self.buffer.extend(data)
        if not self.header_received:
            if len(self.buffer) < 24:
                return
            magic = bytes(self.buffer[:4])
            if magic == b"\xd4\xc3\xb2\xa1":
                self.endian = "<"
            elif magic == b"\xa1\xb2\xc3\xd4":
                self.endian = ">"
            else:
                raise CaptureError("USBPcap returned an invalid PCAP header.")
            major, minor, _, _, self.snaplen, linktype = struct.unpack(
                self.endian + "HHIIII", self.buffer[4:24]
            )
            if (major, minor) != (2, 4) or linktype != 249:
                raise CaptureError("Expected PCAP 2.4 with USBPcap link type 249.")
            if not 0 < self.snaplen <= SNAPLEN:
                raise CaptureError("USBPcap reported an unsupported snapshot length.")
            self._write(self.buffer[:24])
            del self.buffer[:24]
            self.header_received = True

        while len(self.buffer) >= 16:
            _, _, captured, original = struct.unpack(
                self.endian + "IIII", self.buffer[:16]
            )
            if captured > self.snaplen or captured > original:
                raise CaptureError("USBPcap returned an invalid packet length.")
            length = 16 + captured
            if len(self.buffer) < length:
                return
            packet = self.buffer[16:length]
            self._write(self.buffer[:length])
            del self.buffer[:length]
            self.packets += 1
            self.truncated_packets += captured < original
            if len(packet) >= 27:
                # USBPcap pseudoheaders are little-endian even in big-endian PCAP.
                header_length = struct.unpack_from("<H", packet)[0]
                bus, address = struct.unpack_from("<HH", packet, 17)
                endpoint = packet[21]
                phase = "completion" if packet[16] & 1 else "submission"
                direction = "IN" if endpoint & 0x80 else "OUT"
                payload = packet[header_length:] if 27 <= header_length <= len(packet) else b""
                self.preview = (
                    f"Bus {bus} / address {address} / endpoint 0x{endpoint:02x} "
                    f"{direction} ({phase}) | {len(payload)} captured payload bytes"
                    f"\nHEX: {bytes(payload[:32]).hex(' ')}"
                )
            else:
                self.preview = f"Short USBPcap pseudoheader: {len(packet)} bytes"

    def _write(self, data):
        if self.output.write(data) != len(data):
            raise CaptureError("Incomplete capture-file write.")
        self.bytes_written += len(data)


class FirmwareCapture(QObject):
    log_requested = Signal(str)
    active_changed = Signal(bool)
    hubs_ready = Signal(list)
    topology_ready = Signal(str)
    discovery_finished = Signal()

    def __init__(self, parent=None, executable=None, admin_check=is_administrator):
        super().__init__(parent)
        self.executable = executable or find_usbpcap()
        self.admin_check = admin_check
        self.active = False
        self.ready = False
        self.stopping = False
        self.failed = False
        self.output_path = None
        self.output = None
        self.recorder = None
        self.stderr_tail = ""
        self.query_mode = ""
        self.query_failed = False
        self.query = QProcess(self)
        self.query.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.query.finished.connect(self._query_finished)
        self.query.errorOccurred.connect(self._query_error)
        self.query_timer = QTimer(self)
        self.query_timer.setSingleShot(True)
        self.query_timer.setInterval(5000)
        self.query_timer.timeout.connect(self._query_timeout)
        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self._read_capture)
        self.process.readyReadStandardError.connect(self._read_errors)
        self.process.finished.connect(self._finished)
        self.process.errorOccurred.connect(self._process_error)
        self.start_timer = QTimer(self)
        self.start_timer.setSingleShot(True)
        self.start_timer.setInterval(10000)
        self.start_timer.timeout.connect(self._startup_timeout)

    @property
    def discovering(self):
        return self.query.state() != QProcess.ProcessState.NotRunning

    def discover(self):
        self.executable = self.executable or find_usbpcap()
        self._query("hubs", ["--extcap-interfaces"])

    def inspect_hub(self, hub):
        self._validate_hub(hub)
        self._query("topology", ["--extcap-interface", hub, "--extcap-config"])

    def _query(self, mode, arguments):
        if self.active or self.discovering:
            raise CaptureError("Wait for capture/discovery to finish.")
        if not self.executable:
            raise CaptureError(
                "USBPcapCMD.exe was not found. Install USBPcap using the "
                "Wireshark installer, then restart Windows if requested."
            )
        self.query_mode = mode
        self.query_failed = False
        self.query.start(self.executable, arguments)
        self.query_timer.start()

    def _query_timeout(self):
        self.query_failed = True
        self.log_requested.emit("[ERROR] USBPcap discovery timed out.")
        self.query.kill()

    def _query_error(self, error):
        if error == QProcess.ProcessError.FailedToStart:
            self.query_timer.stop()
            self.query_failed = True
            self.log_requested.emit(
                f"[ERROR] USBPcap discovery: {self.query.errorString()}"
            )
            self.discovery_finished.emit()

    def _query_finished(self, code, status):
        self.query_timer.stop()
        text = bytes(self.query.readAllStandardOutput().data()).decode("utf-8", errors="replace")
        if not self.query_failed:
            if code != 0 or status != QProcess.ExitStatus.NormalExit:
                self.log_requested.emit(f"[ERROR] USBPcap discovery failed: {text[-2000:]}")
            elif self.query_mode == "hubs":
                hubs = parse_hubs(text)
                self.hubs_ready.emit(hubs)
                if not hubs:
                    self.log_requested.emit(
                        "[ERROR] No USBPcap root hubs found. Check the driver "
                        "installation, reboot requirement and administrator permissions."
                    )
            else:
                self.topology_ready.emit(parse_topology(text))
        self.discovery_finished.emit()

    @staticmethod
    def _validate_hub(hub):
        if not isinstance(hub, str) or not HUB_PATTERN.fullmatch(hub):
            raise CaptureError("Select a USBPcap root hub, not a COM port/network adapter.")

    def start(self, hub, output_path):
        if self.active or self.discovering:
            raise CaptureError("Capture or discovery is already running.")
        self._validate_hub(hub)
        if not self.executable:
            raise CaptureError("USBPcap is not installed.")
        if not self.admin_check():
            raise CaptureError(
                "Restart this application as administrator to capture USB. "
                "No automatic elevation or driver installation is performed."
            )
        path = Path(output_path)
        if path.suffix.lower() != ".pcap":
            raise CaptureError("Choose a new .pcap output file.")
        try:
            self.output = path.open("xb")
        except OSError as error:
            raise CaptureError(f"Cannot create capture file: {error}") from error
        self.output_path = path
        self.recorder = PcapRecorder(self.output)
        self.stderr_tail = ""
        self.ready = False
        self.stopping = False
        self.failed = False
        self.active = True
        self.active_changed.emit(True)
        self.log_requested.emit(
            f"[INFO] Starting passive USB capture on {hub} -> {path}. "
            "All devices on this hub are included."
        )
        # Binary stdout is kept separate from diagnostic stderr.
        self.process.start(self.executable, [
            "-d", hub, "-o", "-", "-A", "-s", str(SNAPLEN),
            "-b", "16777216",
        ])
        self.start_timer.start()

    def _read_capture(self):
        data = bytes(self.process.readAllStandardOutput().data())
        if not data or self.output is None or self.failed:
            return
        assert self.recorder is not None
        try:
            self.recorder.feed(data)
            self.output.flush()
        except (OSError, CaptureError) as error:
            self._fail(f"Capture write/stream error: {error}")
            return
        if self.recorder.header_received and not self.ready:
            self.ready = True
            self.start_timer.stop()
            self.log_requested.emit(
                "[INFO] CAPTURE READY: USBPcap stream header received. "
                "Confirm target activity, then perform the update manually in ProLink."
            )

    def _read_errors(self):
        text = bytes(self.process.readAllStandardError().data()).decode("utf-8", errors="replace")
        if text:
            self.stderr_tail = (self.stderr_tail + text)[-8000:]
            self.log_requested.emit(f"[USBPcap] {text.rstrip()}")

    def _startup_timeout(self):
        self._fail("No USBPcap stream header within 10 seconds. Check permissions/driver.")

    def _fail(self, message):
        self.failed = True
        self.log_requested.emit(f"[ERROR] {message}")
        self.stop()

    def _process_error(self, error):
        if error == QProcess.ProcessError.FailedToStart:
            self.failed = True
            self.log_requested.emit(f"[ERROR] Cannot start USBPcap: {self.process.errorString()}")
            self._finished(-1, QProcess.ExitStatus.CrashExit)
        elif not self.stopping:
            self._fail(f"USBPcap process error: {self.process.errorString()}")

    def stop(self):
        if not self.active or self.stopping:
            return
        self.stopping = True
        self.start_timer.stop()
        self.log_requested.emit(
            "[INFO] Stopping recorder only; ProLink and the firmware update are NOT stopped. "
            "Final in-flight USB records may be lost."
        )
        # USBPcap's 'q' command uses a console input handle, not piped stdin.
        # Terminate only our reader; persist complete records already received.
        self.process.kill()

    def _finished(self, code: int, status: QProcess.ExitStatus):
        if not self.active:
            return
        assert self.recorder is not None and self.output is not None
        self.start_timer.stop()
        self._read_capture()
        self._read_errors()
        if not self.stopping:
            self.failed = True
            self.log_requested.emit(
                f"[ERROR] USBPcap exited unexpectedly (code {code}, {status.name})."
            )
        if not self.ready:
            self.failed = True
            self.log_requested.emit("[ERROR] No valid USBPcap stream was received; capture is unusable.")
        elif self.recorder.packets == 0:
            self.log_requested.emit("[WARN] Capture contains no USB packets. Check the selected hub.")
        if self.recorder.buffer:
            self.log_requested.emit(
                f"[WARN] Omitted {len(self.recorder.buffer)} trailing bytes of an incomplete record."
            )
        if self.recorder.truncated_packets:
            self.log_requested.emit(
                f"[WARN] {self.recorder.truncated_packets} packets exceeded snapshot length."
            )
        try:
            self.output.close()
        except OSError as error:
            self.failed = True
            self.log_requested.emit(f"[ERROR] Could not close capture file: {error}")
        self.output = None
        result = "with errors" if self.failed else "(not proof of update success)"
        self.log_requested.emit(
            f"[INFO] Capture ended {result}: {self.recorder.packets} records, "
            f"{self.recorder.bytes_written} bytes -> {self.output_path}"
        )
        self.active = False
        self.ready = False
        self.active_changed.emit(False)

    def shutdown_discovery(self):
        if self.discovering:
            self.query.kill()
            self.query.waitForFinished(1000)
