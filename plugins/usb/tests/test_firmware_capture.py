import io
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QByteArray, QProcess
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox

from core.firmware_capture import (
    CaptureError, FirmwareCapture, PcapRecorder, SNAPLEN, find_usbpcap,
    parse_hubs, parse_topology,
)
from plugins.serial_console import SerialConsole
from ui.firmware_capture_panel import FirmwareCapturePanel
from ui.main_window import MainWindow
from ui.test_panel import TestPanel


HUB = r"\\.\USBPcap1"


def stream_header(endian="<"):
    return struct.pack(endian + "IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, 249)


def packet_record(payload=b"\x01\x02\xff", endpoint=0x81, original=None, endian="<"):
    pseudoheader = struct.pack(
        "<HQIHBHHBBI", 27, 1, 0, 9, 1, 2, 7, endpoint, 3, len(payload)
    )
    packet = pseudoheader + payload
    return struct.pack(
        endian + "IIII", 123, 456, len(packet),
        len(packet) if original is None else original,
    ) + packet


class PcapRecorderTests(unittest.TestCase):
    def setUp(self):
        self.output = io.BytesIO()
        self.recorder = PcapRecorder(self.output)

    def test_bytewise_stream_preserves_exact_pcap_and_previews_endpoint(self):
        data = stream_header() + packet_record()
        for byte in data:
            self.recorder.feed(bytes([byte]))
        self.assertEqual(self.output.getvalue(), data)
        self.assertEqual(self.recorder.packets, 1)
        self.assertEqual(self.recorder.bytes_written, len(data))
        self.assertIn("address 7", self.recorder.preview)
        self.assertIn("0x81 IN (completion)", self.recorder.preview)
        self.assertIn("01 02 ff", self.recorder.preview)
        self.assertFalse(self.recorder.buffer)

    def test_big_endian_pcap_with_little_endian_usb_header(self):
        data = stream_header(">") + packet_record(endian=">")
        self.recorder.feed(data)
        self.assertEqual(self.output.getvalue(), data)
        self.assertEqual(self.recorder.packets, 1)
        self.assertIn("Bus 2", self.recorder.preview)

    def test_partial_record_is_not_saved(self):
        record = packet_record()
        self.recorder.feed(stream_header() + record + record[:-1])
        self.assertEqual(self.recorder.packets, 1)
        self.assertEqual(self.output.getvalue(), stream_header() + record)
        self.assertEqual(len(self.recorder.buffer), len(record) - 1)

    def test_short_packets_do_not_crash_preview(self):
        data = b"\x01"
        self.recorder.feed(stream_header() + struct.pack("<IIII", 0, 0, 1, 1) + data)
        self.assertIn("Short", self.recorder.preview)

    def test_reports_snaplen_truncation(self):
        self.recorder.feed(stream_header() + packet_record(original=500))
        self.assertEqual(self.recorder.truncated_packets, 1)

    def test_rejects_bad_header_and_wrong_link_type(self):
        for header in (b"x" * 24, stream_header()[:-4] + struct.pack("<I", 1)):
            with self.subTest(header=header), self.assertRaises(CaptureError):
                PcapRecorder(io.BytesIO()).feed(header)

    def test_rejects_packet_larger_than_snapshot_or_original(self):
        for captured, original in ((SNAPLEN + 1, SNAPLEN + 1), (50, 49)):
            with self.subTest(captured=captured), self.assertRaises(CaptureError):
                PcapRecorder(io.BytesIO()).feed(
                    stream_header() + struct.pack("<IIII", 0, 0, captured, original)
                )

    def test_short_write_is_an_error(self):
        sink = Mock()
        sink.write.return_value = 0
        with self.assertRaisesRegex(CaptureError, "Incomplete"):
            PcapRecorder(sink).feed(stream_header())


class DiscoveryTests(unittest.TestCase):
    def test_only_usbpcap_hubs_are_parsed(self):
        text = (
            f"interface {{value={HUB}}}{{display=USBPcap1}}\n"
            "interface {value=Wi-Fi}{display=Wi-Fi}\n"
            "interface {value=COM6}{display=Serial}"
        )
        self.assertEqual(parse_hubs(text), [HUB])

    def test_topology_and_missing_details(self):
        text = "value {arg=99}{value=7}{display=Emerson 15a2:0400}{enabled=true}"
        self.assertIn("Address 7: Emerson 15a2:0400", parse_topology(text))
        self.assertIn("did not report", parse_topology(""))

    def test_detection_uses_path_then_known_installation(self):
        with patch("core.firmware_capture.shutil.which", return_value=r"C:\USBPcapCMD.exe"):
            self.assertEqual(find_usbpcap(), r"C:\USBPcapCMD.exe")
        with (
            patch("core.firmware_capture.shutil.which", return_value=None),
            patch.dict(os.environ, {"ProgramFiles": r"C:\Programs"}),
            patch("core.firmware_capture.os.path.isfile", side_effect=lambda p: p == r"C:\Programs\USBPcap\USBPcapCMD.exe"),
        ):
            self.assertEqual(find_usbpcap(), r"C:\Programs\USBPcap\USBPcapCMD.exe")


class CaptureLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "firmware.pcap"
        self.capture = FirmwareCapture(executable="USBPcapCMD.exe", admin_check=lambda: True)
        self.logs = []
        self.states = []
        self.capture.log_requested.connect(self.logs.append)
        self.capture.active_changed.connect(self.states.append)
        self.start_patch = patch.object(self.capture.process, "start")
        self.start_process = self.start_patch.start()
        self.addCleanup(self.start_patch.stop)
        self.addCleanup(self.cleanup_capture)

    def cleanup_capture(self):
        self.capture.start_timer.stop()
        if self.capture.active:
            self.capture.stop()
            self.capture._finished(0, QProcess.NormalExit)
        self.capture.shutdown_discovery()

    def feed(self, data):
        with patch.object(self.capture.process, "readAllStandardOutput", return_value=QByteArray(data)):
            self.capture._read_capture()

    def test_capture_arguments_are_passive_binary_stdout_whole_hub(self):
        self.capture.start(HUB, self.path)
        self.start_process.assert_called_once_with("USBPcapCMD.exe", [
            "-d", HUB, "-o", "-", "-A", "-s", str(SNAPLEN), "-b", "16777216",
        ])
        self.assertTrue(self.capture.active)
        self.assertFalse(self.capture.ready)
        self.assertEqual(self.states, [True])

    def test_ready_requires_valid_header_and_stop_preserves_only_complete_records(self):
        self.capture.start(HUB, self.path)
        data = stream_header() + packet_record()
        self.feed(data[:10])
        self.assertFalse(self.capture.ready)
        self.feed(data[10:] + packet_record()[:20])
        self.assertTrue(self.capture.ready)
        self.capture.stop()
        self.assertTrue(self.capture.active)
        self.capture._finished(-1, QProcess.CrashExit)
        self.assertFalse(self.capture.active)
        self.assertFalse(self.capture.failed)
        self.assertEqual(self.path.read_bytes(), data)
        self.assertEqual(self.states, [True, False])
        self.assertTrue(any("Omitted" in line for line in self.logs))
        self.assertTrue(any("NOT stopped" in line for line in self.logs))

    def test_rejects_non_admin_without_file_or_process(self):
        self.capture.admin_check = lambda: False
        with self.assertRaisesRegex(CaptureError, "administrator"):
            self.capture.start(HUB, self.path)
        self.assertFalse(self.path.exists())
        self.start_process.assert_not_called()

    def test_existing_capture_is_never_overwritten(self):
        self.path.write_bytes(b"existing")
        with self.assertRaisesRegex(CaptureError, "Cannot create"):
            self.capture.start(HUB, self.path)
        self.assertEqual(self.path.read_bytes(), b"existing")
        self.start_process.assert_not_called()

    def test_invalid_hub_and_extension_are_rejected(self):
        for hub, path in (("COM6", self.path), (HUB, self.path.with_suffix(".bin"))):
            with self.subTest(hub=hub), self.assertRaises(CaptureError):
                self.capture.start(hub, path)
        self.start_process.assert_not_called()

    def test_duplicate_start_is_rejected(self):
        self.capture.start(HUB, self.path)
        with self.assertRaises(CaptureError):
            self.capture.start(HUB, self.path)

    def test_failed_start_releases_file_and_lock(self):
        self.capture.start(HUB, self.path)
        self.capture._process_error(QProcess.FailedToStart)
        self.assertFalse(self.capture.active)
        self.assertIsNone(self.capture.output)
        self.assertTrue(self.capture.failed)
        self.assertFalse(self.capture.start_timer.isActive())
        self.assertEqual(self.states, [True, False])

    def test_invalid_stream_stops_and_reports_failure(self):
        self.capture.start(HUB, self.path)
        self.feed(b"x" * 24)
        self.assertTrue(self.capture.stopping)
        self.assertTrue(self.capture.failed)
        self.assertTrue(any("invalid PCAP header" in line for line in self.logs))

    def test_write_error_stops_recording_explicitly(self):
        self.capture.start(HUB, self.path)
        self.capture.output.close()
        failing_output = Mock()
        failing_output.write.side_effect = OSError("disk full")
        self.capture.output = failing_output
        self.capture.recorder.output = failing_output
        self.feed(stream_header())
        self.assertTrue(self.capture.failed)
        self.assertTrue(any("disk full" in line for line in self.logs))

    def test_timeout_is_failure_and_zero_records_warn(self):
        self.capture.start(HUB, self.path)
        self.capture._startup_timeout()
        self.assertTrue(self.capture.failed)
        self.assertTrue(self.capture.stopping)

    def test_unexpected_exit_and_empty_capture_are_not_success(self):
        self.capture.start(HUB, self.path)
        self.feed(stream_header())
        self.capture._finished(0, QProcess.NormalExit)
        self.assertTrue(self.capture.failed)
        self.assertTrue(any("no USB packets" in line for line in self.logs))
        self.assertTrue(any("unexpectedly" in line for line in self.logs))

    def test_discovery_uses_read_only_extcap_options(self):
        with patch.object(self.capture.query, "start") as start:
            self.capture.discover()
            start.assert_called_once_with("USBPcapCMD.exe", ["--extcap-interfaces"])
            self.capture.query_timer.stop()

    def test_discovery_timeout_and_failure_are_logged(self):
        self.capture._query_timeout()
        self.assertTrue(any("timed out" in line for line in self.logs))
        self.capture._query_error(QProcess.FailedToStart)
        self.assertTrue(any("discovery:" in line for line in self.logs))

    def test_real_qprocess_stream_capture_without_usb_hardware(self):
        self.start_patch.stop()
        original_start = self.capture.process.start
        data = stream_header() + packet_record()
        script = (
            "import sys,time; "
            f"sys.stdout.buffer.write({data!r}); sys.stdout.buffer.flush(); "
            "sys.stderr.write('synthetic capture\\n'); sys.stderr.flush(); time.sleep(30)"
        )
        with patch.object(
            self.capture.process, "start",
            side_effect=lambda *args: original_start(sys.executable, ["-u", "-c", script]),
        ):
            self.capture.start(HUB, self.path)
        try:
            for _ in range(100):
                QTest.qWait(20)
                if self.capture.ready:
                    break
            self.assertTrue(self.capture.ready, "\n".join(self.logs))
            self.assertEqual(self.capture.recorder.packets, 1)
            self.assertEqual(self.path.read_bytes(), data)
        finally:
            self.capture.stop()
            self.capture.process.waitForFinished(3000)
        self.assertFalse(self.capture.active)
        self.assertFalse(self.capture.failed)
        self.assertEqual(self.path.read_bytes(), data)


class CapturePanelAndIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.capture = FirmwareCapture(executable="USBPcapCMD.exe", admin_check=lambda: True)
        self.guard = Mock()
        self.panel = FirmwareCapturePanel(capture=self.capture, start_guard=self.guard)
        self.addCleanup(self.panel.close)
        warning = patch("ui.firmware_capture_panel.QMessageBox.warning")
        warning.start()
        self.addCleanup(warning.stop)

    def test_no_hub_auto_selection_and_consent_required(self):
        self.panel._hubs_ready([HUB])
        self.assertEqual(self.panel.hub_box.currentIndex(), -1)
        self.assertFalse(self.panel.btn_start.isEnabled())
        self.panel.start_capture()
        self.guard.assert_not_called()

    def test_start_calls_guard_and_capture_not_prolink(self):
        with patch.object(self.capture, "inspect_hub"):
            self.panel.hub_box.addItem(HUB)
        self.panel.output_box.setText(r"C:\captures\update.pcap")
        self.panel.consent.setChecked(True)
        with patch.object(self.capture, "start") as start:
            self.panel.start_capture()
        self.guard.assert_called_once()
        start.assert_called_once_with(HUB, r"C:\captures\update.pcap")
        self.assertFalse(hasattr(self.panel, "btn_launch"))

    def test_guard_failure_prevents_capture(self):
        self.panel.consent.setChecked(True)
        self.guard.side_effect = CaptureError("Stop tests first")
        with patch.object(self.capture, "start") as start:
            self.panel.start_capture()
        start.assert_not_called()
        self.assertIn("Stop tests first", self.panel.console.toPlainText())

    def test_active_capture_disables_configuration(self):
        self.capture.active = True
        self.panel.update_controls()
        self.assertFalse(self.panel.output_box.isEnabled())
        self.assertFalse(self.panel.btn_refresh.isEnabled())
        self.assertTrue(self.panel.btn_stop.isEnabled())
        self.capture.active = False

    def test_close_cancel_leaves_capture_running(self):
        self.capture.active = True
        event = Mock()
        with patch(
            "ui.firmware_capture_panel.QMessageBox.question", return_value=QMessageBox.No
        ), patch.object(self.capture, "stop") as stop:
            self.panel.closeEvent(event)
        event.ignore.assert_called_once()
        stop.assert_not_called()
        self.capture.active = False

    def test_escape_uses_close_confirmation_during_capture(self):
        self.capture.active = True
        with patch.object(self.panel, "close") as close:
            self.panel.reject()
        close.assert_called_once()
        self.capture.active = False

    def test_confirmed_close_stops_owned_process_and_flushes_file(self):
        data = stream_header() + packet_record()
        script = (
            "import sys,time; "
            f"sys.stdout.buffer.write({data!r}); sys.stdout.buffer.flush(); time.sleep(30)"
        )
        original_start = self.capture.process.start
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "close.pcap"
            with patch.object(
                self.capture.process, "start",
                side_effect=lambda *args: original_start(sys.executable, ["-u", "-c", script]),
            ):
                self.capture.start(HUB, path)
            try:
                for _ in range(100):
                    QTest.qWait(20)
                    if self.capture.ready:
                        break
                self.assertTrue(self.capture.ready)
                with patch(
                    "ui.firmware_capture_panel.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Yes,
                ):
                    self.assertTrue(self.panel.close())
                self.assertFalse(self.capture.active)
                self.assertEqual(self.capture.process.state(), QProcess.ProcessState.NotRunning)
                self.assertEqual(path.read_bytes(), data)
            finally:
                if self.capture.active:
                    self.capture.stop()
                    self.capture.process.waitForFinished(3000)

    def test_main_window_preflight_rejects_tests_and_connected_console(self):
        window = SimpleNamespace(
            test_panel=SimpleNamespace(runner=SimpleNamespace(running=True), serial_console=None)
        )
        with self.assertRaisesRegex(CaptureError, "running test"):
            MainWindow.prepare_firmware_capture(window)
        window.test_panel.runner.running = False
        window.test_panel.serial_console = SimpleNamespace(is_connected=True)
        with self.assertRaisesRegex(CaptureError, "Disconnect"):
            MainWindow.prepare_firmware_capture(window)
        window.test_panel.serial_console.is_connected = False
        MainWindow.prepare_firmware_capture(window)

    def test_test_starts_and_preexisting_console_reconnect_are_locked(self):
        panel = TestPanel()
        self.addCleanup(panel.close)
        with patch("plugins.serial_console.serial.tools.list_ports.comports", return_value=[]):
            console = SerialConsole(panel)
        self.addCleanup(console.close)
        panel.serial_console = console
        panel.set_firmware_capture_active(True)
        with patch.object(panel.runner, "start") as start:
            panel.start_test()
        start.assert_not_called()
        with patch.object(console, "report_error") as error, patch(
            "plugins.serial_console.serial.Serial"
        ) as serial_factory:
            console.connect_port()
        serial_factory.assert_not_called()
        error.assert_called_once()
        self.assertFalse(console.isEnabled())
        panel.set_firmware_capture_active(False)
        self.assertTrue(console.isEnabled())
        self.assertIsNone(console.connection_blocked_reason)


if __name__ == "__main__":
    unittest.main()
