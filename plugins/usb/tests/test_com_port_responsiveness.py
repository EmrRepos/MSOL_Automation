import os
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QPushButton

from core.com_port_manager import COMPortManager
from ui.com_port_panel import COMPortPanel


def port_info(port="COM6", hwid="USB VID:PID=15A2:0400"):
    return SimpleNamespace(
        device=port, hwid=hwid, description=f"USB Port ({port})",
        vid=0x15A2, pid=0x0400, serial_number="123", manufacturer="Vendor",
    )


class MetadataCacheTests(unittest.TestCase):
    def test_manager_creation_does_not_connect_to_wmi(self):
        with patch("core.com_port_manager.DeviceManager") as factory:
            COMPortManager()
            factory.assert_not_called()

    def test_unchanged_ports_reuse_metadata_and_changes_invalidate(self):
        manager = COMPortManager()
        with (
            patch("core.com_port_manager.list_ports.comports") as discover,
            patch.object(manager, "_usb_devices_by_port", return_value={}) as wmi,
        ):
            discover.return_value = [port_info()]
            first, new = manager.scan()
            self.assertEqual(new, [])
            self.assertEqual(first[0]["port"], "COM6")
            manager.scan()
            self.assertEqual(wmi.call_count, 1)

            discover.return_value = [port_info("COM7")]
            _, new = manager.scan()
            self.assertEqual(new[0]["port"], "COM7")
            self.assertEqual(wmi.call_count, 2)

            discover.return_value = []
            self.assertEqual(manager.scan(), ([], []))
            discover.return_value = [port_info("COM7")]
            manager.scan()
            self.assertEqual(wmi.call_count, 3)

    def test_discovery_error_is_not_treated_as_disconnection(self):
        manager = COMPortManager()
        with (
            patch("core.com_port_manager.list_ports.comports", return_value=[port_info()]),
            patch.object(manager, "_usb_devices_by_port", return_value={}),
        ):
            manager.scan()
        with patch(
            "core.com_port_manager.list_ports.comports",
            side_effect=OSError("Discovery unavailable"),
        ):
            with self.assertRaisesRegex(OSError, "Discovery unavailable"):
                manager.scan()
        self.assertEqual(manager._known_ports, {"COM6"})


class PanelResponsivenessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.release = threading.Event()
        self.started = threading.Event()
        self.calls = 0
        self.scan_thread = None
        self.error = None
        self.records = [{"port": "COM6", "name": "Serial Device"}]
        test = self

        class SlowManager:
            def scan(self):
                test.calls += 1
                test.scan_thread = threading.get_ident()
                test.started.set()
                if not test.release.wait(3):
                    raise TimeoutError("Test did not release scan")
                if test.error:
                    raise test.error
                return test.records, []

        with patch("ui.com_port_panel.COMPortManager", SlowManager):
            self.panel = COMPortPanel()
        self.logs = []
        self.panel.log_requested.connect(self.logs.append)

    def wait_until(self, predicate, timeout=2):
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            QTest.qWait(10)
        self.assertTrue(predicate(), "Timed out waiting for scan")

    def tearDown(self):
        self.release.set()
        self.wait_until(lambda: not self.panel._scan_in_progress)
        self.panel.stop_monitoring()
        self.panel.deleteLater()
        self.app.processEvents()

    def test_slow_scan_keeps_heartbeat_and_clicks_responsive(self):
        ticks = []
        timer = QTimer()
        timer.setInterval(10)
        timer.timeout.connect(lambda: ticks.append(time.monotonic()))
        timer.start()
        button = QPushButton()
        clicks = []
        button.clicked.connect(lambda: clicks.append(True))
        selected_threads = []
        self.panel.device_selected.connect(
            lambda _: selected_threads.append(threading.get_ident())
        )
        try:
            start = time.monotonic()
            self.panel.start_monitoring()
            self.assertLess(time.monotonic() - start, 0.15)
            self.wait_until(self.started.is_set)
            QTest.qWait(250)
            button.click()
            self.assertEqual(clicks, [True])
            self.assertGreaterEqual(len(ticks), 5)
            self.assertTrue(self.panel._scan_in_progress)
            self.assertNotEqual(self.scan_thread, threading.get_ident())
            self.release.set()
            self.wait_until(lambda: not self.panel._scan_in_progress)
            self.assertEqual(self.panel.port_combo.currentText(), "COM6")
            self.assertEqual(selected_threads, [threading.get_ident()])
        finally:
            timer.stop()

    def test_refresh_requests_do_not_overlap(self):
        self.panel.start_monitoring()
        self.wait_until(self.started.is_set)
        for _ in range(10):
            self.panel.poll_ports()
            self.panel.refresh_ports()
        self.assertEqual(self.calls, 1)
        self.assertFalse(self.panel.refresh_btn.isEnabled())
        self.release.set()
        self.wait_until(lambda: not self.panel._scan_in_progress)
        self.assertTrue(self.panel.refresh_btn.isEnabled())

    def test_scan_failure_is_visible_and_retry_succeeds(self):
        self.error = OSError("Driver query failed")
        self.release.set()
        self.panel.refresh_ports()
        self.wait_until(lambda: not self.panel._scan_in_progress)
        self.assertTrue(any("Driver query failed" in log for log in self.logs))
        self.assertTrue(self.panel.refresh_btn.isEnabled())
        self.error = None
        self.panel.refresh_ports()
        self.wait_until(lambda: not self.panel._scan_in_progress)
        self.assertEqual(self.panel.current_device()["port"], "COM6")

    def test_stopping_does_not_wait_for_driver_or_apply_late_results(self):
        self.panel.start_monitoring()
        self.wait_until(self.started.is_set)
        start = time.monotonic()
        self.panel.stop_monitoring()
        self.assertLess(time.monotonic() - start, 0.1)
        self.release.set()
        self.wait_until(lambda: not self.panel._scan_in_progress)
        self.assertEqual(self.panel.devices, [])
        self.assertEqual(self.logs, [])


if __name__ == "__main__":
    unittest.main()
