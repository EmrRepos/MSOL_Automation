import csv
import os
import tempfile
import threading
import unittest
from copy import deepcopy
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtTest import QTest
from PySide6.QtGui import QTextDocument
from PySide6.QtWidgets import QApplication, QMessageBox

from core.com_port_manager import COMPortManager
from core.report_generator import ReportGenerator
from core.hardware_helpers import read_descriptors
from plugins.serial_comm_test import SerialCommunicationTest
from core.serial_evidence import inspect_cdc_driver, match_cdc_driver
from core.test_runner import TestRunner
from core.test_suite import (
    ApplicableSuite, STANDARD, STRESS, SUITE_NAME, overall_status, refresh_device,
)
from ui.test_panel import TestPanel
from ui.suite_results_panel import SuiteResultsPanel
from ui.report_center import ReportCenter


# Synthetic fixtures only; runtime discovery never imports this test module.
DEVICE = {
    "name": "Synthetic serial device", "port": "COM6", "vid": "1234", "pid": "5678",
    "serial": "TEST-A", "usb_class": "CDC", "status": "Connected",
}
DEVICES = (
    DEVICE,
    dict(DEVICE, name="Second synthetic device", port="COM17", vid="ABCD", pid="0001", serial="TEST-B"),
    dict(DEVICE, name="Third synthetic device", port="COM42", vid="4321", pid="8765", serial="TEST-C"),
)


def pnp_id(device):
    return f"USB\\VID_{device['vid']}&PID_{device['pid']}\\{device['serial']}"


DESCRIPTORS = {
    "interfaces_available": True,
    "interfaces": [{"bInterfaceClass": 2, "endpoints": [{"bEndpointAddress": 129}]}],
}
APPROVED = {
    "name": "Documented test fixture (not a real device profile)",
    "suite_approved": True, "match": {key: DEVICE[key] for key in ("vid", "pid")},
    "serial": {"baudrate": 38400, "timeout": 1},
    "commands": [{"payload": "hex:00", "expect": "hex:01"}],
}


class SuiteExecutionTests(unittest.TestCase):
    def setUp(self):
        access = patch("core.test_suite.hardware_helpers.cdc_check", return_value=(True, "port_accessible"))
        self.access = access.start()
        self.addCleanup(access.stop)
        driver = patch("core.test_suite.inspect_cdc_driver", return_value={
            "confirmed": False, "details": "No CDC evidence in this fixture",
        })
        driver.start()
        self.addCleanup(driver.stop)
        self.cancel = threading.Event()
        self.plugins = {}
        for name in STANDARD + ("Serial Communication Validation Test",):
            factory = Mock()
            factory.return_value.execute.return_value = {"status": "PASS", "details": ["fixture result"]}
            self.plugins[name] = factory
        self.refresh = Mock(side_effect=lambda device: dict(device))
        self.read = Mock(return_value=(True, deepcopy(DESCRIPTORS)))
        self.suite = ApplicableSuite(self.plugins, self.refresh, self.read)
        self.log = []
        self.progress = []
        self.updates = []

    def run_suite(self, hardware=True):
        return self.suite.run(
            DEVICE, hardware, self.cancel, self.log.append,
            self.progress.append, self.updates.append,
        )

    def by_name(self, result):
        return {row["profile"]: row for row in result["results"]}

    def test_selected_port_usbser_evidence_can_validate_cdc_without_raw_descriptors(self):
        self.read.return_value = (False, {"error": "access denied"})
        with patch("core.test_suite.inspect_cdc_driver", return_value={
            "confirmed": True, "port": "COM6", "service": "usbser",
            "device_id": pnp_id(DEVICE),
            "details": "Exact-port Windows usbser driver evidence",
        }):
            rows = self.by_name(self.run_suite())
        self.assertEqual(rows["CDC Validation"]["status"], "PASS")
        self.assertIn("usbser", rows["CDC Validation"]["evidence"])
        self.assertEqual(rows["Endpoint Validation"]["status"], "BLOCKED")

    def test_suite_serial_checks_are_skipped_without_port_access_or_commands(self):
        with patch("serial.Serial") as connection:
            rows = self.by_name(self.run_suite())
        self.access.assert_not_called()
        connection.assert_not_called()
        for name in ("Serial Communication Validation Test", "Serial Command/Response Validation"):
            self.assertNotIn(name, rows)

    def test_suite_results_have_no_obsolete_serial_configuration(self):
        result = self.run_suite()
        self.assertNotIn("serial_access_settings", result)
        self.assertNotIn("serial_exchange", result)
        self.assertNotIn("stress_enabled", result)

    def test_suite_never_attempts_serial_access_even_when_port_would_fail(self):
        self.access.return_value = (False, "open_failed: Access denied")
        rows = self.by_name(self.run_suite())
        self.access.assert_not_called()
        self.assertNotIn("Serial Communication Validation Test", rows)
        self.assertNotIn("Serial Command/Response Validation", rows)

    def test_standard_suite_plan_and_sequential_live_results(self):
        self.assertEqual(SUITE_NAME, "Standard USB Validation")
        self.assertEqual(STANDARD, (
            "Enumeration Validation", "Descriptor Validation", "Descriptor Robustness Test",
            "Endpoint Validation", "CDC Validation", "HID Validation", "Storage Validation",
        ))
        result = self.run_suite()
        rows = self.by_name(result)
        self.assertEqual(len(rows), 7)
        self.assertEqual(tuple(rows), STANDARD)
        self.assertEqual(rows["Endpoint Validation"]["status"], "PASS")
        self.assertEqual(rows["HID Validation"]["status"], "SKIPPED")
        self.assertEqual(rows["Storage Validation"]["status"], "SKIPPED")
        self.assertNotIn("Serial Communication Validation Test", rows)
        self.assertNotIn("Serial Command/Response Validation", rows)
        self.plugins["CDC Validation"].return_value.execute.assert_called_once()
        self.plugins["Serial Communication Validation Test"].assert_not_called()
        self.assertTrue(all(name not in rows for name in STRESS))
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(self.progress[0], 0)
        self.assertEqual(self.progress[-1], 100)
        self.assertEqual(self.progress, sorted(self.progress))
        statuses = [u["status"] for u in self.updates if u["profile"] == "Descriptor Validation"]
        self.assertEqual(statuses, ["PENDING", "RUNNING", "PASS"])
        self.assertTrue(self.read.call_args.kwargs["require_unique"])

    def test_metadata_mode_never_performs_live_usb_or_serial_io(self):
        result = self.run_suite(hardware=False)
        rows = self.by_name(result)
        self.read.assert_not_called()
        self.assertIn("METADATA ONLY", result["mode"])
        for name in ("Endpoint Validation",):
            self.assertEqual(rows[name]["status"], "BLOCKED")
        for name in ("Serial Communication Validation Test", "Serial Command/Response Validation"):
            self.assertNotIn(name, rows)
        for factory in self.plugins.values():
            for call in factory.return_value.execute.call_args_list:
                self.assertIs(call.args[2], False)
        self.access.assert_not_called()

    def test_live_access_failure_cannot_pass_interface_checks(self):
        self.read.return_value = (False, {"error": "access denied"})
        rows = self.by_name(self.run_suite())
        for name in ("Descriptor Validation", "Endpoint Validation", "CDC Validation"):
            self.assertEqual(rows[name]["status"], "BLOCKED")

    def test_missing_interface_details_block_endpoints(self):
        self.read.return_value = (True, {"interfaces_available": False})
        rows = self.by_name(self.run_suite())
        self.assertEqual(rows["Endpoint Validation"]["status"], "BLOCKED")
        self.assertEqual(rows["CDC Validation"]["status"], "BLOCKED")

    def test_composite_hid_and_storage_are_selected_from_actual_interfaces(self):
        info = deepcopy(DESCRIPTORS)
        info["interfaces"].extend([
            {"bInterfaceClass": 3, "endpoints": []}, {"bInterfaceClass": 8, "endpoints": []},
        ])
        self.read.return_value = True, info
        rows = self.by_name(self.run_suite())
        self.assertEqual(rows["HID Validation"]["status"], "PASS")
        self.assertEqual(rows["Storage Validation"]["status"], "PASS")
        passed_device = self.plugins["HID Validation"].return_value.execute.call_args.args[0]
        self.assertEqual(passed_device["usb_class"], "HID")
        self.assertEqual(DEVICE["usb_class"], "CDC")

    def test_device_loss_stops_further_operations_and_preserves_results(self):
        self.refresh.side_effect = [dict(DEVICE), ConnectionError("Device removed")]
        result = self.run_suite()
        rows = result["results"]
        self.assertEqual(rows[0]["status"], "ERROR")
        self.assertTrue(all(row["status"] == "BLOCKED" for row in rows[1:]))
        self.read.assert_not_called()
        self.assertEqual(result["status"], "ERROR")

    def test_failure_continues_and_plugin_exception_is_error(self):
        self.plugins["Enumeration Validation"].return_value.execute.return_value = {
            "status": "FAIL", "details": ["failed assertion"],
        }
        self.plugins["Descriptor Robustness Test"].return_value.execute.side_effect = RuntimeError("boom")
        rows = self.by_name(self.run_suite())
        self.assertEqual(rows["Enumeration Validation"]["status"], "FAIL")
        self.assertEqual(rows["Descriptor Robustness Test"]["status"], "ERROR")
        self.assertEqual(rows["Endpoint Validation"]["status"], "PASS")

    def test_cancel_before_start_performs_no_io(self):
        self.cancel.set()
        result = self.run_suite()
        self.refresh.assert_not_called()
        self.read.assert_not_called()
        self.assertTrue(all(row["status"] == "CANCELLED" for row in result["results"]))
        self.assertEqual(result["status"], "CANCELLED")

    def test_cancel_after_io_does_not_execute_more_plugins(self):
        def read(*args, **kwargs):
            self.cancel.set()
            return True, deepcopy(DESCRIPTORS)
        self.read.side_effect = read
        rows = self.by_name(self.run_suite())
        self.assertEqual(rows["Enumeration Validation"]["status"], "PASS")
        self.assertEqual(rows["Descriptor Validation"]["status"], "CANCELLED")
        self.plugins["Descriptor Validation"].assert_not_called()
        self.plugins["CDC Validation"].assert_not_called()

    def test_standard_suite_never_adds_stress(self):
        result = self.run_suite()
        self.assertEqual(tuple(self.by_name(result)), STANDARD)
        self.assertEqual(self.read.call_count, 1)

    def test_unique_run_ids(self):
        self.assertNotEqual(self.run_suite()["run_id"], self.run_suite()["run_id"])

    def test_check_boundaries_have_timestamps_and_separators_in_order(self):
        result = self.run_suite()
        previous_end = -1
        for row in result["results"]:
            name = row["profile"]
            start_index = next(i for i, line in enumerate(self.log) if f"START CHECK: {name}" in line)
            end_index = next(i for i, line in enumerate(self.log) if f"STOP CHECK: {name} |" in line)
            self.assertGreater(start_index, previous_end)
            self.assertGreater(end_index, start_index)
            for index in (start_index, end_index):
                self.assertRegex(self.log[index], r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]")
            self.assertEqual(self.log[end_index + 1], "--------------------")
            self.assertIn("started", row)
            self.assertIn("finished", row)
            previous_end = end_index + 1

    def run_revalidation(self, stop_at=None):
        clock = [0.0]

        def wait(seconds):
            clock[0] += seconds
            if stop_at is not None and clock[0] >= stop_at:
                self.cancel.set()
            return self.cancel.is_set()

        with (
            patch("core.test_suite.monotonic", side_effect=lambda: clock[0]),
            patch.object(self.cancel, "wait", side_effect=wait),
        ):
            return self.suite.run(
                DEVICE, True, self.cancel, self.log.append, self.progress.append,
                self.updates.append, duration_seconds=30, interval_seconds=30,
            )

    def test_thirty_second_revalidation_refreshes_all_seven_checks_at_start_and_end(self):
        result = self.run_revalidation()
        self.assertEqual(tuple(self.by_name(result)), STANDARD)
        self.assertEqual(result["validation"], {
            "requested_seconds": 30, "interval_seconds": 30,
            "elapsed_seconds": 30.0, "rounds": 2, "completed": True,
        })
        self.assertEqual(self.read.call_count, 2)
        self.assertEqual(self.refresh.call_count, 2 * 7 * 2)
        self.assertEqual(result["status"], "PASS")
        for row in result["results"]:
            self.assertEqual(row["sample_count"], 2)
            self.assertEqual(len(row["samples"]), 2)
        self.assertEqual(self.progress, sorted(self.progress))
        self.assertEqual(self.progress[-1], 100)
        self.access.assert_not_called()

    def test_revalidation_never_hides_an_earlier_failure(self):
        self.plugins["Enumeration Validation"].return_value.execute.side_effect = [
            {"status": "FAIL", "details": ["First observation failed"]},
            {"status": "PASS", "details": ["Later pass"]},
        ]
        result = self.run_revalidation()
        row = self.by_name(result)["Enumeration Validation"]
        self.assertEqual(row["status"], "FAIL")
        self.assertEqual(row["status_counts"], {"FAIL": 1, "PASS": 1})
        self.assertIn("First observation failed", row["details"])
        self.assertEqual(result["status"], "FAIL")

    def test_unavailable_descriptors_remain_blocked_for_full_window(self):
        self.read.return_value = (False, {"error": "access denied"})
        result = self.run_revalidation()
        self.assertEqual(result["validation"]["elapsed_seconds"], 30)
        self.assertEqual(self.read.call_count, 2)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(self.by_name(result)["Descriptor Validation"]["status_counts"], {"BLOCKED": 2})

    def test_revalidation_cancellation_during_wait_is_prompt_and_not_complete(self):
        result = self.run_revalidation(stop_at=12)
        self.assertEqual(result["status"], "CANCELLED")
        self.assertEqual(result["validation"]["elapsed_seconds"], 12)
        self.assertFalse(result["validation"]["completed"])
        self.assertEqual(result["validation"]["rounds"], 1)
        self.assertLess(self.progress[-1], 100)
        self.assertTrue(all(row["status"] == "CANCELLED" for row in result["results"]))

    def test_identity_change_stops_revalidation_without_waiting_full_window(self):
        calls = [0]

        def refresh(device):
            calls[0] += 1
            if calls[0] > 14:
                raise ConnectionError("Device replaced")
            return dict(device)

        self.refresh.side_effect = refresh
        result = self.run_revalidation()
        self.assertEqual(result["status"], "ERROR")
        self.assertTrue(result["identity_lost"])
        self.assertFalse(result["validation"]["completed"])
        self.assertEqual(result["validation"]["rounds"], 2)
        self.assertEqual(result["validation"]["elapsed_seconds"], 30)
        self.assertEqual(self.read.call_count, 1)

    def test_invalid_revalidation_schedule_fails_before_io(self):
        for duration, interval in ((-1, 30), (601, 30), (True, 30), (300, 0), (300, 61)):
            with self.subTest(duration=duration, interval=interval), self.assertRaises(ValueError):
                self.suite.run(
                    DEVICE, True, self.cancel, Mock(), Mock(), Mock(),
                    duration_seconds=duration, interval_seconds=interval,
                )
        self.refresh.assert_not_called()

    def test_discovered_devices_supply_their_own_identity_to_live_suite_checks(self):
        manager = COMPortManager()
        for selected in DEVICES:
            with self.subTest(port=selected["port"], vid=selected["vid"], pid=selected["pid"]):
                port = SimpleNamespace(
                    device=selected["port"], vid=int(selected["vid"], 16),
                    pid=int(selected["pid"], 16), serial_number=selected["serial"],
                    description=selected["name"], manufacturer="Synthetic vendor",
                    hwid=pnp_id(selected),
                )
                self.read.reset_mock()
                self.access.reset_mock()
                suite = ApplicableSuite(self.plugins, refresh_device, self.read)
                with (
                    patch("core.com_port_manager.list_ports.comports", return_value=[port]),
                    patch.object(manager, "_usb_devices_by_port", return_value={}),
                ):
                    discovered = manager.list_ports()
                    self.assertEqual(len(discovered), 1)
                    result = suite.run(
                        discovered[0], True, self.cancel, self.log.append,
                        self.progress.append, self.updates.append,
                    )
                for key in ("port", "vid", "pid", "serial"):
                    self.assertEqual(result["device"][key], selected[key])
                self.assertEqual(self.read.call_args.args[:2], (selected["vid"], selected["pid"]))
                self.access.assert_not_called()
                rows = self.by_name(result)
                self.assertNotIn("Serial Communication Validation Test", rows)
                self.assertNotIn("Serial Command/Response Validation", rows)
                for row in result["results"]:
                    if "observed_device" in row:
                        for key in ("port", "vid", "pid", "serial"):
                            self.assertEqual(row["observed_device"][key], selected[key])
                self.assertEqual(result["status"], "PASS")

    def test_overall_status_never_hides_blocked_or_cancelled(self):
        for statuses, expected in (
            (["PASS", "SKIPPED"], "PASS"), (["PASS", "BLOCKED"], "BLOCKED"),
            (["FAIL", "ERROR"], "ERROR"), (["PASS", "CANCELLED"], "CANCELLED"),
            (["SKIPPED"], "BLOCKED"),
        ):
            self.assertEqual(overall_status([{"status": s} for s in statuses]), expected)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.port = SimpleNamespace(
            device=DEVICE["port"], vid=int(DEVICE["vid"], 16), pid=int(DEVICE["pid"], 16),
            serial_number=DEVICE["serial"], description="Live device", manufacturer="Synthetic vendor",
        )

    def test_refresh_uses_live_identity_and_not_connected_flag(self):
        with patch("core.test_suite.list_ports.comports", return_value=[self.port]):
            current = refresh_device(dict(DEVICE, status="Disconnected"))
        self.assertEqual(current["status"], "Connected")
        self.assertEqual(current["name"], "Live device")

    def test_missing_replaced_and_unverifiable_identity_rejected(self):
        for ports in ([], [self.port, self.port]):
            with patch("core.test_suite.list_ports.comports", return_value=ports), self.assertRaises(ConnectionError):
                refresh_device(DEVICE)
        for field, value in (
            ("vid", 0x1111), ("pid", 0x2222),
            ("serial_number", "OTHER"), ("serial_number", None),
        ):
            with self.subTest(field=field):
                port = deepcopy(self.port)
                setattr(port, field, value)
                with patch("core.test_suite.list_ports.comports", return_value=[port]), self.assertRaises(ConnectionError):
                    refresh_device(DEVICE)

    def test_hardware_id_fallback_detects_replacement_without_serial(self):
        self.port.hwid = pnp_id(dict(DEVICE, serial="OTHER"))
        selected = dict(DEVICE, serial="N/A", device_id=pnp_id(dict(DEVICE, serial="EXPECTED")))
        with patch("core.test_suite.list_ports.comports", return_value=[self.port]), self.assertRaises(ConnectionError):
            refresh_device(selected)


class ExactPortDriverEvidenceTests(unittest.TestCase):
    def entity(self, device=None, **changes):
        device = DEVICE if device is None else device
        return SimpleNamespace(**{
            "Name": f"USB Serial Device ({device['port']})", "Service": "usbser",
            "DeviceID": pnp_id(device), "CompatibleID": [],
            **changes,
        })

    def test_exact_selected_port_not_first_device_with_same_vid_pid(self):
        other = self.entity(Name="USB Serial Device (COM9)", Service="vendor")
        result = match_cdc_driver(DEVICE, [other, self.entity()])
        self.assertTrue(result["confirmed"])
        self.assertEqual(result["port"], "COM6")
        self.assertEqual(result["service"], "usbser")

    def test_generic_ports_class_or_com_name_is_not_cdc_proof(self):
        result = match_cdc_driver(DEVICE, [self.entity(Service="ftser2k")])
        self.assertFalse(result["confirmed"])
        self.assertIn("alone does not prove", result["details"])

    def test_cdc_compatible_ids_can_confirm_vendor_driver(self):
        result = match_cdc_driver(DEVICE, [
            self.entity(Service="custom", CompatibleID=[r"USB\Class_02&SubClass_02&Prot_01"]),
        ])
        self.assertTrue(result["confirmed"])

    def test_cdc_evidence_tracks_different_selected_devices(self):
        entities = [self.entity(device) for device in DEVICES]
        for selected in DEVICES:
            with self.subTest(port=selected["port"]):
                result = match_cdc_driver(selected, entities)
                self.assertTrue(result["confirmed"])
                self.assertEqual(result["port"], selected["port"])
                self.assertEqual(result["device_id"], pnp_id(selected))

    def test_missing_ambiguous_mismatched_non_usb_and_wrong_serial_not_accepted(self):
        for entities in (
            [], [self.entity(), self.entity()],
            [self.entity(Name="Device (COM60)")],
            [self.entity(DeviceID=pnp_id(dict(DEVICE, vid="FFFF")))],
            [self.entity(DeviceID=pnp_id(dict(DEVICE, serial="OTHER")))],
            [self.entity(DeviceID=pnp_id(DEVICE).replace("USB\\", "PCI\\", 1))],
        ):
            with self.subTest(entities=entities):
                self.assertFalse(match_cdc_driver(DEVICE, entities)["confirmed"])

    @unittest.skipUnless(os.name == "nt", "Windows PnP query")
    def test_windows_query_is_scoped_to_port_and_balances_com_apartment(self):
        connection = Mock()
        connection.ExecQuery.return_value = [self.entity()]
        with (
            patch("pythoncom.CoInitialize") as initialize,
            patch("pythoncom.CoUninitialize") as uninitialize,
            patch("win32com.client.GetObject", return_value=connection),
        ):
            result = inspect_cdc_driver(DEVICE)
        self.assertTrue(result["confirmed"])
        self.assertIn("WHERE Name LIKE '%(COM6)'", connection.ExecQuery.call_args.args[0])
        initialize.assert_called_once()
        uninitialize.assert_called_once()

    @unittest.skipUnless(os.name == "nt", "Windows PnP query")
    def test_windows_query_error_is_explicit_and_uninitializes_com(self):
        import pythoncom
        with (
            patch("pythoncom.CoInitialize"),
            patch("pythoncom.CoUninitialize") as uninitialize,
            patch("win32com.client.GetObject", side_effect=pythoncom.com_error(-1, "denied", None, None)),
        ):
            result = inspect_cdc_driver(DEVICE)
        self.assertFalse(result["confirmed"])
        self.assertIn("query failed", result["details"])
        uninitialize.assert_called_once()


class NoCommandSerialAccessTests(unittest.TestCase):
    def test_access_uses_framing_closes_and_never_reads_or_writes(self):
        from core.hardware_helpers import cdc_check
        connection = Mock()
        with patch("serial.Serial", return_value=connection) as serial_factory:
            ok, _ = cdc_check(
                "COM6", Mock(), baudrate=38400, bytesize=8, parity="E",
                stopbits=1, read_unsolicited=False,
            )
        self.assertTrue(ok)
        self.assertEqual(serial_factory.call_args.kwargs["parity"], "E")
        self.assertEqual(serial_factory.call_args.kwargs["baudrate"], 38400)
        connection.read.assert_not_called()
        connection.write.assert_not_called()
        connection.close.assert_called_once()

    def test_access_denied_is_not_command_rejection_or_pass(self):
        import serial
        from core.hardware_helpers import cdc_check
        with patch("serial.Serial", side_effect=serial.SerialException("Access denied")):
            ok, reason = cdc_check("COM6", Mock(), read_unsolicited=False)
        self.assertFalse(ok)
        self.assertIn("Access denied", reason)


class DescriptorIdentityAndSerialCancellationTests(unittest.TestCase):
    def test_duplicate_vid_pid_is_blocked_before_descriptor_access(self):
        with (
            patch("usb.backend.libusb1.get_backend", return_value=Mock()),
            patch("usb.core.find", return_value=[Mock(), Mock()]) as find,
            patch("usb.util.dispose_resources") as dispose,
        ):
            ok, info = read_descriptors(DEVICE["vid"], DEVICE["pid"], Mock(), require_unique=True)
        self.assertFalse(ok)
        self.assertEqual(info["error"], "missing_or_ambiguous_usb_identity")
        self.assertTrue(find.call_args.kwargs["find_all"])
        dispose.assert_not_called()

    def test_descriptor_resources_released_even_when_read_fails(self):
        import usb.core
        device = Mock(spec=usb.core.Device)
        device.idVendor = int(DEVICE["vid"], 16)
        # Fail before descriptor construction completes.
        device.idProduct = object()
        with (
            patch("usb.backend.libusb1.get_backend", return_value=Mock()),
            patch("usb.core.find", return_value=[device]),
            patch("usb.util.dispose_resources") as dispose,
        ):
            ok, _ = read_descriptors(DEVICE["vid"], DEVICE["pid"], Mock(), require_unique=True)
        self.assertFalse(ok)
        dispose.assert_called_once_with(device)

    def test_serial_commands_cancel_between_exchanges(self):
        cancel = threading.Event()
        profile = deepcopy(APPROVED)
        profile["commands"] *= 2

        def exchange(*args, **kwargs):
            cancel.set()
            return True, {"response_len": 1}

        with (
            patch("plugins.serial_comm_test._hw.cdc_check", return_value=(True, "accessible")),
            patch("plugins.serial_comm_test._hw.serial_transaction", side_effect=exchange) as tx,
        ):
            result = SerialCommunicationTest().execute(
                DEVICE, Mock(), True, profile=profile, cancel_event=cancel
            )
        self.assertEqual(result["status"], "CANCELLED")
        self.assertEqual(tx.call_count, 1)


class SuiteReportTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(temp.name)
        self.reporter = ReportGenerator()
        self.result = {
            "run_id": "test123", "suite": SUITE_NAME, "device": DEVICE,
            "started": "2026-10-26T12:00:00", "finished": "2026-10-26T12:00:01",
            "mode": "LIVE HARDWARE", "status": "BLOCKED",
            "report_errors": [],
            "results": [{
                "profile": "Descriptor Validation", "status": "BLOCKED",
                "duration": 0.01, "evidence": "Unavailable <unknown>",
                "details": ["Unverified descriptor & model"], "log": ["No USB data available"],
                "observed_at": "2026-10-26T12:00:00", "observed_device": dict(DEVICE),
                "driver_evidence": {"confirmed": False, "details": "No CDC evidence"},
            }],
        }

    def test_combined_pdf_csv_only_include_evidence_and_outcomes(self):
        paths = self.reporter.export_suite(self.result, Mock())
        self.assertEqual(set(paths), {"pdf", "csv"})
        for kind, path in paths.items():
            self.assertEqual(Path(path), Path("reports", "usb", f"USB_Suite_Validation_Report.{kind}").resolve())
        self.assertEqual({path.suffix for path in Path("reports", "usb").iterdir()}, {".pdf", ".csv"})
        self.assertTrue(Path(paths["pdf"]).read_bytes().startswith(b"%PDF"))
        with Path(paths["csv"]).open(newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "BLOCKED")
        self.assertEqual(rows[0]["vid"], DEVICE["vid"])
        self.assertEqual(rows[0]["pid"], DEVICE["pid"])
        self.assertEqual(rows[0]["suite"], SUITE_NAME)
        self.assertEqual(rows[0]["overall_status"], "BLOCKED")
        self.assertEqual(rows[0]["started"], self.result["started"])
        self.assertEqual(rows[0]["finished"], self.result["finished"])
        self.assertIn("Unverified descriptor", rows[0]["details"])
        self.assertIn("No USB data available", rows[0]["log"])
        self.assertIn("serial: TEST-A", rows[0]["observed_device"])
        self.assertNotIn("{", rows[0]["observed_device"])
        self.assertIn("CDC: Communications Device Class", rows[0]["abbreviations"])
        self.assertIn("No CDC evidence", rows[0]["driver_evidence"])
        self.assertNotIn("serial_access_settings", rows[0])
        self.assertNotIn("serial_exchange", rows[0])

    def test_individual_reports_use_usb_directory(self):
        result = {"status": "PASS", "passed": 1, "total": 1}
        csv_path = Path(self.reporter.export_csv(DEVICE, "Validation", result))
        pdf_path = Path(self.reporter.export_pdf(DEVICE, "Validation", result))
        for path in (csv_path, pdf_path):
            self.assertEqual(path.parent, Path("reports", "usb"))
            self.assertTrue(path.is_file())

    def test_pdf_error_is_logged_and_persisted_in_csv(self):
        logger = Mock()
        with patch("core.report_generator.SimpleDocTemplate", side_effect=OSError("disk full")):
            paths = self.reporter.export_suite(self.result, logger)
        with Path(paths["csv"]).open(newline="", encoding="utf-8") as source:
            row = next(csv.DictReader(source))
        self.assertEqual(row["overall_status"], "ERROR")
        self.assertIn("disk full", row["report_errors"])
        self.assertEqual(self.result["status"], "ERROR")
        self.assertNotIn("pdf", paths)
        self.assertEqual(set(paths), {"csv"})
        self.assertFalse(list(Path("reports", "usb").glob("*.json")))
        self.assertTrue(logger.called)

    def test_pdf_contains_observed_identity_and_driver_evidence(self):
        from reportlab.platypus import Paragraph
        with patch("core.report_generator.Paragraph", wraps=Paragraph) as paragraph:
            self.reporter.export_suite(self.result, Mock())
        text = "\n".join(call.args[0] for call in paragraph.call_args_list)
        self.assertIn(f"{SUITE_NAME} Report", text)
        self.assertIn("Device identity", text)
        self.assertIn(DEVICE["serial"], text)
        self.assertIn("driver evidence / details:", text)
        self.assertIn("No CDC evidence", text)
        self.assertIn("Unverified descriptor &amp; model", text)
        self.assertNotIn("Serial access settings", text)

    def test_pdf_has_abbreviation_table_and_no_inline_dictionaries(self):
        from PySide6.QtPdf import QPdfDocument
        self.result["results"][0]["descriptor_snapshot"] = {
            "idVendor": "0x1234", "interfaces": [{"bInterfaceClass": 2}],
        }
        paths = self.reporter.export_suite(self.result, Mock())
        doc = QPdfDocument()
        self.assertEqual(doc.load(paths["pdf"]), QPdfDocument.Error.None_)
        text = "\n".join(doc.getAllText(page).text() for page in range(doc.pageCount()))
        doc.close()
        self.assertIn("Abbreviations", text)
        self.assertIn("Communications Device Class", text)
        self.assertIn("Vendor Identifier", text)
        self.assertIn("descriptor snapshot / interfaces / item 1 / Interface class: 2", text)
        self.assertNotIn("{", text)
        self.assertNotIn("}", text)
        self.assertNotIn("observed_device:", text)

    def test_csv_export_failure_is_explicit_without_json_fallback(self):
        logger = Mock()
        with patch.object(Path, "open", side_effect=PermissionError("CSV denied")):
            paths = self.reporter.export_suite(self.result, logger)
        self.assertEqual(set(paths), {"pdf"})
        self.assertEqual(self.result["status"], "ERROR")
        self.assertTrue(any("CSV report failed" in error for error in self.result["report_errors"]))
        self.assertTrue(any("[ERROR]" in call.args[0] for call in logger.call_args_list))
        self.assertFalse(list(Path("reports", "usb").glob("*.json")))

    def test_later_run_replaces_both_reports_using_the_same_simple_names(self):
        from PySide6.QtPdf import QPdfDocument
        first_paths = self.reporter.export_suite(self.result, Mock())
        self.result["run_id"] = "next-run"
        self.result["results"][0]["evidence"] = "Latest validation evidence"
        paths = self.reporter.export_suite(self.result, Mock())
        self.assertEqual(paths, first_paths)
        self.assertEqual(len(list(Path("reports", "usb").iterdir())), 2)
        self.assertEqual(self.result["report_errors"], [])
        with Path(paths["csv"]).open(newline="", encoding="utf-8") as source:
            row = next(csv.DictReader(source))
        self.assertEqual(row["run_id"], "next-run")
        self.assertEqual(row["evidence"], "Latest validation evidence")
        doc = QPdfDocument()
        self.assertEqual(doc.load(paths["pdf"]), QPdfDocument.Error.None_)
        text = "\n".join(doc.getAllText(page).text() for page in range(doc.pageCount()))
        doc.close()
        self.assertIn("Latest validation evidence", text)
        self.assertNotIn("Unavailable <unknown>", text)

    def test_both_export_failures_are_reported_without_json(self):
        logger = Mock()
        with (
            patch("core.report_generator.SimpleDocTemplate", side_effect=OSError("PDF denied")),
            patch.object(Path, "open", side_effect=OSError("CSV denied")),
        ):
            paths = self.reporter.export_suite(self.result, logger)
        self.assertEqual(paths, {})
        self.assertEqual(self.result["status"], "ERROR")
        self.assertEqual(len(self.result["report_errors"]), 2)
        self.assertFalse(list(Path("reports", "usb").iterdir()))

    def test_reports_use_each_selected_device_identity(self):
        for selected in DEVICES:
            with self.subTest(port=selected["port"], vid=selected["vid"], pid=selected["pid"]):
                result = deepcopy(self.result)
                result["run_id"] = f"test-{selected['port']}"
                result["device"] = deepcopy(selected)
                paths = self.reporter.export_suite(result, Mock())
                with Path(paths["csv"]).open(newline="", encoding="utf-8") as source:
                    row = next(csv.DictReader(source))
                for key in ("port", "vid", "pid", "serial"):
                    self.assertEqual(row[key], selected[key])
                self.assertEqual(row["device_name"], selected["name"])


class SuiteRunnerAndUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_stop_keeps_runner_locked_until_worker_and_reports_finish(self):
        entered = threading.Event()
        release = threading.Event()
        finished = Mock()
        with patch("core.test_runner.TestHistoryDB"), patch("core.test_runner.ReportGenerator"):
            runner = TestRunner()

        def run(*args, **kwargs):
            entered.set()
            release.wait(3)
            return {
                "status": "CANCELLED", "started": "now", "run_id": "id",
                "report_errors": [], "results": [],
            }

        with patch("core.test_runner.ApplicableSuite") as suite:
            suite.return_value.run.side_effect = run
            runner.start(SUITE_NAME, DEVICE, Mock(), Mock(), suite_finished=finished)
            try:
                self.assertTrue(entered.wait(2))
                runner.stop()
                self.assertTrue(runner.running)
                self.assertTrue(runner._stop_requested.is_set())
                runner.start("Descriptor Validation", DEVICE, Mock(), Mock())
                self.assertEqual(suite.return_value.run.call_count, 1)
                self.assertNotIn("duration_seconds", suite.return_value.run.call_args.kwargs)
            finally:
                release.set()
                runner.worker_thread.join(3)
        self.assertFalse(runner.running)
        finished.assert_called_once()
        self.assertEqual(runner.last_suite["status"], "CANCELLED")

    def test_threaded_suite_persists_one_history_row_and_combined_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            previous = os.getcwd()
            os.chdir(folder)
            runner = None
            try:
                with (
                    patch("core.test_suite.refresh_device", side_effect=lambda device: dict(device)),
                    patch("core.test_suite.hardware_helpers.read_descriptors", return_value=(True, DESCRIPTORS)),
                    patch("core.test_suite.hardware_helpers.cdc_check", return_value=(True, "port_accessible")),
                ):
                    # Pass the injected refresh explicitly because default args are bound at definition time.
                    original = ApplicableSuite
                    with patch(
                        "core.test_runner.ApplicableSuite",
                        side_effect=lambda plugins: original(
                            plugins, refresh=lambda device: dict(device)
                        ),
                    ), patch("core.test_runner.AUTO_FINISH_DELAY_SECONDS", 0):
                        runner = TestRunner()
                        done = Mock()
                        updates = []
                        runner.start(
                            SUITE_NAME, DEVICE, Mock(), Mock(), use_hardware=True,
                            suite_update=updates.append, suite_finished=done,
                        )
                        runner.worker_thread.join(5)
                    self.assertFalse(runner.running)
                    done.assert_called_once()
                    self.assertEqual(runner.last_suite["status"], "PASS")
                    self.assertEqual(len(runner.last_suite["results"]), 7)
                    self.assertEqual(
                        tuple(row["profile"] for row in runner.last_suite["results"]), STANDARD
                    )
                    self.assertTrue(any(row["status"] == "RUNNING" for row in updates))
                    files = list(Path("reports", "usb").iterdir())
                    self.assertEqual({path.suffix for path in files}, {".pdf", ".csv"})
                    with next(path for path in files if path.suffix == ".csv").open(
                        newline="", encoding="utf-8"
                    ) as source:
                        self.assertEqual(tuple(row["profile"] for row in csv.DictReader(source)), STANDARD)
                    import sqlite3
                    with closing(sqlite3.connect("usb_tests.db")) as connection:
                        self.assertEqual(connection.execute("SELECT count(*) FROM test_history").fetchone()[0], 1)
            finally:
                if runner is not None and runner.worker_thread is not None:
                    runner.stop()
                    runner.worker_thread.join(5)
                os.chdir(previous)

    def test_ui_grouped_selector_suite_callbacks_and_separate_stress_confirmation(self):
        with patch("ui.test_panel.TestRunner") as runner_class:
            runner = runner_class.return_value
            runner.running = False
            panel = TestPanel()
        self.addCleanup(panel.close)
        panel.set_selected_device(DEVICE)
        panel.profile.setCurrentText(SUITE_NAME)
        panel.hardware_checkbox.setChecked(True)
        panel.start_test()
        self.addCleanup(panel.suite_panel.close)
        self.assertFalse(panel.profile.isEnabled())
        args = runner.start.call_args
        self.assertEqual(args.args[0], SUITE_NAME)
        self.assertNotIn("include_stress", args.kwargs)
        self.assertNotIn("serial_access_settings", args.kwargs)
        self.assertNotIn("serial_exchange", args.kwargs)
        self.assertFalse(hasattr(panel, "serial_access_group"))
        args.kwargs["suite_update"]({
            "profile": "Descriptor Validation", "status": "RUNNING",
            "duration": 0, "evidence": "live", "details": [],
        })
        args.kwargs["suite_finished"]({"status": "BLOCKED", "results": [], "report_errors": []})
        QTest.qWait(10)
        self.assertEqual(panel.suite_panel.table.item(0, 1).text(), "RUNNING")
        self.assertTrue(panel.profile.isEnabled())
        for name in STANDARD:
            self.assertEqual(panel.profile.findText(name), -1)
        self.assertFalse(hasattr(panel, "stress_checkbox"))
        self.assertEqual(panel.suite_description.text().count("<li>"), 7)
        for name in STANDARD:
            self.assertIn(f"<li>{name}</li>", panel.suite_description.text())
        self.assertNotIn("Seven checks in one run", panel.suite_description.text())
        self.assertNotIn("JSON", panel.suite_description.toolTip())
        self.assertEqual(panel.profile.count(), 8)
        self.assertEqual(panel.suite_panel.windowTitle(), f"{SUITE_NAME} - Live Results")
        panel.profile.setCurrentText("Enumeration Stress Test")
        runner.start.reset_mock()
        with patch("ui.test_panel.QMessageBox.question", return_value=QMessageBox.StandardButton.No):
            panel.start_test()
        runner.start.assert_not_called()
        with patch("ui.test_panel.QMessageBox.question", return_value=QMessageBox.StandardButton.Yes):
            panel.start_test()
        self.assertEqual(runner.start.call_args.args[0], "Enumeration Stress Test")

    def test_stability_is_separate_and_requires_confirmation(self):
        with patch("ui.test_panel.TestRunner") as runner_class:
            runner = runner_class.return_value
            runner.running = False
            panel = TestPanel()
        self.addCleanup(panel.close)
        panel.set_selected_device(DEVICE)
        panel.profile.setCurrentText("Stability Validation")
        with patch("ui.test_panel.QMessageBox.question", return_value=QMessageBox.StandardButton.No):
            panel.start_test()
        runner.start.assert_not_called()
        self.assertFalse(panel.suite_active)
        with patch("ui.test_panel.QMessageBox.question", return_value=QMessageBox.StandardButton.Yes):
            panel.start_test()
        self.assertEqual(runner.start.call_args.args[0], "Stability Validation")
        self.assertNotIn("suite_update", runner.start.call_args.kwargs)

    def test_result_panel_updates_same_row_not_duplicates(self):
        panel = SuiteResultsPanel()
        self.addCleanup(panel.close)
        panel.reset(False)
        row = {"profile": "Test", "status": "PENDING", "duration": 0, "evidence": "", "details": []}
        panel.update_result(row)
        panel.update_result(dict(row, status="PASS"))
        self.assertEqual(panel.table.rowCount(), 1)
        self.assertEqual(panel.table.item(0, 1).text(), "PASS")

    def test_results_window_supports_maximize_and_reopens_without_losing_results(self):
        from PySide6.QtCore import Qt
        with patch("ui.test_panel.TestRunner") as runner_class:
            runner_class.return_value.running = False
            panel = TestPanel()
        self.addCleanup(panel.close)
        self.assertFalse(panel.view_results_btn.isEnabled())
        panel.set_selected_device(DEVICE)
        panel.start_test()
        results = panel.suite_panel
        self.addCleanup(results.close)
        self.assertTrue(results.windowFlags() & Qt.WindowMaximizeButtonHint)
        self.assertTrue(panel.view_results_btn.isEnabled())
        row = {"profile": STANDARD[0], "status": "PASS", "duration": 1, "evidence": "fresh", "details": []}
        panel.update_suite_row(row)
        panel.finish_suite({"status": "PASS", "results": [row], "report_paths": {}})
        results.close()
        self.assertFalse(results.isVisible())
        panel.view_results_btn.click()
        self.assertTrue(results.isVisible())
        self.assertEqual(results.table.item(0, 1).text(), "PASS")
        results.showMaximized()
        self.app.processEvents()
        self.assertTrue(results.isMaximized())
        results.close()
        panel.view_results_btn.click()
        self.assertTrue(results.isVisible())
        self.assertEqual(results.table.rowCount(), 1)
        self.assertEqual(runner_class.return_value.start.call_count, 1)

    def test_bullet_list_renders_each_check_without_widening_panel(self):
        with patch("ui.test_panel.TestRunner"):
            panel = TestPanel()
        self.addCleanup(panel.close)
        panel.resize(340, 500)
        panel.show()
        self.app.processEvents()
        label = panel.suite_description
        document = QTextDocument()
        document.setHtml(label.text())
        self.assertEqual(document.toPlainText().strip().splitlines(), list(STANDARD))
        self.assertGreaterEqual(label.height(), label.heightForWidth(label.width()))
        width_with_list = panel.minimumSizeHint().width()
        label.hide()
        self.app.processEvents()
        self.assertEqual(panel.minimumSizeHint().width(), width_with_list)
        panel.profile.setCurrentText("Serial Console")
        self.assertFalse(label.isVisible())

    def test_report_center_lists_only_pdf_csv_and_preserves_old_json(self):
        with tempfile.TemporaryDirectory() as folder:
            for name in ("run.pdf", "run.csv", "old.json", "notes.txt"):
                Path(folder, name).write_text("fixture", encoding="utf-8")
            panel = ReportCenter()
            self.addCleanup(panel.close)
            panel.reports_dir = folder
            panel.load_reports()
            self.assertEqual(panel.table.rowCount(), 2)
            self.assertEqual(
                {panel.table.item(row, 1).text() for row in range(2)}, {"PDF", "CSV"}
            )
            self.assertTrue(Path(folder, "old.json").exists())
            with patch("ui.report_center.os.startfile") as open_file:
                panel.table.selectRow(0)
                panel.open_report()
            self.assertIn(Path(open_file.call_args.args[0]).suffix, (".pdf", ".csv"))

    def test_report_center_uses_only_usb_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            previous = os.getcwd()
            try:
                os.chdir(folder)
                usb = Path("reports", "usb")
                ethernet = Path("reports", "ethernetip")
                usb.mkdir(parents=True)
                ethernet.mkdir(parents=True)
                (usb / "usb.pdf").write_text("usb", encoding="utf-8")
                (ethernet / "ethernet.pdf").write_text("ethernet", encoding="utf-8")
                panel = ReportCenter()
                try:
                    self.assertEqual(Path(panel.reports_dir), usb.resolve())
                    self.assertEqual(panel.table.rowCount(), 1)
                    self.assertEqual(panel.table.item(0, 0).text(), "usb.pdf")
                finally:
                    panel.close()
            finally:
                os.chdir(previous)

    def test_serial_console_is_the_only_serial_selector_workflow(self):
        with patch("ui.test_panel.TestRunner") as runner_class:
            runner = runner_class.return_value
            runner.running = False
            panel = TestPanel()
        self.addCleanup(panel.close)
        panel.set_selected_device(DEVICE)
        self.assertGreaterEqual(panel.profile.findText("Serial Console"), 0)
        self.assertEqual(panel.profile.findText("Serial Communication Validation Test"), -1)
        for name in ("suite_baud", "configure_exchange_btn", "enable_exchange"):
            self.assertFalse(hasattr(panel, name))


if __name__ == "__main__":
    unittest.main()
