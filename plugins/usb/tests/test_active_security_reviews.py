import unittest
from unittest.mock import patch

from core import findings
from core.findings import (
    Finding, FindingReport, CONFIRMED, INCONCLUSIVE, NOT_AFFECTED,
    ATTACK_SURFACE, VULNERABILITY, CRITICAL, HIGH, MEDIUM, INFO, LOW,
)
from plugins.cdc_security_review import CDCSecurityReview
from plugins.hid_attack_surface_review import HIDAttackSurfaceReview
from plugins.storage_exposure_review import StorageExposureReview


def sink():
    logs = []
    return logs, logs.append


def assert_contract(testcase, result):
    testcase.assertIn(result["status"], ("PASS", "FAIL"))
    testcase.assertIsInstance(result["passed"], int)
    testcase.assertIsInstance(result["total"], int)
    testcase.assertIsInstance(result["details"], list)
    testcase.assertLessEqual(result["passed"], result["total"])
    testcase.assertGreaterEqual(result["passed"], 0)


class FindingModelTests(unittest.TestCase):
    def test_confirmed_info_is_not_a_vulnerability(self):
        f = Finding("port open", severity=INFO, status=CONFIRMED)
        self.assertFalse(f.is_vulnerability)
        self.assertEqual(f.tag(), "[INFO]")

    def test_confirmed_medium_is_a_vulnerability(self):
        f = Finding("accepts commands", severity=MEDIUM, status=CONFIRMED)
        self.assertTrue(f.is_vulnerability)
        self.assertEqual(f.tag(), "[VULN]")

    def test_confirmed_attack_surface_is_not_a_vulnerability(self):
        # The core correction: confirming a capability is attack surface,
        # never a vulnerability, regardless of severity.
        f = Finding(
            "keyboard interface present", severity=MEDIUM,
            status=CONFIRMED, category=ATTACK_SURFACE,
        )
        self.assertFalse(f.is_vulnerability)
        self.assertTrue(f.is_attack_surface)
        self.assertEqual(f.tag(), "[SURFACE]")

    def test_attack_surface_does_not_fail_a_review(self):
        logs, logger = sink()
        report = FindingReport(logger)
        report.add(Finding(
            "storage interface present", severity=MEDIUM,
            status=CONFIRMED, category=ATTACK_SURFACE,
        ))
        result = report.result()
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(any("ATTACK_SURFACE" in d for d in result["details"]))

    def test_inconclusive_never_counts_as_vulnerability(self):
        f = Finding("cannot verify", severity=MEDIUM, status=INCONCLUSIVE)
        self.assertFalse(f.is_vulnerability)

    def test_report_fails_only_on_confirmed_vuln(self):
        logs, logger = sink()
        report = FindingReport(logger)
        report.add(Finding("ctx", severity=INFO, status=CONFIRMED))
        report.add(Finding("maybe", severity=MEDIUM, status=INCONCLUSIVE))
        result = report.result()
        self.assertEqual(result["status"], "PASS")

        report.add(Finding("vuln", severity=MEDIUM, status=CONFIRMED))
        result = report.result()
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["total"] - result["passed"], 1)


class CDCActiveProbeTests(unittest.TestCase):
    def setUp(self):
        self.device = {
            "name": "Micro Motion 5700 USB Port (COM6)",
            "vid": "15A2", "pid": "0400", "usb_class": "CDC",
            "port": "COM6", "status": "Connected",
        }

    def test_hardware_off_is_inconclusive_not_a_finding(self):
        logs, logger = sink()
        result = CDCSecurityReview().execute(self.device, logger, use_hardware=False)
        assert_contract(self, result)
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(any("not actively tested" in d.lower() for d in result["details"]))

    def test_readonly_response_is_attack_surface_not_vulnerability(self):
        logs, logger = sink()
        with (
            patch("plugins.cdc_security_review._hw.cdc_check", return_value=(True, "port_accessible")),
            patch(
                "plugins.cdc_security_review._hw.serial_transaction",
                return_value=(True, {
                    "request": "6f 11 ec 4c",
                    "response": "6f 91 01 ed 8d",
                    "response_len": 5,
                }),
            ),
        ):
            result = CDCSecurityReview().execute(self.device, logger, use_hardware=True)
        assert_contract(self, result)
        # A read-only reply is attack surface, not a confirmed vulnerability.
        self.assertEqual(result["status"], "PASS")
        joined = "\n".join(logs)
        self.assertIn("[SURFACE]", joined)
        self.assertIn("read-only", joined.lower())
        self.assertIn("6f 11 ec 4c", joined)    # TX evidence still present
        self.assertIn("6f 91 01 ed 8d", joined)  # RX evidence still present
        self.assertNotIn("[VULN]", joined)

    def test_state_changing_command_requires_optin_and_is_not_sent(self):
        logs, logger = sink()
        profile = {"commands": [
            {"name": "read id", "payload": "hex:6f 11"},
            {"name": "write preset", "payload": "hex:6f 06", "state_changing": True},
        ]}
        with (
            patch("plugins.cdc_security_review._hw.cdc_check", return_value=(True, "port_accessible")),
            patch("plugins.cdc_security_review._profiles.find_profile", return_value=profile),
            patch("plugins.cdc_security_review._profiles.serial_settings", return_value={}),
            patch(
                "plugins.cdc_security_review._hw.serial_transaction",
                return_value=(True, {"request": "6f 11", "response": "6f 91", "response_len": 2}),
            ) as tx,
        ):
            result = CDCSecurityReview().execute(self.device, logger, use_hardware=True)
        assert_contract(self, result)
        # Only the read-only command is sent; the state-changing one is withheld.
        self.assertEqual(tx.call_count, 1)
        joined = "\n".join(logs)
        self.assertIn("opt-in required", joined.lower())
        self.assertEqual(result["status"], "PASS")  # nothing confirmed as a vuln

    def test_state_changing_command_accepted_is_confirmed_vulnerability(self):
        logs, logger = sink()
        device = dict(self.device, active_write_opt_in=True)
        profile = {"commands": [
            {"name": "write preset", "payload": "hex:6f 06", "state_changing": True},
        ]}
        with (
            patch("plugins.cdc_security_review._hw.cdc_check", return_value=(True, "port_accessible")),
            patch("plugins.cdc_security_review._profiles.find_profile", return_value=profile),
            patch("plugins.cdc_security_review._profiles.serial_settings", return_value={}),
            patch(
                "plugins.cdc_security_review._hw.serial_transaction",
                return_value=(True, {"request": "6f 06 ..", "response": "6f 06 ok", "response_len": 4}),
            ) as tx,
        ):
            result = CDCSecurityReview().execute(device, logger, use_hardware=True)
        assert_contract(self, result)
        self.assertEqual(tx.call_count, 1)
        joined = "\n".join(logs)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("[VULN]", joined)
        self.assertIn("state-changing", joined.lower())
        self.assertIn("boundary", joined.lower())

    def test_no_response_is_inconclusive_not_confirmed(self):
        logs, logger = sink()
        with (
            patch("plugins.cdc_security_review._hw.cdc_check", return_value=(True, "port_accessible")),
            patch(
                "plugins.cdc_security_review._hw.serial_transaction",
                return_value=(False, {"error": "no_response", "response_len": 0}),
            ),
        ):
            result = CDCSecurityReview().execute(self.device, logger, use_hardware=True)
        assert_contract(self, result)
        self.assertEqual(result["status"], "PASS")
        self.assertNotIn("accepts and responds", "\n".join(logs))

    def test_unprofiled_device_does_not_send_arbitrary_bytes(self):
        logs, logger = sink()
        unknown = dict(self.device, name="Serial Thing", vid="1234", pid="ABCD")
        with (
            patch("plugins.cdc_security_review._hw.cdc_check", return_value=(True, "port_accessible")),
            patch("plugins.cdc_security_review._hw.serial_transaction") as tx,
        ):
            result = CDCSecurityReview().execute(unknown, logger, use_hardware=True)
            tx.assert_not_called()  # no profile command -> nothing sent
        assert_contract(self, result)
        self.assertTrue(any("not verified" in d.lower() for d in result["details"]))


class HIDActiveProbeTests(unittest.TestCase):
    def setUp(self):
        self.device = {
            "name": "USB Keyboard", "vid": "046D", "pid": "C31C",
            "usb_class": "HID", "status": "Connected",
        }

    def test_boot_keyboard_descriptor_is_attack_surface_not_vulnerability(self):
        logs, logger = sink()
        desc = {"interfaces_available": True, "interfaces": [
            {"bInterfaceNumber": 0, "bInterfaceClass": 0x03, "bInterfaceProtocol": 1},
        ]}
        with patch("plugins.hid_attack_surface_review._hw.read_descriptors", return_value=(True, desc)):
            result = HIDAttackSurfaceReview().execute(self.device, logger, use_hardware=True)
        assert_contract(self, result)
        joined = "\n".join(logs)
        # Confirming a keyboard interface is attack surface, not a vulnerability.
        self.assertEqual(result["status"], "PASS")
        self.assertIn("[SURFACE]", joined)
        self.assertIn("keystroke-injection capable", joined)
        self.assertIn("bInterfaceProtocol=1", joined)
        self.assertNotIn("[VULN]", joined)

    def test_blocked_descriptor_is_inconclusive_not_faked(self):
        logs, logger = sink()
        desc = {"interfaces_available": False, "interfaces": [], "interfaces_error": "NotImplementedError"}
        with patch("plugins.hid_attack_surface_review._hw.read_descriptors", return_value=(True, desc)):
            result = HIDAttackSurfaceReview().execute(self.device, logger, use_hardware=True)
        assert_contract(self, result)
        self.assertEqual(result["status"], "PASS")  # nothing confirmed
        self.assertIn("[INCONCLUSIVE]", "\n".join(logs))
        self.assertNotIn("[VULN]", "\n".join(logs))

    def test_hardware_off_is_potential_based_on_name(self):
        logs, logger = sink()
        result = HIDAttackSurfaceReview().execute(self.device, logger, use_hardware=False)
        assert_contract(self, result)
        self.assertIn("[POTENTIAL]", "\n".join(logs))
        self.assertIn("not actively verified", "\n".join(logs).lower())

    def test_non_hid_is_not_affected(self):
        logs, logger = sink()
        dev = {"name": "USB Hub", "vid": "1A40", "pid": "0101", "usb_class": "Hub", "status": "Connected"}
        result = HIDAttackSurfaceReview().execute(dev, logger, use_hardware=True)
        assert_contract(self, result)
        self.assertEqual(result["status"], "PASS")


class StorageActiveProbeTests(unittest.TestCase):
    def test_mass_storage_interface_is_attack_surface_not_vulnerability(self):
        logs, logger = sink()
        dev = {"name": "USB Flash Disk", "vid": "0781", "pid": "5567", "usb_class": "Mass Storage", "status": "Connected"}
        desc = {"interfaces_available": True, "interfaces": [
            {"bInterfaceNumber": 0, "bInterfaceClass": 0x08, "bInterfaceSubClass": 6, "bInterfaceProtocol": 0x50},
        ]}
        with patch("plugins.storage_exposure_review._hw.read_descriptors", return_value=(True, desc)):
            result = StorageExposureReview().execute(dev, logger, use_hardware=True)
        assert_contract(self, result)
        joined = "\n".join(logs)
        self.assertEqual(result["status"], "PASS")
        self.assertIn("[SURFACE]", joined)
        self.assertIn("Mass Storage interface", joined)
        self.assertNotIn("[VULN]", joined)

    def test_non_storage_not_affected(self):
        logs, logger = sink()
        dev = {"name": "Webcam", "vid": "0BDA", "pid": "5570", "usb_class": "Video", "status": "Connected"}
        result = StorageExposureReview().execute(dev, logger, use_hardware=False)
        assert_contract(self, result)
        self.assertEqual(result["status"], "PASS")


class CrashSafetyTests(unittest.TestCase):
    DEVICES = [
        {"name": "Micro Motion (COM6)", "vid": "15A2", "pid": "0400", "usb_class": "CDC", "port": "COM6", "status": "Connected"},
        {"name": "USB Keyboard", "vid": "046D", "pid": "C31C", "usb_class": "HID", "status": "Connected"},
        {"name": "USB Flash Disk", "vid": "0781", "pid": "5567", "usb_class": "Mass Storage", "status": "Connected"},
        {},  # empty device record must not crash
    ]

    def test_reviews_never_crash(self):
        reviews = [CDCSecurityReview(), HIDAttackSurfaceReview(), StorageExposureReview()]
        # Force hardware helpers to behave as if nothing is attached.
        with (
            patch("plugins.cdc_security_review._hw.cdc_check", return_value=(False, "open_failed")),
            patch("plugins.cdc_security_review._hw.serial_transaction", return_value=(False, {"response_len": 0, "error": "no_response"})),
            patch("plugins.hid_attack_surface_review._hw.read_descriptors", return_value=(False, {"error": "pyusb_missing"})),
            patch("plugins.storage_exposure_review._hw.read_descriptors", return_value=(False, {"error": "pyusb_missing"})),
        ):
            for review in reviews:
                for dev in self.DEVICES:
                    for hw in (False, True):
                        logs, logger = sink()
                        result = review.execute(dev, logger, use_hardware=hw)
                        assert_contract(self, result)


if __name__ == "__main__":
    unittest.main()
