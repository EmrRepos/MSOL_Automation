import unittest
from unittest.mock import patch

from core.test_runner import TestRunner


def device_for(plugin_name):
    device = {
        "name": "Synthetic USB Device",
        "vid": "1234",
        "pid": "5678",
        "usb_class": "CDC",
        "status": "Connected",
    }

    if "HID" in plugin_name:
        device.update(name="Synthetic HID Keyboard", usb_class="HID")
    elif "Storage" in plugin_name:
        device.update(name="Synthetic USB Storage", usb_class="Mass Storage")

    if "CDC" in plugin_name or "Serial" in plugin_name:
        device["port"] = "COM6"

    return device


class PluginMockModeTests(unittest.TestCase):
    def test_registered_plugins_run_without_hardware_access(self):
        with (
            patch("core.test_runner.TestHistoryDB"),
            patch("core.test_runner.ReportGenerator"),
        ):
            plugins = TestRunner().plugins

        with (
            patch(
                "core.hardware_helpers.read_descriptors",
                side_effect=AssertionError("descriptor access in mock mode"),
            ) as read_descriptors,
            patch(
                "core.hardware_helpers.cdc_check",
                side_effect=AssertionError("serial access in mock mode"),
            ) as cdc_check,
            patch(
                "core.hardware_helpers.serial_transaction",
                side_effect=AssertionError("serial transaction in mock mode"),
            ) as serial_transaction,
        ):
            for name, plugin_type in plugins.items():
                with self.subTest(plugin=name):
                    logs = []
                    result = plugin_type().execute(
                        device_for(name), logs.append, use_hardware=False
                    )

                    self.assertIn(result["status"], ("PASS", "FAIL"))
                    self.assertIsInstance(result["passed"], int)
                    self.assertIsInstance(result["total"], int)
                    self.assertIsInstance(result["details"], list)
                    self.assertGreaterEqual(result["passed"], 0)
                    self.assertLessEqual(result["passed"], result["total"])
                    self.assertTrue(logs)

            read_descriptors.assert_not_called()
            cdc_check.assert_not_called()
            serial_transaction.assert_not_called()
