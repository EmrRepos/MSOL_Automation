from plugins.base import TestPlugin
from core import hardware_helpers as _hw


class DescriptorTest(TestPlugin):

    name = "Descriptor Validation"

    def execute(self, device, logger, use_hardware=False):

        logger(
            "[INFO] Starting Descriptor Validation"
        )

        logger(
            "--------------------------------"
        )

        logger(
            "[INFO] Device Information"
        )

        logger(
            f"Name      : {device.get('name', 'Unknown')}"
        )

        logger(
            f"VID       : {device.get('vid', 'N/A')}"
        )

        logger(
            f"PID       : {device.get('pid', 'N/A')}"
        )

        logger(
            f"USB Class : {device.get('usb_class', 'Unknown')}"
        )

        logger(
            f"Subclass  : {device.get('subclass', 'Unknown')}"
        )

        logger(
            f"Mfr       : {device.get('manufacturer', 'Unknown')}"
        )

        logger(
            f"Serial    : {device.get('serial', 'N/A')}"
        )

        logger(
            f"Driver    : {device.get('service', 'N/A')}"
        )

        logger(
            f"Port      : {device.get('port', 'N/A')}"
        )

        logger(
            "--------------------------------"
        )

        checks = []
        details = []

        if (
            device.get("name")
            and device.get("name") != "Unknown Device"
        ):

            logger(
                "[PASS] Device Name Present"
            )

            checks.append(True)

            details.append(
                "Device Name Present"
            )

        else:

            logger(
                "[FAIL] Device Name Missing"
            )

            checks.append(False)

        if (
            device.get("vid")
            and device.get("vid") != "N/A"
        ):

            logger(
                f"[PASS] VID Found : {device['vid']}"
            )

            checks.append(True)

            details.append(
                "VID Present"
            )

        else:

            logger(
                "[FAIL] VID Missing"
            )

            checks.append(False)

        if (
            device.get("pid")
            and device.get("pid") != "N/A"
        ):

            logger(
                f"[PASS] PID Found : {device['pid']}"
            )

            checks.append(True)

            details.append(
                "PID Present"
            )

        else:

            logger(
                "[FAIL] PID Missing"
            )

            checks.append(False)

        if (
            device.get("usb_class")
            and device.get("usb_class") != "Unknown"
        ):

            logger(
                f"[PASS] USB Class : {device['usb_class']}"
            )

            checks.append(True)

            details.append(
                "USB Class Detected"
            )

        else:

            logger(
                "[FAIL] USB Class Missing"
            )

            checks.append(False)

        if device.get("status") == "Connected":

            logger(
                "[PASS] Device Connected"
            )

            checks.append(True)

            details.append(
                "Device Connected"
            )

        else:

            logger(
                "[FAIL] Device Not Connected"
            )

            checks.append(False)

        total = len(checks)
        passed = sum(checks)

        logger(
            f"[INFO] Checks Passed : {passed}/{total}"
        )

        # If hardware mode requested, attempt to read descriptors via pyusb
        if use_hardware and device.get("vid") and device.get("pid"):
            try:
                ok, info = _hw.read_descriptors(device.get("vid"), device.get("pid"), logger)
                if ok:
                    details.append("Descriptors read via pyusb")
                    passed += 1
                    total += 1
                    logger("[PASS] Descriptor read via hardware")

                    bcd_usb = info.get("bcdUSB")
                    if bcd_usb:
                        logger(f"[INFO] USB Specification : {bcd_usb}")
                        details.append(f"USB spec {bcd_usb}")

                    bcd_device = info.get("bcdDevice")
                    if bcd_device:
                        logger(
                            f"[INFO] Device Firmware Revision : {bcd_device}"
                        )
                        details.append(f"Firmware revision {bcd_device}")

                    strings = info.get("strings") or {}
                    if strings:
                        for label, value in strings.items():
                            logger(f"[INFO] {label} : {value}")
                        details.append(
                            f"String descriptors: {len(strings)}"
                        )
                    else:
                        logger(
                            "[INFO] String descriptors unavailable "
                            "(device bound to a native class driver)"
                        )
                else:
                    logger(f"[WARN] Descriptor read failed: {info}")
                    total += 1
                    # leave passed unchanged
            except Exception as ex:
                logger(f"[WARN] Hardware descriptor read error: {ex}")
                total += 1
        if passed == total:

            logger(
                "[PASS] Descriptor Validation Successful"
            )

            return {
                "status": "PASS",
                "passed": passed,
                "total": total,
                "details": details
            }

        logger(
            "[FAIL] Descriptor Validation Failed"
        )

        return {
            "status": "FAIL",
            "passed": passed,
            "total": total,
            "details": details
        }