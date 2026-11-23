from plugins.base import TestPlugin


class EnumerationTest(TestPlugin):

    name = "Enumeration Validation"

    def execute(self, device, logger, use_hardware=False):

        logger(
            "[INFO] Starting Enumeration Validation"
        )

        logger(
            "--------------------------------"
        )

        logger(
            "[INFO] Enumeration Information"
        )

        logger(
            f"Device Name : {device.get('name', 'Unknown')}"
        )

        logger(
            f"VID         : {device.get('vid', 'N/A')}"
        )

        logger(
            f"PID         : {device.get('pid', 'N/A')}"
        )

        logger(
            f"USB Class   : {device.get('usb_class', 'Unknown')}"
        )

        logger(
            "--------------------------------"
        )

        checks = []
        details = []

        if device.get("name"):

            logger("[PASS] Device Found")

            checks.append(True)

            details.append(
                "Device Enumeration Successful"
            )

        else:

            logger("[FAIL] Device Missing")

            checks.append(False)

        vid = device.get(
            "vid",
            "N/A"
        )

        if vid != "N/A":

            logger("[PASS] VID Available")

            checks.append(True)

            details.append(
                "VID Retrieved"
            )

        else:

            logger("[FAIL] VID Missing")

            checks.append(False)

        pid = device.get(
            "pid",
            "N/A"
        )

        if pid != "N/A":

            logger("[PASS] PID Available")

            checks.append(True)

            details.append(
                "PID Retrieved"
            )

        else:

            logger("[FAIL] PID Missing")

            checks.append(False)

        usb_class = device.get(
            "usb_class",
            "Unknown"
        )

        if usb_class != "Unknown":

            logger(
                f"[PASS] USB Class : {usb_class}"
            )

            checks.append(True)

            details.append(
                "USB Class Available"
            )

        else:

            logger(
                "[FAIL] USB Class Unknown"
            )

            checks.append(False)

        if device.get("status") == "Connected":

            logger(
                "[PASS] Device Connected"
            )

            checks.append(True)

            details.append(
                "Connection State Verified"
            )

        else:

            logger(
                "[FAIL] Device Not Connected"
            )

            checks.append(False)

        total = len(checks)

        passed = sum(checks)

        # Hardware: verify device is present via pyusb
        if use_hardware and device.get("vid") and device.get("pid"):
            try:
                from core.hardware_helpers import read_descriptors
                ok, info = read_descriptors(device.get("vid"), device.get("pid"), logger)
                total += 1
                if ok:
                    logger("[PASS] Device discovered via pyusb")
                    passed += 1
                    details.append("Discovered via pyusb")
                else:
                    logger("[FAIL] Device not found via pyusb")
                    details.append(f"pyusb: {info}")
            except Exception as ex:
                logger(f"[WARN] Enumeration hardware check error: {ex}")
                total += 1
                details.append(f"Enumeration check error: {ex}")

        logger(
            f"[INFO] Enumeration Result : {passed}/{total}"
        )

        return {
            "status":
                "PASS"
                if passed == total
                else "FAIL",

            "passed": passed,

            "total": total,

            "details": details
        }