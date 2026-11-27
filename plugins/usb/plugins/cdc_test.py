from plugins.base import TestPlugin
from core import hardware_helpers as _hw


class CDCValidationTest(TestPlugin):

    name = "CDC Validation"

    def execute(self, device, logger, use_hardware=False):

        logger(
            "[INFO] Starting CDC Validation"
        )

        logger(
            "--------------------------------"
        )

        logger(
            "[INFO] CDC Information"
        )

        logger(
            f"Device Name : {device.get('name','Unknown')}"
        )

        logger(
            f"COM Port    : {device.get('port','N/A')}"
        )

        logger(
            f"VID         : {device.get('vid','N/A')}"
        )

        logger(
            f"PID         : {device.get('pid','N/A')}"
        )

        logger(
            "--------------------------------"
        )

        checks = []
        details = []

        if device.get("usb_class") == "CDC":

            logger(
                "[PASS] CDC Device Detected"
            )

            checks.append(True)

            details.append(
                "CDC Class Detected"
            )

        else:

            logger(
                "[FAIL] Device Is Not CDC"
            )

            checks.append(False)

        port = device.get(
            "port",
            "N/A"
        )

        if port != "N/A":

            logger(
                f"[PASS] COM Port Assigned : {port}"
            )

            checks.append(True)

            details.append(
                f"COM Port {port}"
            )

        else:

            logger(
                "[FAIL] COM Port Not Assigned"
            )

            checks.append(False)

        # If hardware mode requested, verify that the serial port is usable
        if use_hardware and port != "N/A":
            try:
                success, info = _hw.cdc_check(port, logger)
                if success:
                    logger("[PASS] CDC serial port accessible")
                    checks.append(True)
                    details.append("Serial port accessible")
                else:
                    logger(f"[FAIL] Serial port check failed: {info}")
                    checks.append(False)
            except Exception as ex:
                logger(f"[WARN] Hardware CDC check error: {ex}")
                checks.append(False)

        if device.get("vid") != "N/A":

            logger(
                "[PASS] VID Present"
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

        if device.get("pid") != "N/A":

            logger(
                "[PASS] PID Present"
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

        if device.get("status") == "Connected":

            logger(
                "[PASS] Device Connected"
            )

            checks.append(True)

            details.append(
                "Connected"
            )

        else:

            logger(
                "[FAIL] Device Not Connected"
            )

            checks.append(False)

        total = len(checks)
        passed = sum(checks)

        logger(
            f"[INFO] CDC Validation Result : {passed}/{total}"
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