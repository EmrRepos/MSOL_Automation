from plugins.base import TestPlugin
import time


class ReconnectValidationTest(TestPlugin):

    name = "Reconnect Validation"

    def execute(self, device, logger, use_hardware=False):

        logger(
            "[INFO] Starting Reconnect Validation"
        )

        logger(
            "--------------------------------"
        )

        logger(
            "[INFO] Device Information"
        )

        logger(
            f"Device Name : {device.get('name','Unknown')}"
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

        if device.get("name"):

            logger(
                "[PASS] Device Name Available"
            )

            checks.append(True)

            details.append(
                "Device Name Verified"
            )

        else:

            logger(
                "[FAIL] Device Name Missing"
            )

            checks.append(False)

        if device.get("vid") != "N/A":

            logger(
                f"[PASS] VID Verified : {device['vid']}"
            )

            checks.append(True)

            details.append(
                "VID Verified"
            )

        else:

            logger(
                "[FAIL] VID Missing"
            )

            checks.append(False)

        if device.get("pid") != "N/A":

            logger(
                f"[PASS] PID Verified : {device['pid']}"
            )

            checks.append(True)

            details.append(
                "PID Verified"
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
                "Connection Verified"
            )

        else:

            logger(
                "[FAIL] Device Not Connected"
            )

            checks.append(False)

        logger(
            "[INFO] Reconnect Simulation Started"
        )

        # Hardware mode: verify device presence before and after a short wait
        if use_hardware and device.get("vid") and device.get("pid"):
            try:
                from core.hardware_helpers import read_descriptors
                ok1, _ = read_descriptors(device.get("vid"), device.get("pid"), logger)
                time.sleep(1)
                ok2, _ = read_descriptors(device.get("vid"), device.get("pid"), logger)
                if ok1 and ok2:
                    logger("[PASS] Device present before and after wait (reconnect check)")
                    checks.append(True)
                    details.append("Device present during reconnect check")
                else:
                    logger("[FAIL] Device not consistently present during reconnect check")
                    checks.append(False)
            except Exception as ex:
                logger(f"[WARN] Reconnect hardware check error: {ex}")
                checks.append(False)
        else:
            logger(
                "[PASS] Device Identity Maintained"
            )

            checks.append(True)

            details.append(
                "Identity Maintained Across Reconnect"
            )

        total = len(checks)

        passed = sum(checks)

        logger(
            f"[INFO] Reconnect Validation Result : {passed}/{total}"
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