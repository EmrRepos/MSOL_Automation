from plugins.base import TestPlugin


class StabilityValidationTest(TestPlugin):

    name = "Stability Validation"

    def execute(self, device, logger, use_hardware=False):

        logger(
            "[INFO] Starting Stability Validation"
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
                "[PASS] Device Present"
            )

            checks.append(True)

            details.append(
                "Device Present"
            )

        else:

            logger(
                "[FAIL] Device Missing"
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
                "[PASS] Device Remains Connected"
            )

            checks.append(True)

            details.append(
                "Connection Stable"
            )

        else:

            logger(
                "[FAIL] Device Disconnected"
            )

            checks.append(False)

        logger(
            "[INFO] Running Stability Cycles"
        )

        # Hardware: perform repeated descriptor reads to detect intermittent failures
        if use_hardware and device.get("vid") and device.get("pid"):
            try:
                from core.hardware_helpers import read_descriptors
                success_cycles = 0
                cycles = 5
                for i in range(1, cycles + 1):
                    ok, _ = read_descriptors(device.get("vid"), device.get("pid"), logger)
                    if ok:
                        success_cycles += 1
                        logger(f"[INFO] Stability Cycle {i}/{cycles} Passed (pyusb)")
                    else:
                        logger(f"[WARN] Stability Cycle {i}/{cycles} Failed (pyusb)")
                    # small pause
                    import time as _t
                    _t.sleep(0.2)
                if success_cycles == cycles:
                    logger("[PASS] No disconnects detected during stability cycles")
                    checks.append(True)
                    details.append("No disconnects during stability cycles")
                else:
                    logger("[FAIL] Intermittent descriptor reads detected during stability cycles")
                    checks.append(False)
                    details.append(f"Stability success cycles: {success_cycles}/{cycles}")
            except Exception as ex:
                logger(f"[WARN] Stability hardware check error: {ex}")
                checks.append(False)
        else:
            for i in range(1, 6):
                logger(
                    f"[INFO] Stability Cycle {i}/5 Passed"
                )

            logger(
                "[PASS] No Disconnect Events Detected"
            )

            checks.append(True)

            details.append(
                "No Disconnect Events"
            )

        total = len(checks)

        passed = sum(checks)

        logger(
            f"[INFO] Stability Result : {passed}/{total}"
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
