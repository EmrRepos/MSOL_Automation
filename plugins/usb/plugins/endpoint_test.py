from plugins.base import TestPlugin


class EndpointValidationTest(TestPlugin):

    name = "Endpoint Validation"

    def execute(self, device, logger, use_hardware=False):

        logger(
            "[INFO] Starting Endpoint Validation"
        )

        logger(
            "--------------------------------"
        )

        logger(
            "[INFO] Endpoint Validation Information"
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
            f"USB Class   : {device.get('usb_class','Unknown')}"
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

        if device.get("pid") != "N/A":

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

        if device.get("usb_class"):

            logger(
                f"[PASS] USB Class : {device['usb_class']}"
            )

            checks.append(True)

            details.append(
                "USB Class Available"
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
                "Connected"
            )

        else:

            logger(
                "[FAIL] Device Not Connected"
            )

            checks.append(False)

        logger(
            "[INFO] Endpoint Details Not Yet Implemented"
        )

        total = len(checks)
        passed = sum(checks)

        # Hardware: inspect endpoints via pyusb
        if use_hardware and device.get("vid") and device.get("pid"):
            try:
                from core.hardware_helpers import read_descriptors
                ok, info = read_descriptors(device.get("vid"), device.get("pid"), logger)
                if ok and info.get("interfaces_available"):
                    ep_count = 0
                    for intf in info.get("interfaces", []):
                        ep_count += len(intf.get("endpoints", []))
                    logger(f"[INFO] Endpoint count (pyusb): {ep_count}")
                    total += 1
                    if ep_count > 0:
                        logger("[PASS] Endpoints present")
                        details.append(f"Endpoints: {ep_count}")
                        passed += 1
                    else:
                        logger("[FAIL] No endpoints detected via pyusb")
                        details.append("No endpoints detected")
                elif ok:
                    logger(
                        "[WARN] Endpoint descriptors not readable on this "
                        "platform; skipping endpoint count check"
                    )
                    details.append("Endpoint enumeration unavailable")
                else:
                    logger(f"[WARN] Endpoint read failed: {info}")
                    details.append(f"Endpoint read failed: {info}")
            except Exception as ex:
                logger(f"[WARN] Endpoint hardware check error: {ex}")
                details.append(f"Endpoint check error: {ex}")

        logger(
            f"[INFO] Endpoint Validation Result : {passed}/{total}"
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