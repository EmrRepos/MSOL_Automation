from plugins.base import TestPlugin


class HIDValidationTest(TestPlugin):

    name = "HID Validation"

    def execute(self, device, logger, use_hardware=False):

        logger(
            "[INFO] Starting HID Validation"
        )

        logger(
            "--------------------------------"
        )

        logger(
            "[INFO] HID Information"
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

        usb_class = device.get(
            "usb_class",
            "Unknown"
        )

        device_name = device.get(
            "name",
            ""
        ).lower()

        if usb_class == "HID":

            logger(
                "[PASS] HID Class Detected"
            )

            checks.append(True)

            details.append(
                "HID Class Detected"
            )

        else:

            logger(
                "[FAIL] Device Is Not HID"
            )

            checks.append(False)

        if "keyboard" in device_name:

            logger(
                "[INFO] Keyboard Device Detected"
            )

            details.append(
                "Keyboard Interface"
            )

        elif "mouse" in device_name:

            logger(
                "[INFO] Mouse Device Detected"
            )

            details.append(
                "Mouse Interface"
            )

        else:

            logger(
                "[INFO] Generic HID Device"
            )

            details.append(
                "Generic HID Device"
            )

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
                "Device Connected"
            )

        else:

            logger(
                "[FAIL] Device Not Connected"
            )

            checks.append(False)

        total = len(checks)

        passed = sum(checks)

        # Hardware: verify HID interface class via pyusb
        if use_hardware and device.get("vid") and device.get("pid"):
            try:
                from core.hardware_helpers import read_descriptors
                ok, info = read_descriptors(device.get("vid"), device.get("pid"), logger)
                if ok and info.get("interfaces_available"):
                    total += 1
                    found_hid = False
                    for intf in info.get("interfaces", []):
                        if intf.get("bInterfaceClass") == 0x03:
                            found_hid = True
                            break
                    if found_hid:
                        logger("[PASS] HID interface found via pyusb")
                        passed += 1
                        details.append("HID interface (pyusb)")
                    else:
                        logger("[FAIL] No HID interface found via pyusb")
                        details.append("No HID interface (pyusb)")
                elif ok:
                    logger(
                        "[WARN] HID interface descriptors not readable on "
                        "this platform; skipping interface class check"
                    )
                    details.append("HID interface check unavailable")
                else:
                    logger(f"[WARN] HID hardware descriptor read failed: {info}")
                    details.append(f"pyusb: {info}")
            except Exception as ex:
                logger(f"[WARN] HID hardware check error: {ex}")
                details.append(f"HID check error: {ex}")

        logger(
            f"[INFO] HID Validation Result : {passed}/{total}"
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