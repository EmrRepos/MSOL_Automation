from plugins.base import TestPlugin


class StorageValidationTest(TestPlugin):

    name = "Storage Validation"

    def execute(self, device, logger, use_hardware=False):

        logger(
            "[INFO] Starting Storage Validation"
        )

        logger(
            "--------------------------------"
        )

        logger(
            "[INFO] Storage Device Information"
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

        usb_class = device.get(
            "usb_class",
            "Unknown"
        )

        device_name = device.get(
            "name",
            ""
        ).lower()

        if usb_class == "Mass Storage":

            logger(
                "[PASS] Mass Storage Device Detected"
            )

            checks.append(True)

            details.append(
                "Mass Storage Class Detected"
            )

        elif "storage" in device_name:

            logger(
                "[PASS] Storage Device Identified"
            )

            checks.append(True)

            details.append(
                "Storage Device Identified"
            )

        elif "flash" in device_name:

            logger(
                "[PASS] Flash Device Identified"
            )

            checks.append(True)

            details.append(
                "Flash Device Identified"
            )

        elif "disk" in device_name:

            logger(
                "[PASS] Disk Device Identified"
            )

            checks.append(True)

            details.append(
                "Disk Device Identified"
            )

        else:

            logger(
                "[FAIL] Device Is Not Storage Class"
            )

            checks.append(False)

        if device.get("vid") != "N/A":

            logger(
                f"[PASS] VID Present : {device['vid']}"
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
                f"[PASS] PID Present : {device['pid']}"
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

        # Hardware: check for Mass Storage interface via pyusb
        if use_hardware and device.get("vid") and device.get("pid"):
            try:
                from core.hardware_helpers import read_descriptors
                ok, info = read_descriptors(device.get("vid"), device.get("pid"), logger)
                if ok and info.get("interfaces_available"):
                    total += 1
                    has_storage = any(
                        intf.get("bInterfaceClass") == 0x08
                        for intf in info.get("interfaces", [])
                    )
                    if has_storage:
                        logger("[PASS] Mass Storage interface confirmed via pyusb")
                        passed += 1
                        details.append("Mass Storage (pyusb)")
                    else:
                        logger("[WARN] No Mass Storage interface detected via pyusb")
                        details.append("No Mass Storage (pyusb)")
                elif ok:
                    logger(
                        "[WARN] Storage interface descriptors not readable on "
                        "this platform; skipping interface class check"
                    )
                    details.append("Storage interface check unavailable")
                else:
                    logger(f"[WARN] pyusb storage read failed: {info}")
                    details.append(f"pyusb: {info}")
            except Exception as ex:
                logger(f"[WARN] Storage hardware check error: {ex}")
                details.append(f"Storage check error: {ex}")

        logger(
            f"[INFO] Storage Validation Result : {passed}/{total}"
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