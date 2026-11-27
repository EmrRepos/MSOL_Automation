from plugins.base import TestPlugin


def _is_valid_id(value):
    """A USB VID/PID must be exactly four hexadecimal digits."""
    text = str(value).strip().upper()
    if text.startswith("0X"):
        text = text[2:]
    if len(text) != 4:
        return False
    return all(c in "0123456789ABCDEF" for c in text)


def _is_placeholder(value):
    """0000 and FFFF are unprogrammed/reserved identifier values."""
    text = str(value).strip().upper()
    if text.startswith("0X"):
        text = text[2:]
    return text in ("0000", "FFFF")


class DescriptorRobustnessTest(TestPlugin):

    name = "Descriptor Robustness Test"
    def execute(self, device, logger, use_hardware=False):

        logger(
            "[INFO] Starting Descriptor Robustness Test"
        )

        logger(
            "--------------------------------"
        )

        logger(
            "[INFO] Descriptor Information"
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

        #
        # Device Name
        #

        name = device.get(
            "name",
            ""
        )

        if name and len(name) >= 3:

            logger(
                "[PASS] Device Name Valid"
            )

            checks.append(True)

            details.append(
                "Device Name Valid"
            )

        else:

            logger(
                "[FAIL] Device Name Suspicious"
            )

            checks.append(False)

        #
        # VID
        #

        vid = device.get(
            "vid",
            "N/A"
        )

        if vid != "N/A" and _is_valid_id(vid):

            logger(
                f"[PASS] VID Format Valid : {vid}"
            )

            checks.append(True)

            details.append(
                "VID Format Valid"
            )

        else:

            logger(
                "[FAIL] VID Format Invalid"
            )

            checks.append(False)

        #
        # PID
        #

        pid = device.get(
            "pid",
            "N/A"
        )

        if pid != "N/A" and _is_valid_id(pid):

            logger(
                f"[PASS] PID Format Valid : {pid}"
            )

            checks.append(True)

            details.append(
                "PID Format Valid"
            )

        else:

            logger(
                "[FAIL] PID Format Invalid"
            )

            checks.append(False)

        #
        # Reserved / placeholder identifiers
        #

        if _is_placeholder(vid) or _is_placeholder(pid):

            logger(
                "[WARN] Placeholder VID/PID detected "
                "(0000 or FFFF) - possible unprogrammed or spoofed device"
            )

            checks.append(False)

            details.append(
                "Placeholder VID/PID"
            )

        else:

            logger(
                "[PASS] No Placeholder Identifiers"
            )

            checks.append(True)

            details.append(
                "Identifiers Not Placeholder"
            )

        #
        # USB Class
        #

        usb_class = device.get(
            "usb_class",
            "Unknown"
        )

        if usb_class != "Unknown":

            logger(
                f"[PASS] USB Class Present : {usb_class}"
            )

            checks.append(True)

            details.append(
                "USB Class Present"
            )

        else:

            logger(
                "[WARN] USB Class Unknown"
            )

            checks.append(False)

        #
        # Connection
        #

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

        #
        # Security Assessment
        #

        total = len(checks)

        passed = sum(checks)

        # Hardware-assisted checks: attempt to read descriptors and validate fields
        if use_hardware and device.get("vid") and device.get("pid"):
            try:
                from core.hardware_helpers import read_descriptors
                ok, info = read_descriptors(device.get("vid"), device.get("pid"), logger)
                total += 1
                if ok and info.get("interfaces") is not None:
                    logger("[PASS] Hardware descriptor read OK")
                    passed += 1
                    details.append("Hardware descriptor read")
                else:
                    logger(f"[WARN] Hardware descriptor read failed: {info}")
                    details.append(f"Hardware read issue: {info}")
            except Exception as ex:
                logger(f"[WARN] Descriptor robustness hardware check error: {ex}")
                total += 1
                details.append(f"Descriptor check error: {ex}")

        score = round(
            (passed / total) * 100,
            2
        )

        logger(
            "--------------------------------"
        )

        logger(
            f"[INFO] Descriptor Score : "
            f"{score}%"
        )

        if score >= 90:

            risk = "LOW"

        elif score >= 70:

            risk = "MEDIUM"

        else:

            risk = "HIGH"

        logger(
            f"[INFO] Risk Rating : {risk}"
        )

        details.append(
            f"Descriptor Score = {score}%"
        )

        details.append(
            f"Risk Rating = {risk}"
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
