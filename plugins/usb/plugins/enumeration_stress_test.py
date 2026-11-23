from plugins.base import TestPlugin


class EnumerationStressTest(TestPlugin):

    name = "Enumeration Stress Test"

    def execute(self, device, logger, use_hardware=False):

        logger(
            "[INFO] Starting Enumeration Stress Test"
        )

        logger(
            "--------------------------------"
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
            "--------------------------------"
        )

        checks = []
        details = []

        iterations = 10

        for i in range(
            1,
            iterations + 1
        ):

            if use_hardware and device.get("vid") and device.get("pid"):
                try:
                    from core.hardware_helpers import read_descriptors
                    ok, _ = read_descriptors(device.get("vid"), device.get("pid"), logger)
                    if ok:
                        logger(f"[PASS] Enumeration Cycle {i}/{iterations} (pyusb)")
                        checks.append(True)
                    else:
                        logger(f"[FAIL] Enumeration Cycle {i}/{iterations} (pyusb)")
                        checks.append(False)
                except Exception as ex:
                    logger(f"[WARN] Enumeration stress hardware error: {ex}")
                    checks.append(False)
            else:
                if device.get("status") == "Connected":
                    logger(
                        f"[PASS] Enumeration Cycle {i}/{iterations}"
                    )
                    checks.append(True)
                else:
                    logger(
                        f"[FAIL] Enumeration Cycle {i}/{iterations}"
                    )
                    checks.append(False)

        passed = sum(checks)

        total = len(checks)

        logger(
            "--------------------------------"
        )

        logger(
            f"[INFO] Successful Enumerations : "
            f"{passed}/{total}"
        )

        success_rate = round(
            (passed / total) * 100,
            2
        )

        logger(
            f"[INFO] Success Rate : "
            f"{success_rate}%"
        )

        #
        # Security Assessment
        #

        if success_rate == 100:

            risk = "LOW"

        elif success_rate >= 80:

            risk = "MEDIUM"

        else:

            risk = "HIGH"

        logger(
            f"[INFO] Risk Rating : {risk}"
        )

        details.append(
            f"Enumeration Success Rate = "
            f"{success_rate}%"
        )

        details.append(
            f"Security Risk Rating = "
            f"{risk}"
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