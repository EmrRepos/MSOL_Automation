from plugins.base import TestPlugin

from core import device_profile as _profiles
from core import hardware_helpers as _hw


class SerialCommunicationTest(TestPlugin):

    name = "Serial Communication Test"

    def execute(self, device, logger, use_hardware=False, profile=None, cancel_event=None):

        if cancel_event is not None and cancel_event.is_set():
            return {"status": "CANCELLED", "details": ["Stopped before opening serial port."]}

        logger(
            "[INFO] Starting Serial Communication Test"
        )

        logger(
            "--------------------------------"
        )

        port = device.get("port", "N/A")

        logger(
            f"Device Name : {device.get('name','Unknown')}"
        )

        logger(
            f"COM Port    : {port}"
        )

        logger(
            f"VID         : {device.get('vid','N/A')}"
        )

        logger(
            f"PID         : {device.get('pid','N/A')}"
        )

        checks = []
        details = []

        profile = profile if profile is not None else _profiles.find_profile(device, logger=logger)

        if profile:
            logger(
                f"Profile     : {profile.get('name', 'Unnamed')} "
                f"({profile.get('_source', 'unknown')})"
            )
            details.append(
                f"Profile: {profile.get('name', 'Unnamed')}"
            )
        else:
            logger(
                "Profile     : none matched"
            )

        logger(
            "--------------------------------"
        )

        #
        # Port Assignment
        #

        if port != "N/A":

            logger(
                f"[PASS] Serial Port Assigned : {port}"
            )

            checks.append(True)

            details.append(
                f"Serial Port {port}"
            )

        else:

            logger(
                "[FAIL] No Serial Port Assigned"
            )

            checks.append(False)

            return self._result(checks, details, logger)

        #
        # Hardware Exchange
        #

        if not use_hardware:

            logger(
                "[INFO] Hardware mode disabled; skipping live serial exchange"
            )

            details.append(
                "Live exchange skipped (hardware mode off)"
            )

            return self._result(checks, details, logger)

        settings = _profiles.serial_settings(profile)

        ok, info = _hw.cdc_check(
            port,
            logger,
            baudrate=settings.get("baudrate", 115200),
            timeout=settings.get("timeout", 2)
        )

        if ok:

            logger(
                "[PASS] Serial Port Accessible"
            )

            checks.append(True)

            details.append(
                "Serial port accessible"
            )

        else:

            logger(
                f"[FAIL] Serial Port Not Accessible : {info}"
            )

            checks.append(False)

            return self._result(checks, details, logger)

        commands = _profiles.commands(profile)

        if cancel_event is not None and cancel_event.is_set():
            return {"status": "CANCELLED", "details": details + ["Stopped after port access check."]}

        if not commands:

            logger(
                "[INFO] Profile defines no commands; "
                "no data sent to the device"
            )

            details.append(
                "No profile commands defined"
            )

            return self._result(checks, details, logger)

        logger(
            "--------------------------------"
        )

        logger(
            f"[INFO] Executing {len(commands)} profile command(s)"
        )

        for command in commands:
            if cancel_event is not None and cancel_event.is_set():
                return {"status": "CANCELLED", "details": details + ["Stopped between commands."]}

            self._run_command(
                command,
                port,
                settings,
                checks,
                details,
                logger
            )

        return self._result(checks, details, logger)

    def _run_command(
        self,
        command,
        port,
        settings,
        checks,
        details,
        logger
    ):

        label = command.get("name", "Unnamed Command")
        required = command.get("required", True)

        logger(
            f"[INFO] Command : {label}"
        )

        try:

            ok, info = _hw.serial_transaction(
                port,
                command.get("payload", ""),
                logger,
                baudrate=settings.get("baudrate", 115200),
                timeout=command.get(
                    "timeout",
                    settings.get("timeout", 2)
                ),
                read_size=settings.get("read_size", 256),
                settle=settings.get("settle", 0.2),
                expect=command.get("expect"),
                append_crc=command.get("append_crc", False),
                append_newline=command.get("append_newline", False),
                verify_crc=command.get("verify_crc", False)
            )

        except Exception as ex:

            logger(
                f"[WARN] Command error ({label}) : {ex}"
            )

            if required:
                checks.append(False)

            details.append(
                f"{label}: error {ex}"
            )

            return

        if ok:

            logger(
                f"[PASS] {label}"
            )

            checks.append(True)

            details.append(
                f"{label}: responded "
                f"({info.get('response_len', 0)} bytes)"
            )

            return

        reason = info.get("error", "unknown")

        if required:

            logger(
                f"[FAIL] {label} : {reason}"
            )

            checks.append(False)

        else:

            logger(
                f"[WARN] {label} : {reason} (optional command)"
            )

        details.append(
            f"{label}: {reason}"
        )

    def _result(self, checks, details, logger):

        total = len(checks)
        passed = sum(checks)

        logger(
            f"[INFO] Serial Communication Result : {passed}/{total}"
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
