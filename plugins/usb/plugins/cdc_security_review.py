from plugins.base import TestPlugin

from core import device_profile as _profiles
from core import hardware_helpers as _hw
from core.findings import (
    Finding,
    FindingReport,
    CONFIRMED,
    INCONCLUSIVE,
    NOT_AFFECTED,
    ATTACK_SURFACE,
    INFO,
    LOW,
    MEDIUM,
    HIGH,
)


class CDCSecurityReview(TestPlugin):
    """
    Active serial-exposure review.

    Instead of inferring risk from metadata, this review opens the serial
    control channel and actively tests what the device does with real bytes.

    It distinguishes two very different things:

    * **Attack surface (not a vulnerability).** The device answers a safe,
      read-only identification probe. This confirms the channel is reachable
      and processes unauthenticated *reads*, but answering a read-only query is
      normal for most service ports and does not by itself cross a security
      boundary. Reported as ATTACK_SURFACE; does not fail the review.

    * **Confirmed vulnerability.** The device acts on an unauthenticated
      *state-changing* command (a write / configuration / control request).
      That crosses a security boundary: any host that can open the port can
      change the device's state without authentication. Reported as a
      CONFIRMED VULNERABILITY; fails the review.

    State-changing probes are **never** sent by default. A command must be
    explicitly marked ``state_changing`` in a device profile *and* the caller
    must opt in (``device['active_write_opt_in'] == True``) before any such
    byte is written, so the tool cannot alter a transmitter's state on its own.
    """

    name = "CDC Security Review"

    def execute(self, device, logger, use_hardware=False):

        logger("[INFO] Starting CDC Security Review")
        logger("--------------------------------")
        logger("[INFO] Device Information")
        logger(f"Device Name : {device.get('name', 'Unknown')}")
        logger(f"VID         : {device.get('vid', 'N/A')}")
        logger(f"PID         : {device.get('pid', 'N/A')}")
        logger(f"Port        : {device.get('port', 'N/A')}")
        logger("--------------------------------")

        report = FindingReport(logger)

        port = device.get("port", "N/A")

        # --- Context (what the device exposes, stated as fact, not risk) ----
        if device.get("usb_class") == "CDC" or port not in (None, "N/A"):
            report.add(Finding(
                title="Serial control channel is exposed to the host",
                severity=INFO,
                status=CONFIRMED,
                evidence=[f"COM port assigned: {port}"],
            ))
        else:
            report.add(Finding(
                title="No serial control channel exposed",
                severity=INFO,
                status=NOT_AFFECTED,
            ))
            return report.result()

        if port in (None, "N/A"):
            report.add(Finding(
                title="Command acceptance could not be tested",
                severity=MEDIUM,
                status=INCONCLUSIVE,
                impact="No COM port is assigned, so no data could be sent.",
            ))
            return report.result()

        # --- Active probe -------------------------------------------------
        if not use_hardware:
            report.add(Finding(
                title="Unauthenticated command acceptance not actively tested",
                severity=MEDIUM,
                status=INCONCLUSIVE,
                impact=(
                    "Hardware mode is disabled, so no data was sent to the "
                    "device. Enable hardware mode to actively verify whether "
                    "the device accepts unauthenticated commands."
                ),
            ))
            return report.result()

        self._active_probe(device, port, report, logger)
        return report.result()

    def _classify_commands(self, profile):
        """
        Split profile commands into read-only and state-changing lists.

        A command is treated as state-changing if it is explicitly marked
        ``state_changing`` or ``write``. Everything else is considered
        read-only and safe to send. Only read-only commands are ever sent
        unless the caller explicitly opts in to active-write testing.
        """
        read_only = []
        state_changing = []
        for command in _profiles.commands(profile):
            if command.get("state_changing") or command.get("write") \
                    or command.get("read_only") is False:
                state_changing.append(command)
            else:
                read_only.append(command)
        return read_only, state_changing

    def _send(self, port, command, settings, logger):
        """Send one profile command; return (sent_ok, result_dict)."""
        return _hw.serial_transaction(
            port,
            command.get("payload", ""),
            logger,
            baudrate=settings.get("baudrate", 115200),
            timeout=command.get("timeout", settings.get("timeout", 2)),
            read_size=settings.get("read_size", 256),
            settle=settings.get("settle", 0.2),
            expect=command.get("expect"),
            append_crc=command.get("append_crc", False),
            append_newline=command.get("append_newline", False),
            verify_crc=command.get("verify_crc", False),
        )

    def _active_probe(self, device, port, report, logger):

        profile = _profiles.find_profile(device, logger=logger)
        settings = _profiles.serial_settings(profile)

        # First, can the channel even be opened without credentials?
        ok, info = _hw.cdc_check(
            port,
            logger,
            baudrate=settings.get("baudrate", 115200),
            timeout=settings.get("timeout", 2),
        )

        if not ok:
            report.add(Finding(
                title="Serial control channel could not be opened",
                severity=INFO,
                status=INCONCLUSIVE,
                evidence=[str(info)],
                impact="The port exists but could not be opened for testing "
                       "(it may be in use by another application).",
            ))
            return

        read_only, state_changing = self._classify_commands(profile)

        if not read_only and not state_changing:
            report.add(Finding(
                title="Command acceptance not verified",
                severity=INFO,
                status=INCONCLUSIVE,
                evidence=[
                    f"Port {port} opened with no credentials",
                    "No known-safe protocol probe is defined for this device",
                ],
                impact=(
                    "The channel opened without authentication, but no safe "
                    "command is known for this device, so command handling "
                    "was not actively tested. Add a read-only probe to a "
                    "device profile to confirm."
                ),
                remediation="Define a read-only command in a device profile "
                            "to actively test command handling.",
            ))
            return

        self._probe_read_only(read_only, port, settings, report, logger)
        self._probe_state_changing(
            device, state_changing, port, settings, report, logger
        )

    def _probe_read_only(self, commands, port, settings, report, logger):
        """Send read-only probes. A response is attack surface, not a vuln."""

        if not commands:
            return

        responded = False
        last_reason = "no_response"

        for command in commands:
            label = command.get("name", "probe")
            logger(f"[INFO] Active probe : sending read-only '{label}'")

            try:
                _sent_ok, result = self._send(port, command, settings, logger)
            except Exception as ex:
                last_reason = f"error: {ex}"
                continue

            if result.get("response_len"):
                responded = True
                report.add(Finding(
                    title="Service port answers unauthenticated read-only "
                          "commands",
                    severity=LOW,
                    status=CONFIRMED,
                    category=ATTACK_SURFACE,
                    evidence=[
                        f"Probe: {label} (read-only)",
                        f"TX: {result.get('request', '')}",
                        f"RX: {result.get('response', '')}"
                        f" ({result.get('response_len')} bytes)",
                        "No authentication was required to read from the "
                        "device.",
                    ],
                    impact=(
                        "Attack surface, not a confirmed vulnerability: the "
                        "channel is reachable and processes unauthenticated "
                        "read/identification requests. Answering a read-only "
                        "query is normal for a service port; it becomes a "
                        "vulnerability only if the device also acts on "
                        "unauthenticated state-changing commands."
                    ),
                    remediation="If the service port should not be openly "
                                "reachable, require authentication or restrict "
                                "which hosts may open it.",
                ))
                break

            last_reason = result.get("error", "no_response")

        if not responded:
            report.add(Finding(
                title="Device did not respond to the read-only probe",
                severity=LOW,
                status=INCONCLUSIVE,
                evidence=[f"Last result: {last_reason}"],
                impact=(
                    "The port opened but the device did not answer the known "
                    "probe. Command acceptance is unconfirmed; the device may "
                    "use different framing or may be idle."
                ),
            ))

    def _probe_state_changing(
        self, device, commands, port, settings, report, logger
    ):
        """
        Actively test whether an unauthenticated *state-changing* command is
        accepted. This is the only path that can confirm a real vulnerability,
        and it is gated behind an explicit opt-in so nothing is written by
        default.
        """

        if not commands:
            return

        opt_in = bool(device.get("active_write_opt_in"))

        if not opt_in:
            report.add(Finding(
                title="Unauthenticated state-changing command acceptance not "
                      "tested (active-write opt-in required)",
                severity=MEDIUM,
                status=INCONCLUSIVE,
                evidence=[
                    f"{len(commands)} state-changing probe(s) are defined for "
                    "this device but were not sent.",
                    "Set active_write_opt_in to authorise writing to the "
                    "device before this boundary test runs.",
                ],
                impact=(
                    "Whether the device acts on unauthenticated "
                    "state-changing commands - the real security boundary - "
                    "was deliberately not tested, because doing so would write "
                    "to the device."
                ),
            ))
            return

        for command in commands:
            label = command.get("name", "state-changing probe")
            logger(
                f"[WARN] Active WRITE probe (opt-in) : sending "
                f"state-changing '{label}'"
            )

            try:
                _sent_ok, result = self._send(port, command, settings, logger)
            except Exception as ex:
                report.add(Finding(
                    title="State-changing probe could not be completed",
                    severity=MEDIUM,
                    status=INCONCLUSIVE,
                    evidence=[f"Probe: {label}", f"error: {ex}"],
                ))
                continue

            accepted = result.get("response_len") or result.get("expect_matched")

            if accepted:
                report.add(Finding(
                    title="Device acts on unauthenticated state-changing "
                          "commands",
                    severity=HIGH,
                    status=CONFIRMED,
                    evidence=[
                        f"Probe: {label} (state-changing)",
                        f"TX: {result.get('request', '')}",
                        f"RX: {result.get('response', '')}"
                        f" ({result.get('response_len', 0)} bytes)",
                        "The device accepted and acted on a state-changing "
                        "request with no authentication step.",
                    ],
                    impact=(
                        "Security boundary crossed: any host that can open "
                        "this COM port can change the device's state without "
                        "authentication."
                    ),
                    remediation="Require authentication before accepting "
                                "state-changing commands on the service port.",
                ))
            else:
                report.add(Finding(
                    title="Device did not act on the state-changing probe",
                    severity=INFO,
                    status=NOT_AFFECTED,
                    evidence=[
                        f"Probe: {label}",
                        f"Result: {result.get('error', 'no effect observed')}",
                    ],
                ))
