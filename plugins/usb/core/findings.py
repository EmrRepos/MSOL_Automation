"""
Evidence-based security findings.

A metadata observation ("the device name contains 'keyboard'") is not a
vulnerability. A finding is only meaningful when it records *what was actively
tested* and *what was observed*. This module provides a small vocabulary so a
report never presents an unproven capability as a confirmed vulnerability.

Each :class:`Finding` carries a verification status:

* ``CONFIRMED``     - actively probed and the behaviour was observed. Evidence
                      (such as the bytes sent and received) is attached.
* ``POTENTIAL``     - a capability is indicated (e.g. by a descriptor or a
                      reported name) but has not been actively proven.
* ``INCONCLUSIVE``  - a probe was attempted but no result could be obtained
                      (for example the OS blocked access). Never treated as a
                      vulnerability, because nothing was proven.
* ``NOT_AFFECTED``  - actively probed and the device did *not* exhibit the
                      behaviour.

Confirmation is not the same as vulnerability. Observing that a device *is* a
keyboard, *is* mass storage, or *answers a read-only identification query* is
an **attack-surface** fact: it is confirmed, but it does not by itself prove a
security weakness. A finding is only a *vulnerability* when an active test
shows the device crossing an expected security boundary - for example acting
on an **unauthenticated state-changing command**. Each :class:`Finding`
therefore also carries a ``category``:

* ``VULNERABILITY``   - a security boundary was (or would be) crossed. Only a
                        ``CONFIRMED`` vulnerability of severity ``LOW`` or above
                        fails a review.
* ``ATTACK_SURFACE``  - a real, confirmed capability or exposure that a
                        reviewer should see, but which is not itself proof of a
                        weakness. Never fails a review.

A :class:`FindingReport` collects findings and renders them, and also exposes
the legacy ``{"status", "passed", "total", "details"}`` contract that the test
runner, dashboard and report generator already consume, so existing callers
keep working unchanged.
"""

CONFIRMED = "CONFIRMED"
POTENTIAL = "POTENTIAL"
INCONCLUSIVE = "INCONCLUSIVE"
NOT_AFFECTED = "NOT_AFFECTED"

VULNERABILITY = "VULNERABILITY"
ATTACK_SURFACE = "ATTACK_SURFACE"

INFO = "INFO"
LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"

_SEVERITY_ORDER = {
    INFO: 0,
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4,
}

_STATUS_TAG = {
    CONFIRMED: "[VULN]",
    POTENTIAL: "[POTENTIAL]",
    INCONCLUSIVE: "[INCONCLUSIVE]",
    NOT_AFFECTED: "[OK]",
}


class Finding:
    """A single security observation with its verification status."""

    def __init__(
        self,
        title,
        severity=INFO,
        status=INCONCLUSIVE,
        evidence=None,
        impact="",
        remediation="",
        category=VULNERABILITY,
    ):
        self.title = title
        self.severity = str(severity).upper()
        self.status = str(status).upper()
        self.evidence = list(evidence or [])
        self.impact = impact
        self.remediation = remediation
        self.category = str(category).upper()

        if self.severity not in _SEVERITY_ORDER:
            self.severity = INFO
        if self.status not in _STATUS_TAG:
            self.status = INCONCLUSIVE
        if self.category not in (VULNERABILITY, ATTACK_SURFACE):
            self.category = VULNERABILITY

    @property
    def is_attack_surface(self):
        """
        True when this is a confirmed capability/exposure that is *not* a
        proven weakness. It is reported but never fails a review.
        """
        return (
            self.category == ATTACK_SURFACE
            and self.status == CONFIRMED
        )

    @property
    def is_vulnerability(self):
        """
        True only when an actual weakness was actively confirmed.

        Confirming a *capability* (an ``ATTACK_SURFACE`` finding) is never a
        vulnerability, no matter how high its severity. A vulnerability must be
        a ``VULNERABILITY``-category finding that was ``CONFIRMED`` and carries
        a real severity (``LOW`` or above).
        """
        return (
            self.category == VULNERABILITY
            and self.status == CONFIRMED
            and _SEVERITY_ORDER[self.severity] >= _SEVERITY_ORDER[LOW]
        )

    def tag(self):
        if self.is_vulnerability:
            return "[VULN]"
        if self.is_attack_surface:
            return "[SURFACE]"
        if self.status == CONFIRMED:
            return "[INFO]"
        return _STATUS_TAG[self.status]

    def log(self, logger):
        """Render this finding to the live event log."""

        header = (
            f"{self.tag()} ({self.severity}, {self.status}) {self.title}"
        )
        logger(header)

        if self.impact:
            logger(f"        Impact   : {self.impact}")

        for item in self.evidence:
            logger(f"        Evidence : {item}")

        if self.remediation:
            logger(f"        Fix      : {self.remediation}")

    def summary(self):
        if self.is_vulnerability:
            kind = "VULNERABILITY"
        elif self.is_attack_surface:
            kind = "ATTACK_SURFACE"
        else:
            kind = self.status
        return f"{kind}/{self.severity}: {self.title}"


class FindingReport:
    """Collects findings and maps them onto the legacy result contract."""

    def __init__(self, logger):
        self._logger = logger
        self.findings = []

    def add(self, finding):
        self.findings.append(finding)
        finding.log(self._logger)
        return finding

    def confirmed_vulns(self):
        return [f for f in self.findings if f.is_vulnerability]

    def attack_surface(self):
        return [f for f in self.findings if f.is_attack_surface]

    def highest_severity(self):
        vulns = self.confirmed_vulns()
        if not vulns:
            return None
        return max(vulns, key=lambda f: _SEVERITY_ORDER[f.severity]).severity

    def result(self):
        """
        Produce ``{"status", "passed", "total", "details"}``.

        A finding "passes" (is not a problem) unless it is a confirmed
        vulnerability. ``ATTACK_SURFACE``, ``INCONCLUSIVE`` and ``POTENTIAL``
        findings all pass, because none of them is a proven weakness, but they
        remain visible in the log and in ``details`` so the reviewer sees what
        the device exposes and what could not be verified.
        """
        total = len(self.findings)
        vulns = self.confirmed_vulns()
        surface = self.attack_surface()
        passed = total - len(vulns)

        self._logger("--------------------------------")

        if vulns:
            self._logger(
                f"[FAIL] Review Result : {len(vulns)} confirmed "
                f"vulnerability(ies); highest severity "
                f"{self.highest_severity()}"
            )
        else:
            if surface:
                self._logger(
                    f"[PASS] Review Result : no confirmed vulnerabilities; "
                    f"{len(surface)} attack-surface item(s) documented "
                    f"(capability, not a proven weakness)"
                )
            else:
                inconclusive = sum(
                    1 for f in self.findings if f.status == INCONCLUSIVE
                )
                if inconclusive:
                    self._logger(
                        f"[PASS] Review Result : no confirmed vulnerabilities "
                        f"({inconclusive} check(s) could not be verified)"
                    )
                else:
                    self._logger(
                        "[PASS] Review Result : no confirmed vulnerabilities"
                    )

        return {
            "status": "FAIL" if vulns else "PASS",
            "passed": passed,
            "total": total,
            "details": [f.summary() for f in self.findings],
        }
