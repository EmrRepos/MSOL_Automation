from plugins.base import TestPlugin

from core import hardware_helpers as _hw
from core.findings import (
    Finding,
    FindingReport,
    CONFIRMED,
    POTENTIAL,
    INCONCLUSIVE,
    NOT_AFFECTED,
    ATTACK_SURFACE,
    INFO,
    LOW,
    MEDIUM,
)


class HIDAttackSurfaceReview(TestPlugin):
    """
    HID attack-surface review based on descriptor evidence, not the name.

    A device name containing "keyboard" proves nothing. What matters is
    whether the device actually *presents a HID keyboard interface*, which is
    read from the interface descriptor (bInterfaceClass 0x03, bInterfaceProtocol
    1 = keyboard, 2 = mouse).

    Even a confirmed keyboard interface is an *attack surface*, not a
    vulnerability: a wired USB keyboard sends keystrokes to the host, so the
    descriptor proves the device is *capable* of keystroke injection, but it
    does not prove any security boundary has been crossed. Proving a real HID
    vulnerability (for example a host that silently accepts an unauthorised new
    keyboard, enabling BadUSB) requires a host-policy test that this tool does
    not perform. Such findings are therefore reported as ATTACK_SURFACE, and
    the review does not fail on them.

    On Windows, HID devices are bound to the HidUsb class driver and libusb
    usually cannot claim them to read the descriptor. When that happens the
    finding is reported as INCONCLUSIVE rather than invented.
    """

    name = "HID Attack Surface Review"

    def execute(self, device, logger, use_hardware=False):

        logger("[INFO] Starting HID Attack Surface Review")
        logger("--------------------------------")
        logger("[INFO] Device Information")
        logger(f"Device Name : {device.get('name', 'Unknown')}")
        logger(f"VID         : {device.get('vid', 'N/A')}")
        logger(f"PID         : {device.get('pid', 'N/A')}")
        logger(f"USB Class   : {device.get('usb_class', 'Unknown')}")
        logger("--------------------------------")

        report = FindingReport(logger)

        usb_class = str(device.get("usb_class", "Unknown"))
        name = str(device.get("name", "")).lower()

        if usb_class != "HID" and "keyboard" not in name and "mouse" not in name:
            report.add(Finding(
                title="Device does not present a HID interface",
                severity=INFO,
                status=NOT_AFFECTED,
            ))
            return report.result()

        if use_hardware and device.get("vid") not in (None, "N/A") \
                and device.get("pid") not in (None, "N/A"):
            tested = self._active_probe(device, report, logger)
            if tested:
                return report.result()

        # Could not actively verify - fall back to an honest, clearly-labelled
        # capability statement based only on what Windows reported.
        self._reported_capability(usb_class, name, report)
        return report.result()

    def _active_probe(self, device, report, logger):
        """
        Read the interface descriptor and judge the capability from it.

        Returns True if an active result (confirmed or not-affected) was
        reached, False if the probe could not obtain descriptor data.
        """
        try:
            ok, info = _hw.read_descriptors(
                device.get("vid"), device.get("pid"), logger
            )
        except Exception as ex:
            logger(f"[WARN] HID descriptor probe error: {ex}")
            report.add(Finding(
                title="HID report descriptor could not be read",
                severity=INFO,
                status=INCONCLUSIVE,
                evidence=[f"probe error: {ex}"],
            ))
            return True

        if not ok:
            report.add(Finding(
                title="HID report descriptor could not be read",
                severity=INFO,
                status=INCONCLUSIVE,
                evidence=[str(info)],
                impact="The device could not be opened to read its "
                       "descriptor, so its input capability is unverified.",
            ))
            return True

        if not info.get("interfaces_available"):
            report.add(Finding(
                title="HID interface capability not verified",
                severity=MEDIUM,
                status=INCONCLUSIVE,
                evidence=[
                    "Interface descriptors unavailable: the device is bound "
                    "to a native class driver (HidUsb) and could not be "
                    "claimed to read the HID report descriptor.",
                ],
                impact="Whether the device can inject keystrokes could not be "
                       "actively confirmed on this platform.",
            ))
            return True

        hid_interfaces = [
            intf for intf in info.get("interfaces", [])
            if intf.get("bInterfaceClass") == 0x03
        ]

        if not hid_interfaces:
            report.add(Finding(
                title="No HID interface present in the descriptor",
                severity=INFO,
                status=NOT_AFFECTED,
                evidence=["Interface descriptors read; no class 0x03 interface"],
            ))
            return True

        confirmed_keyboard = False
        for intf in hid_interfaces:
            protocol = intf.get("bInterfaceProtocol")
            number = intf.get("bInterfaceNumber")

            if protocol == 1:
                confirmed_keyboard = True
                report.add(Finding(
                    title="Device presents a HID keyboard interface "
                          "(keystroke-injection capable)",
                    severity=MEDIUM,
                    status=CONFIRMED,
                    category=ATTACK_SURFACE,
                    evidence=[
                        f"Interface {number}: bInterfaceClass=0x03, "
                        "bInterfaceProtocol=1 (boot keyboard)",
                    ],
                    impact="Attack surface, not a confirmed vulnerability: a "
                           "keyboard interface is capable of sending "
                           "keystrokes to the host. Whether that can be abused "
                           "(BadUSB) depends on host policy accepting an "
                           "unauthorised keyboard, which is not tested here.",
                    remediation="Restrict which HID devices are permitted, or "
                                "require explicit authorisation before a new "
                                "keyboard is accepted.",
                ))
            elif protocol == 2:
                report.add(Finding(
                    title="Device presents a HID mouse interface",
                    severity=LOW,
                    status=CONFIRMED,
                    category=ATTACK_SURFACE,
                    evidence=[
                        f"Interface {number}: bInterfaceClass=0x03, "
                        "bInterfaceProtocol=2 (boot mouse)",
                    ],
                    impact="Attack surface, not a vulnerability: a pointer "
                           "interface can move the cursor and click but cannot "
                           "type.",
                ))
            else:
                report.add(Finding(
                    title="Device presents a generic HID interface",
                    severity=INFO,
                    status=CONFIRMED,
                    category=ATTACK_SURFACE,
                    evidence=[
                        f"Interface {number}: bInterfaceClass=0x03, "
                        f"bInterfaceProtocol={protocol}",
                    ],
                    impact="Attack surface: vendor-defined HID interface; "
                           "input capability depends on the report descriptor.",
                ))

        if not confirmed_keyboard:
            report.add(Finding(
                title="No keyboard interface confirmed in the descriptor",
                severity=INFO,
                status=NOT_AFFECTED,
            ))
        return True

    def _reported_capability(self, usb_class, name, report):
        """Honest, clearly-labelled fallback when nothing could be probed."""

        if "keyboard" in name:
            report.add(Finding(
                title="Device is reported as a keyboard (not actively "
                      "verified)",
                severity=MEDIUM,
                status=POTENTIAL,
                evidence=[f"Windows device name contains 'keyboard'"],
                impact="If this is genuinely a keyboard it can inject "
                       "keystrokes, but the capability was not confirmed "
                       "from the descriptor.",
            ))
        elif "mouse" in name:
            report.add(Finding(
                title="Device is reported as a mouse (not actively verified)",
                severity=LOW,
                status=POTENTIAL,
                evidence=[f"Windows device name contains 'mouse'"],
            ))
        elif usb_class == "HID":
            report.add(Finding(
                title="Device is a HID-class device (input capability not "
                      "actively verified)",
                severity=LOW,
                status=POTENTIAL,
                evidence=["Windows reports USB class HID"],
                impact="Enable hardware mode to read the descriptor and "
                       "confirm whether it can inject input.",
            ))
