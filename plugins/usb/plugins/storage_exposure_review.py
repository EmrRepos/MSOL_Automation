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


class StorageExposureReview(TestPlugin):
    """
    Storage-exposure review based on descriptor evidence.

    A mass-storage interface (bInterfaceClass 0x08) is a removable read/write
    data surface that *could* be used for exfiltration or malware ingress. Its
    presence is confirmed from the interface descriptor rather than guessed
    from the device name, but the presence of the interface is an *attack
    surface*, not a proven vulnerability: proving a weakness would require
    showing, for example, that the volume auto-mounts and accepts writes
    against host policy, which this tool does not do. Confirmed storage
    interfaces are therefore reported as ATTACK_SURFACE and do not fail the
    review. When Windows blocks descriptor access the finding is INCONCLUSIVE.
    """

    name = "Storage Exposure Review"

    def execute(self, device, logger, use_hardware=False):

        logger("[INFO] Starting Storage Exposure Review")
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

        looks_storage = (
            usb_class == "Mass Storage"
            or any(k in name for k in ("storage", "flash", "disk"))
        )

        if not looks_storage:
            report.add(Finding(
                title="Device does not present a storage interface",
                severity=INFO,
                status=NOT_AFFECTED,
            ))
            return report.result()

        if use_hardware and device.get("vid") not in (None, "N/A") \
                and device.get("pid") not in (None, "N/A"):
            if self._active_probe(device, report, logger):
                return report.result()

        self._reported_capability(usb_class, name, report)
        return report.result()

    def _active_probe(self, device, report, logger):
        try:
            ok, info = _hw.read_descriptors(
                device.get("vid"), device.get("pid"), logger
            )
        except Exception as ex:
            logger(f"[WARN] Storage descriptor probe error: {ex}")
            report.add(Finding(
                title="Storage interface could not be verified",
                severity=INFO,
                status=INCONCLUSIVE,
                evidence=[f"probe error: {ex}"],
            ))
            return True

        if not ok:
            report.add(Finding(
                title="Storage interface could not be verified",
                severity=INFO,
                status=INCONCLUSIVE,
                evidence=[str(info)],
            ))
            return True

        if not info.get("interfaces_available"):
            report.add(Finding(
                title="Storage interface capability not verified",
                severity=MEDIUM,
                status=INCONCLUSIVE,
                evidence=[
                    "Interface descriptors unavailable: the device is bound "
                    "to a native class driver and could not be claimed to "
                    "read its interface descriptor.",
                ],
                impact="Whether a mounted read/write volume is exposed could "
                       "not be actively confirmed on this platform.",
            ))
            return True

        storage_interfaces = [
            intf for intf in info.get("interfaces", [])
            if intf.get("bInterfaceClass") == 0x08
        ]

        if storage_interfaces:
            intf = storage_interfaces[0]
            report.add(Finding(
                title="Device presents a USB Mass Storage interface "
                      "(removable read/write data surface)",
                severity=MEDIUM,
                status=CONFIRMED,
                category=ATTACK_SURFACE,
                evidence=[
                    f"Interface {intf.get('bInterfaceNumber')}: "
                    f"bInterfaceClass=0x08, "
                    f"bInterfaceSubClass={intf.get('bInterfaceSubClass')}, "
                    f"bInterfaceProtocol={intf.get('bInterfaceProtocol')}",
                ],
                impact="Attack surface, not a confirmed vulnerability: a "
                       "mass-storage volume could be used to copy data off the "
                       "host or to introduce files onto it. Whether this is "
                       "actually exploitable depends on host mount/write "
                       "policy, which is not tested here.",
                remediation="Apply a USB storage control policy (block or "
                            "read-only) for unauthorised devices.",
            ))
        else:
            report.add(Finding(
                title="No mass-storage interface present in the descriptor",
                severity=INFO,
                status=NOT_AFFECTED,
                evidence=["Interface descriptors read; no class 0x08 interface"],
            ))
        return True

    def _reported_capability(self, usb_class, name, report):
        report.add(Finding(
            title="Device is reported as storage (not actively verified)",
            severity=MEDIUM,
            status=POTENTIAL,
            evidence=[
                f"USB class: {usb_class}",
            ],
            impact="Enable hardware mode to read the descriptor and confirm "
                   "whether a mass-storage interface is present.",
        ))
