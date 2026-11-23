"""
USB device class mapping.

Classification prefers authoritative Windows data (the bound driver service
and the PnP setup class) and only falls back to device-name keywords when
that data is unavailable. Name matching alone is unreliable: for example
"USB Composite Device" contains the substring "com" but is not a CDC device.
"""

# Bound driver service -> (class, subclass, protocol)
SERVICE_MAP = {
    "hidusb": ("HID", "Boot Interface", "Generic HID"),
    "kbdhid": ("HID", "Boot Interface", "Keyboard"),
    "mouhid": ("HID", "Boot Interface", "Mouse"),
    "usbser": ("CDC", "ACM", "Serial"),
    "usbstor": ("Mass Storage", "SCSI", "Bulk Only"),
    "uaspstor": ("Mass Storage", "SCSI", "UAS"),
    "disk": ("Mass Storage", "SCSI", "Bulk Only"),
    "usbhub": ("Hub", "USB Hub", "Hub Protocol"),
    "usbhub3": ("Hub", "USB Hub", "Hub Protocol"),
    "usbvideo": ("Video", "Video Control", "Streaming"),
    "usbaudio": ("Audio", "Audio Control", "Streaming"),
    "usbaudio2": ("Audio", "Audio Control", "Streaming"),
    "usbprint": ("Printer", "Printer", "Bidirectional"),
    "rndismp": ("CDC", "RNDIS", "Ethernet"),
    "wmbclass": ("CDC", "MBIM", "Network"),
}

# PnP setup class -> (class, subclass, protocol)
PNP_CLASS_MAP = {
    "hidclass": ("HID", "Human Interface", "Generic HID"),
    "keyboard": ("HID", "Boot Interface", "Keyboard"),
    "mouse": ("HID", "Boot Interface", "Mouse"),
    "ports": ("CDC", "ACM", "Serial"),
    "modem": ("CDC", "ACM", "Modem"),
    "diskdrive": ("Mass Storage", "SCSI", "Bulk Only"),
    "wpd": ("Mass Storage", "MTP", "Media Transfer"),
    "volume": ("Mass Storage", "SCSI", "Bulk Only"),
    "camera": ("Video", "Video Control", "Streaming"),
    "image": ("Image", "Still Capture", "PTP"),
    "media": ("Audio", "Audio Control", "Streaming"),
    "net": ("CDC", "Ethernet", "Network"),
    "printer": ("Printer", "Printer", "Bidirectional"),
    "smartcardreader": ("Smart Card", "CCID", "CCID"),
    "usb": ("Hub", "USB Hub", "Hub Protocol"),
}

UNKNOWN = ("Unknown", "Unknown", "Unknown")
VENDOR_SPECIFIC = ("Vendor Specific", "Unknown", "Unknown")


def _classify_by_name(name):
    """Keyword fallback used only when Windows class data is unavailable."""

    name = name.lower()

    if "keyboard" in name:

        return (
            "HID",
            "Boot Interface",
            "Keyboard"
        )

    elif "mouse" in name:

        return (
            "HID",
            "Boot Interface",
            "Mouse"
        )

    elif "storage" in name:

        return (
            "Mass Storage",
            "SCSI",
            "Bulk Only"
        )

    elif "flash" in name:

        return (
            "Mass Storage",
            "SCSI",
            "Bulk Only"
        )

    # Match a real COM port reference such as "(COM6)" rather than any word
    # that merely contains "com", for example "Composite".
    elif "(com" in name or "com port" in name:

        return (
            "CDC",
            "ACM",
            "Serial"
        )

    elif "serial" in name:

        return (
            "CDC",
            "ACM",
            "Serial"
        )

    elif "hub" in name:

        return (
            "Hub",
            "USB Hub",
            "Hub Protocol"
        )

    return VENDOR_SPECIFIC


def classify_device(name, service=None, pnp_class=None):
    """
    Return (usb_class, subclass, protocol) for a device.

    `service` and `pnp_class` are optional Windows values. When supplied they
    take priority over name keywords because they reflect the driver actually
    bound to the device.
    """

    if service:
        mapped = SERVICE_MAP.get(str(service).strip().lower())
        if mapped:
            return mapped

    if pnp_class:
        mapped = PNP_CLASS_MAP.get(str(pnp_class).strip().lower())
        if mapped:
            return mapped

    if not name:
        return UNKNOWN

    return _classify_by_name(name)