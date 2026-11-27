# core/com_port_manager.py

"""
COM-port oriented device discovery.

Replaces full USB enumeration with a focused view: only serial (COM) ports
that are present on the system, enriched with USB descriptor metadata when
the underlying device is a USB device.
"""

import re

from serial.tools import list_ports

from core.usb_class_mapper import classify_device

try:
    from core.device_manager import DeviceManager
except Exception:  # pragma: no cover - wmi unavailable
    DeviceManager = None


class COMPortManager:
    """Enumerate COM ports and report which ones are newly connected."""

    def __init__(self):

        self._known_ports = set()
        self._first_scan = True

        self._port_signature = None
        self._usb_by_port = {}

    def _usb_devices_by_port(self):
        """Map COM port -> enriched USB device dict from WMI."""

        mapping = {}

        if DeviceManager is None:
            return mapping

        # Keep COM objects local to the scanning thread.
        manager = DeviceManager()
        for dev in manager.enumerate_devices():
            port = str(dev.get("port", "N/A")).upper()
            if port and port != "N/A" and port not in mapping:
                mapping[port] = dev

        return mapping

    def _ids_from_hwid(self, hwid):
        """Extract VID/PID from a pyserial hwid string."""

        vid = pid = "N/A"

        try:
            vid_match = re.search(
                r"VID[_:]([0-9A-F]{4})", hwid, re.IGNORECASE
            )
            pid_match = re.search(
                r"PID[_:]([0-9A-F]{4})", hwid, re.IGNORECASE
            )

            if vid_match:
                vid = vid_match.group(1).upper()
            if pid_match:
                pid = pid_match.group(1).upper()
        except Exception:
            pass

        return vid, pid

    @staticmethod
    def _is_usb_backed(hwid, vid, pid):
        """
        True only when the port is genuinely carried over USB.

        A PCI, virtual or Bluetooth serial port has no USB descriptors, so
        USB-specific fields must not be inferred for it.
        """

        if str(hwid).strip().upper().startswith("USB"):
            return True

        return vid != "N/A" and pid != "N/A"

    def list_ports(self):
        """Return one enriched device dict per COM port present."""

        ports = []

        discovered = list(list_ports.comports())
        signature = sorted(
            (str(info.device), str(info.hwid), str(info.description),
             str(info.serial_number), str(info.vid), str(info.pid))
            for info in discovered
        )
        if signature != self._port_signature:
            self._usb_by_port = (
                self._usb_devices_by_port() if discovered else {}
            )
            self._port_signature = signature

        usb_by_port = self._usb_by_port

        for info in discovered:

            port_name = str(info.device)
            hwid = str(info.hwid or "")

            usb_dev = usb_by_port.get(port_name.upper())

            if usb_dev:
                device = dict(usb_dev)
                device["port"] = port_name
                device["usb_backed"] = True
                ports.append(device)
                continue

            # Not matched to a USB device in WMI: build the record from
            # pyserial metadata alone.
            if info.vid is not None and info.pid is not None:
                vid = f"{info.vid:04X}"
                pid = f"{info.pid:04X}"
            else:
                vid, pid = self._ids_from_hwid(hwid)

            name = str(info.description or port_name)

            usb_backed = self._is_usb_backed(hwid, vid, pid)

            if usb_backed:
                usb_class, subclass, protocol = classify_device(name)

                # A USB device exposing a COM port is, by definition, a USB
                # CDC serial endpoint even when the name tells us nothing.
                if usb_class == "Vendor Specific":
                    usb_class, subclass, protocol = (
                        "CDC", "Serial", "Serial"
                    )
            else:
                # Non-USB serial port (PCI/virtual/Bluetooth). It has no USB
                # descriptors at all, so report them as unavailable rather
                # than inventing plausible-looking values.
                usb_class = subclass = protocol = "N/A"

            ports.append({
                "name": name,
                "vid": vid,
                "pid": pid,
                "usb_class": usb_class,
                "subclass": subclass,
                "port": port_name,
                "protocol": protocol,
                "manufacturer": str(info.manufacturer or "Unknown"),
                "serial": str(info.serial_number or "N/A"),
                "service": "N/A",
                "pnp_class": "Ports" if usb_backed else "N/A",
                "interface": "N/A",
                "device_id": hwid or "N/A",
                "status": "Connected",
                "authorized": "Yes",
                "usb_backed": usb_backed,
            })

        ports.sort(key=lambda d: d.get("port", ""))

        return ports

    def scan(self):
        """
        Return ``(all_ports, new_ports)``.

        ``new_ports`` holds ports that appeared since the previous scan. The
        very first scan reports nothing as new, so an existing port is not
        announced as a fresh connection at startup.
        """

        ports = self.list_ports()

        current = {p["port"] for p in ports}

        if self._first_scan:
            new_names = set()
            self._first_scan = False
        else:
            new_names = current - self._known_ports

        self._known_ports = current

        new_ports = [p for p in ports if p["port"] in new_names]

        return ports, new_ports

    def removed_since(self, previous):
        """Return port names present in ``previous`` but gone now."""
        return sorted(set(previous) - self._known_ports)
