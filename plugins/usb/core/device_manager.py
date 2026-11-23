# device_manager.py

import re
import wmi

from core.usb_class_mapper import classify_device


class DeviceManager:

    def __init__(self):

        self.wmi_conn = wmi.WMI()

    def get_com_ports(self):

        """
        Build a lookup table:
        USB PNP Device ID -> COM Port
        """

        com_ports = {}

        try:

            for port in self.wmi_conn.Win32_SerialPort():

                try:

                    pnp_id = str(port.PNPDeviceID)

                    com_ports[pnp_id] = port.DeviceID

                except Exception:
                    pass

        except Exception:
            pass

        return com_ports

    def find_com_port(self, device_id, com_map):

        """
        Match USB DeviceID with PNPDeviceID
        """

        for pnp_id, com_port in com_map.items():

            try:

                vid_match = re.search(
                    r"VID_([0-9A-F]{4})",
                    pnp_id,
                    re.IGNORECASE
                )

                pid_match = re.search(
                    r"PID_([0-9A-F]{4})",
                    pnp_id,
                    re.IGNORECASE
                )

                dev_vid_match = re.search(
                    r"VID_([0-9A-F]{4})",
                    device_id,
                    re.IGNORECASE
                )

                dev_pid_match = re.search(
                    r"PID_([0-9A-F]{4})",
                    device_id,
                    re.IGNORECASE
                )

                if (
                    vid_match
                    and pid_match
                    and dev_vid_match
                    and dev_pid_match
                ):

                    if (
                        vid_match.group(1)
                        == dev_vid_match.group(1)
                        and
                        pid_match.group(1)
                        == dev_pid_match.group(1)
                    ):
                        return com_port

            except Exception:
                pass

        return "N/A"

    def _extract_serial(self, device_id):
        """
        Return the device serial number from a USB DeviceID, or "N/A".

        The final DeviceID segment is either a real serial number or a
        Windows-generated instance path. Instance paths contain "&", so they
        are rejected.
        """

        try:

            parts = str(device_id).split("\\")

            if len(parts) < 3:
                return "N/A"

            candidate = parts[-1].strip()

            if not candidate or "&" in candidate:
                return "N/A"

            return candidate

        except Exception:
            return "N/A"

    def _device_status(self, dev):
        """
        Map the Windows Configuration Manager error code to a status string.

        Code 0 means the device is started and problem-free. Any other code
        indicates a real problem (disabled, driver error, resource conflict).
        """

        try:

            code = dev.ConfigManagerErrorCode

            if code is None:
                return (
                    "Connected"
                    if str(dev.Status).upper() == "OK"
                    else "Error"
                )

            return (
                "Connected"
                if int(code) == 0
                else f"Error ({int(code)})"
            )

        except Exception:
            return "Connected"

    def enumerate_devices(self):

        devices = []

        com_map = self.get_com_ports()

        for dev in self.wmi_conn.Win32_PnPEntity():

            try:

                device_id = str(dev.DeviceID)

                if "USB" not in device_id.upper():
                    continue

                device_name = (
                    dev.Name
                    if dev.Name
                    else "Unknown Device"
                )

                vid_match = re.search(
                    r"VID_([0-9A-F]{4})",
                    device_id,
                    re.IGNORECASE
                )

                pid_match = re.search(
                    r"PID_([0-9A-F]{4})",
                    device_id,
                    re.IGNORECASE
                )

                vid = (
                    vid_match.group(1)
                    if vid_match else "N/A"
                )

                pid = (
                    pid_match.group(1)
                    if pid_match else "N/A"
                )

                service = (
                    str(dev.Service)
                    if dev.Service
                    else ""
                )

                pnp_class = (
                    str(getattr(dev, "PNPClass", "") or "")
                )

                usb_class, subclass, protocol = (
                    classify_device(
                        device_name,
                        service,
                        pnp_class
                    )
                )

                port = self.find_com_port(
                    device_id,
                    com_map
                )

                manufacturer = (
                    str(dev.Manufacturer)
                    if dev.Manufacturer
                    else "Unknown"
                )

                interface_match = re.search(
                    r"MI_([0-9A-F]{2})",
                    device_id,
                    re.IGNORECASE
                )

                devices.append({

                    "name": device_name,

                    "vid": vid,

                    "pid": pid,

                    "usb_class": usb_class,

                    "subclass": subclass,

                    "port": port,

                    "protocol": protocol,

                    "manufacturer": manufacturer,

                    "serial": self._extract_serial(device_id),

                    "service": service if service else "N/A",

                    "pnp_class": pnp_class if pnp_class else "N/A",

                    "interface": (
                        interface_match.group(1)
                        if interface_match else "N/A"
                    ),

                    "device_id": device_id,

                    "status": self._device_status(dev),

                    "authorized": "Yes",

                    "detected_order" : len(devices)

                })

            except Exception:
                pass
        devices.reverse()
        return devices