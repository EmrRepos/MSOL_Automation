"""Windows CDC evidence tied to the selected COM interface, never a VID/PID-only join."""

import os
import re


def match_cdc_driver(device, entities):
    port = str(device.get("port", "")).upper()
    matches = [
        entity for entity in entities
        if re.search(r"\(" + re.escape(port) + r"\)\s*$", str(entity.Name), re.IGNORECASE)
    ]
    if len(matches) != 1:
        return {"confirmed": False, "details": f"Expected one PnP entity for {port}; found {len(matches)}."}
    entity = matches[0]
    identity = str(entity.DeviceID or "").upper()
    if not identity.startswith("USB\\"):
        return {"confirmed": False, "details": f"{port} is not a USB PnP interface."}
    for key in ("vid", "pid"):
        expected = str(device.get(key, "")).upper().removeprefix("0X").zfill(4)
        if not re.search(r"(?:\\|&)" + key.upper() + "_" + re.escape(expected) + r"(?:&|\\|$)", identity):
            return {"confirmed": False, "details": f"{port} PnP {key.upper()} differs from selected device."}
    serial = device.get("serial")
    if serial and serial not in ("N/A", "Unknown") and identity.rsplit("\\", 1)[-1] != str(serial).upper():
        return {
            "confirmed": False,
            "details": f"{port} PnP instance cannot be correlated to selected serial number.",
        }
    service = str(entity.Service or "").lower()
    compatible_ids = list(entity.CompatibleID or [])
    cdc_ids = [
        value for value in compatible_ids
        if re.match(r"^USB\\Class_(?:02|0A)(?:&|$)", str(value), re.IGNORECASE)
    ]
    confirmed = service == "usbser" or bool(cdc_ids)
    return {
        "confirmed": confirmed, "port": port, "device_id": identity,
        "service": service, "compatible_ids": compatible_ids,
        "details": (
            f"Exact-port PnP evidence: {port}, service={service}, CDC compatible IDs={cdc_ids}. "
            "Driver evidence is not a raw descriptor or command/response test."
            if confirmed else
            f"Exact-port PnP entity found for {port}, but service={service} and "
            "compatible IDs do not establish CDC. A COM port alone does not prove CDC."
        ),
    }


def inspect_cdc_driver(device):
    port = str(device.get("port", "")).upper()
    if not re.fullmatch(r"COM[1-9]\d*", port):
        return {"confirmed": False, "details": "Select a valid COM port for CDC driver evidence."}
    if os.name != "nt":
        return {"confirmed": False, "details": "Windows CDC driver evidence unavailable on this platform."}
    import pythoncom
    import win32com.client

    pythoncom.CoInitialize()
    connection = None
    entities = None
    try:
        connection = win32com.client.GetObject(r"winmgmts:root\cimv2")
        entities = connection.ExecQuery(
            "SELECT DeviceID, Name, Service, CompatibleID FROM Win32_PnPEntity "
            f"WHERE Name LIKE '%({port})'"
        )
        return match_cdc_driver(device, entities)
    except pythoncom.com_error as error:
        return {"confirmed": False, "details": f"CDC PnP query failed for {port}: {error}"}
    finally:
        # Release apartment-bound COM wrappers before uninitializing this worker thread.
        entities = None
        connection = None
        pythoncom.CoUninitialize()
