"""
Simple hardware helper utilities for real-device interactions.
Requires `pyusb` and `pyserial` to be installed when using hardware mode.
"""

import time


def modbus_crc(data):
    """Return the Modbus RTU CRC16 for the supplied bytes."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def build_payload(payload, append_crc=False, append_newline=False):
    """Normalise a str/hex/bytes payload into bytes for transmission."""
    if isinstance(payload, (bytes, bytearray)):
        data = bytes(payload)
    elif isinstance(payload, str):
        text = payload.strip()
        if text.lower().startswith("hex:"):
            data = bytes.fromhex(text[4:].replace(" ", ""))
        else:
            data = text.encode("latin1")
    else:
        raise TypeError(f"Unsupported payload type: {type(payload).__name__}")

    if append_newline:
        data += b"\n"
    if append_crc:
        data += modbus_crc(data).to_bytes(2, "little")
    return data


def serial_transaction(
    port,
    payload,
    logger,
    baudrate=115200,
    timeout=2,
    read_size=256,
    settle=0.2,
    expect=None,
    append_crc=False,
    append_newline=False,
    verify_crc=False
):
    """
    Send an arbitrary payload to a serial device and capture the reply.

    This is protocol-neutral: the caller supplies the bytes to send and the
    optional expectation. Nothing device-specific is assumed.

    Returns (ok, info) where info is a dict describing the exchange.
    """
    try:
        import serial
    except Exception as ex:
        logger(f"[WARN] pyserial not available: {ex}")
        return False, {"error": "pyserial_missing"}

    try:
        request = build_payload(payload, append_crc, append_newline)
    except Exception as ex:
        logger(f"[FAIL] Invalid payload: {ex}")
        return False, {"error": f"bad_payload: {ex}"}

    try:
        ser = serial.Serial(
            port=port,
            baudrate=baudrate,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=timeout,
            write_timeout=timeout
        )
    except Exception as ex:
        logger(f"[FAIL] Could not open serial port {port}: {ex}")
        return False, {"error": f"open_failed: {ex}"}

    try:
        ser.reset_input_buffer()
        ser.reset_output_buffer()

        logger(f"[INFO] TX {len(request)} bytes: {request.hex(' ')}")
        ser.write(request)
        ser.flush()

        time.sleep(settle)
        response = ser.read(read_size)

        info = {
            "request": request.hex(" "),
            "response": response.hex(" ") if response else "",
            "response_len": len(response)
        }

        if not response:
            logger("[WARN] No response received within timeout")
            info["error"] = "no_response"
            return False, info

        logger(f"[INFO] RX {len(response)} bytes: {response.hex(' ')}")

        if verify_crc:
            if len(response) < 3:
                logger("[FAIL] Response too short to contain a CRC")
                info["error"] = "response_too_short"
                return False, info
            expected = int.from_bytes(response[-2:], "little")
            actual = modbus_crc(response[:-2])
            info["crc_ok"] = expected == actual
            if not info["crc_ok"]:
                logger(
                    f"[FAIL] CRC mismatch (expected 0x{expected:04X}, "
                    f"computed 0x{actual:04X})"
                )
                info["error"] = "crc_mismatch"
                return False, info
            logger("[PASS] Response CRC valid")

        if expect is not None:
            try:
                needle = build_payload(expect)
            except Exception as ex:
                logger(f"[FAIL] Invalid expectation: {ex}")
                info["error"] = f"bad_expect: {ex}"
                return False, info
            if needle not in response:
                logger(
                    f"[FAIL] Expected pattern {needle.hex(' ')} "
                    "not present in response"
                )
                info["error"] = "expectation_not_met"
                return False, info
            logger("[PASS] Expected pattern found in response")
            info["expect_matched"] = True

        return True, info
    except Exception as ex:
        logger(f"[FAIL] Serial communication error: {ex}")
        return False, {"error": f"comm_error: {ex}"}
    finally:
        ser.close()


def cdc_check(
    port, logger, baudrate=115200, timeout=2, bytesize=8, parity="N",
    stopbits=1, read_unsolicited=True,
):
    try:
        import serial
    except Exception as ex:
        logger(f"[WARN] pyserial not available: {ex}")
        return False, "pyserial not installed"

    try:
        ser = serial.Serial(
            port=port,
            baudrate=baudrate,
            bytesize=bytesize,
            parity=parity,
            stopbits=stopbits,
            timeout=timeout,
            write_timeout=timeout
        )
    except Exception as ex:
        logger(f"[FAIL] Could not open serial port {port}: {ex}")
        return False, f"open_failed: {ex}"

    try:
        logger(
            f"[INFO] Serial port {port} opened at "
            f"{baudrate} baud ({bytesize}-{parity}-{stopbits})"
        )

        if not read_unsolicited:
            logger(
                "[INFO] Port open/close only: no reads or writes; device command acceptance not proven."
            )
            return True, "port_accessible"

        waiting = ser.in_waiting
        if waiting:
            data = ser.read(waiting)
            logger(f"[INFO] Passive serial data received: {data.hex(' ')}")
            return True, "port_accessible_data_received"

        logger(
            "[INFO] Serial port is accessible; no protocol-specific "
            "response required"
        )
        return True, "port_accessible"
    except Exception as ex:
        logger(f"[FAIL] Serial communication error: {ex}")
        return False, f"comm_error: {ex}"
    finally:
        ser.close()


def _format_bcd(value):
    """Format a USB BCD field (such as bcdUSB/bcdDevice) as 'major.minor'."""
    if value is None:
        return None
    try:
        raw = int(value)
    except (TypeError, ValueError):
        return None
    return f"{(raw >> 8) & 0xFF}.{(raw >> 4) & 0x0F}{raw & 0x0F}"


def read_descriptors(vid, pid, logger, require_unique=False):
    try:
        import usb.core
        import usb.util
    except Exception as ex:
        logger(f"[WARN] pyusb not available: {ex}")
        return False, {"error": "pyusb_missing"}

    dev = None
    try:
        backend = None
        try:
            import libusb_package
            import usb.backend.libusb1

            backend = usb.backend.libusb1.get_backend(
                find_library=libusb_package.find_library
            )
        except ImportError:
            pass

        if backend is None:
            import usb.backend.libusb1

            backend = usb.backend.libusb1.get_backend()

        if backend is None:
            logger(
                "[FAIL] PyUSB backend unavailable. Install the Windows "
                "libusb runtime from requirements.txt"
            )
            return False, {"error": "backend_unavailable"}

        if require_unique:
            found = usb.core.find(
                find_all=True, idVendor=int(vid, 16), idProduct=int(pid, 16),
                backend=backend,
            )
            if found is None or isinstance(found, usb.core.Device):
                raise TypeError("USB enumeration did not return a device collection.")
            matches = list(found)
            if len(matches) != 1:
                logger("[ERROR] Suite requires exactly one USB device with this VID/PID.")
                return False, {"error": "missing_or_ambiguous_usb_identity"}
            dev = matches[0]
        else:
            dev = usb.core.find(
                idVendor=int(vid, 16),
                idProduct=int(pid, 16),
                backend=backend
            )
        if dev is None:
            logger(f"[FAIL] USB device VID:PID {vid}:{pid} not found via pyusb")
            return False, {"error": "not_found"}
        if not isinstance(dev, usb.core.Device):
            raise TypeError("USB enumeration did not return a USB device.")

        # Read basic descriptors
        desc = {
            "idVendor": hex(getattr(dev, "idVendor")),
            "idProduct": hex(getattr(dev, "idProduct")),
            "bDeviceClass": getattr(dev, 'bDeviceClass', None),
            "bDeviceSubClass": getattr(dev, 'bDeviceSubClass', None),
            "bDeviceProtocol": getattr(dev, 'bDeviceProtocol', None),
            "bcdUSB": _format_bcd(getattr(dev, 'bcdUSB', None)),
            "bcdDevice": _format_bcd(getattr(dev, 'bcdDevice', None)),
            "bMaxPacketSize0": getattr(dev, 'bMaxPacketSize0', None),
            "bNumConfigurations": getattr(dev, 'bNumConfigurations', None),
            "strings": {},
            "strings_available": False,
            "interfaces": [],
            "interfaces_available": False,
            "interfaces_error": None
        }

        # String descriptors (manufacturer / product / serial). These need a
        # control transfer, which Windows blocks for devices bound to a native
        # class driver, so failure here is expected and non-fatal.
        string_fields = (
            ("manufacturer", "iManufacturer"),
            ("product", "iProduct"),
            ("serial_number", "iSerialNumber")
        )

        for label, attr in string_fields:
            index = getattr(dev, attr, 0)
            if not index:
                continue
            try:
                value = usb.util.get_string(dev, index)
                if value:
                    desc["strings"][label] = value
                    desc["strings_available"] = True
            except Exception:
                pass

        if desc["strings_available"]:
            logger(f"[INFO] String descriptors: {desc['strings']}")

        if desc["bcdDevice"]:
            logger(
                f"[INFO] Device release (bcdDevice): {desc['bcdDevice']}"
            )

        # Attempt to read configuration and interface descriptors in more detail
        try:
            cfg = dev.get_active_configuration()
            if not isinstance(cfg, usb.core.Configuration):
                raise TypeError("Active USB configuration is unavailable.")
            desc["config"] = {
                "bNumInterfaces": getattr(cfg, "bNumInterfaces"),
                "bConfigurationValue": getattr(cfg, "bConfigurationValue")
            }

            for intf in cfg:
                intf_info = {
                    "bInterfaceNumber": getattr(intf, "bInterfaceNumber"),
                    "bInterfaceClass": getattr(intf, "bInterfaceClass"),
                    "bInterfaceSubClass": getattr(intf, "bInterfaceSubClass"),
                    "bInterfaceProtocol": getattr(intf, "bInterfaceProtocol"),
                    "endpoints": []
                }
                try:
                    for ep in intf.endpoints():
                        intf_info["endpoints"].append({
                            "bEndpointAddress": getattr(ep, "bEndpointAddress"),
                            "bmAttributes": getattr(ep, "bmAttributes"),
                            "wMaxPacketSize": getattr(ep, "wMaxPacketSize")
                        })
                except Exception:
                    pass
                desc["interfaces"].append(intf_info)

            desc["interfaces_available"] = True
        except Exception as ex:
            desc["config"] = None
            desc["interfaces_error"] = str(ex)
            logger(
                "[WARN] Interface descriptors unavailable "
                f"({type(ex).__name__}); device is bound to a native class "
                "driver. Interface-level checks will be skipped."
            )

        logger(f"[INFO] Read descriptors for {vid}:{pid}")
        return True, desc

    except Exception as ex:
        logger(f"[FAIL] pyusb error: {ex}")
        return False, {"error": str(ex)}
    finally:
        if dev is not None:
            usb.util.dispose_resources(dev)
