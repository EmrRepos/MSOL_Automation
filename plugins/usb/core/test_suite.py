"""Sequential, evidence-labelled suite execution; no automatic protocol guessing."""

from copy import deepcopy
from datetime import datetime
from time import monotonic
from uuid import uuid4

from serial.tools import list_ports

from core import hardware_helpers
from core.serial_evidence import inspect_cdc_driver


SUITE_NAME = "Standard USB Validation"
STANDARD = (
    "Enumeration Validation", "Descriptor Validation", "Descriptor Robustness Test",
    "Endpoint Validation", "CDC Validation", "HID Validation", "Storage Validation",
)
STRESS = ("Enumeration Stress Test", "Stability Validation")


def _id(value):
    text = str(value or "").upper().removeprefix("0X")
    return text.zfill(4) if text not in ("", "N/A", "NONE") else ""


def refresh_device(selected):
    """Refresh COM presence and identity without opening the port or using cached WMI."""
    matches = [
        port for port in list_ports.comports()
        if port.device.upper() == str(selected.get("port", "")).upper()
    ]
    if len(matches) != 1:
        raise ConnectionError("Selected COM port is absent or ambiguous; suite stopped.")
    port = matches[0]
    for key, value in (("vid", port.vid), ("pid", port.pid)):
        expected = _id(selected.get(key))
        actual = f"{value:04X}" if value is not None else ""
        if expected != actual:
            raise ConnectionError(f"Device {key.upper()} changed; reselect the device.")
    serial = selected.get("serial")
    if serial and serial not in ("N/A", "Unknown") and serial != port.serial_number:
        raise ConnectionError("Device serial number changed or is unavailable.")
    if not serial or serial in ("N/A", "Unknown"):
        expected_hwid = selected.get("device_id")
        if expected_hwid and expected_hwid != "N/A" and expected_hwid.upper() != port.hwid.upper():
            raise ConnectionError("Device hardware identity changed; reselect the device.")
    updated = dict(selected)
    updated.update(
        status="Connected", name=port.description or port.device,
        manufacturer=port.manufacturer or "Unknown",
        serial=port.serial_number or "N/A",
    )
    return updated


def overall_status(rows):
    statuses = {row["status"] for row in rows}
    for status in ("CANCELLED", "ERROR", "FAIL", "BLOCKED"):
        if status in statuses:
            return status
    return "PASS" if "PASS" in statuses else "BLOCKED"


class ApplicableSuite:
    def __init__(self, plugins, refresh=refresh_device, read_descriptors=None):
        self.plugins = plugins
        self.refresh = refresh
        self.read_descriptors = read_descriptors or hardware_helpers.read_descriptors

    def run(
        self, device, hardware, cancel, logger, progress, update,
        duration_seconds=0, interval_seconds=30,
    ):
        if type(duration_seconds) is not int or not 0 <= duration_seconds <= 600:
            raise ValueError("Validation duration must be 0 to 600 seconds.")
        if type(interval_seconds) is not int or not 1 <= interval_seconds <= 60:
            raise ValueError("Validation interval must be 1 to 60 seconds.")
        if not duration_seconds:
            return self._run_once(device, hardware, cancel, logger, progress, update)
        started = monotonic()
        deadline = started + duration_seconds
        aggregate = None
        round_number = 0
        progress(0)
        while True:
            round_number += 1
            logger(f"[INFO] Revalidation sample {round_number}; fresh identity and descriptor observations.")
            sample = self._run_once(device, hardware, cancel, logger, lambda value: None, update)
            if aggregate is None:
                aggregate = deepcopy(sample)
                for row in aggregate["results"]:
                    row["samples"] = []
            for row, observed in zip(aggregate["results"], sample["results"]):
                samples = row["samples"]
                samples.append(deepcopy(observed))
                worst = next(
                    (status for status in ("CANCELLED", "ERROR", "FAIL", "BLOCKED", "PASS", "SKIPPED")
                     if any(item["status"] == status for item in samples)),
                    "BLOCKED",
                )
                representative = next(item for item in reversed(samples) if item["status"] == worst)
                row.update(deepcopy(representative))
                row["samples"] = samples
                row["duration"] = round(sum(item["duration"] for item in samples), 3)
                row["sample_count"] = len(samples)
                row["status_counts"] = {
                    status: sum(item["status"] == status for item in samples)
                    for status in dict.fromkeys(item["status"] for item in samples)
                }
                row["details"] = [
                    f"Revalidation: {len(samples)} samples; " +
                    ", ".join(f"{key}: {value}" for key, value in row["status_counts"].items()) +
                    ". Earlier failures or blocked observations are not hidden by later passes.",
                    *representative["details"],
                ]
                update(deepcopy(row))
            elapsed = monotonic() - started
            progress(min(99, int(100 * elapsed / duration_seconds)))
            if cancel.is_set() or sample.get("identity_lost") or monotonic() >= deadline:
                break
            # Never overlap requests or catch up with bursts after slow native calls.
            next_sample = min(deadline, monotonic() + interval_seconds)
            while monotonic() < next_sample:
                if cancel.wait(min(1.0, next_sample - monotonic())):
                    break
                progress(min(99, int(100 * (monotonic() - started) / duration_seconds)))
            if cancel.is_set():
                break
        aggregate["finished"] = datetime.now().isoformat(timespec="seconds")
        aggregate["validation"] = {
            "requested_seconds": duration_seconds, "interval_seconds": interval_seconds,
            "elapsed_seconds": round(monotonic() - started, 3), "rounds": round_number,
            "completed": not cancel.is_set() and not sample.get("identity_lost"),
        }
        aggregate["identity_lost"] = sample.get("identity_lost", False)
        aggregate["status"] = overall_status(aggregate["results"])
        if cancel.is_set():
            aggregate["status"] = "CANCELLED"
            for row in aggregate["results"]:
                row["status"] = "CANCELLED"
                row["details"].append("Revalidation stopped before the full observation window completed.")
                update(deepcopy(row))
        if not cancel.is_set() and not aggregate["identity_lost"]:
            progress(100)
        logger(
            "[INFO] Revalidation observes USB/OS evidence only, not device protocol acceptance. "
            "Unavailable descriptors remain unavailable regardless of duration."
        )
        return aggregate

    def _run_once(self, device, hardware, cancel, logger, progress, update):
        result = {
            "run_id": uuid4().hex,
            "suite": SUITE_NAME,
            "started": datetime.now().isoformat(timespec="seconds"),
            "device": deepcopy(device),
            "mode": "LIVE HARDWARE + OS METADATA" if hardware else "METADATA ONLY (NO LIVE DEVICE I/O)",
            "results": [],
            "report_errors": [],
        }
        names = STANDARD
        for name in names:
            result["results"].append({
                "profile": name, "status": "PENDING", "duration": 0.0,
                "evidence": "", "details": [], "log": [],
            })
        for row in result["results"]:
            update(deepcopy(row))
        progress(0)
        stopped_reason = None
        descriptors = None
        descriptor_error = "Hardware mode is disabled."
        for index, row in enumerate(result["results"]):
            name = row["profile"]
            started = monotonic()
            row["started"] = datetime.now().isoformat(timespec="seconds")
            logger(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] START CHECK: {name}")
            try:
                if cancel.is_set():
                    row.update(status="CANCELLED", details=["Stop requested; no further device operations."])
                elif stopped_reason:
                    row.update(status="BLOCKED", details=[stopped_reason])
                else:
                    row["status"] = "RUNNING"
                    update(deepcopy(row))

                    def log(message):
                        row["log"].append(str(message))
                        logger(f"[{name}] {message}")

                    # Even metadata-only runs refresh OS identity; no cached Connected flag.
                    current = self.refresh(device)
                    row["observed_at"] = datetime.now().isoformat(timespec="seconds")
                    row["observed_device"] = deepcopy(current)
                    row["evidence"] = "Fresh OS port identity + selected-device metadata"
                    if hardware and name == "Descriptor Validation":
                        ok, info = self.read_descriptors(
                            current.get("vid"), current.get("pid"), log,
                            require_unique=True,
                        )
                        if ok:
                            descriptors = info
                            descriptor_error = ""
                        else:
                            descriptor_error = f"Live descriptor access unavailable: {info}"
                    if cancel.is_set():
                        row.update(status="CANCELLED", details=["Stop requested after current I/O completed."])
                    else:
                        self._execute(
                            row, current, hardware, descriptors, descriptor_error,
                            log,
                        )
                    # Catch disappearance during the operation before proceeding to another test.
                    self.refresh(device)
            except ConnectionError as error:
                stopped_reason = str(error)
                row.update(status="ERROR", details=[stopped_reason])
                logger(f"[ERROR] {stopped_reason}")
            except Exception as error:
                row.update(status="ERROR", details=[f"{type(error).__name__}: {error}"])
                logger(f"[ERROR] {name}: {error}")
            row["duration"] = round(monotonic() - started, 3)
            row["finished"] = datetime.now().isoformat(timespec="seconds")
            if cancel.is_set() and row["status"] not in ("SKIPPED", "BLOCKED", "ERROR"):
                row.update(status="CANCELLED", details=row["details"] + ["Cancellation requested."])
            update(deepcopy(row))
            logger(f"[{row['status']}] {name}: {'; '.join(map(str, row['details']))}")
            logger(
                f"[{datetime.now():%Y-%m-%d %H:%M:%S}] STOP CHECK: {name} | "
                f"{row['status']} | {row['duration']}s"
            )
            logger("--------------------")
            progress(round(100 * (index + 1) / len(names)))
        result["finished"] = datetime.now().isoformat(timespec="seconds")
        result["identity_lost"] = stopped_reason is not None
        result["status"] = overall_status(result["results"])
        return result

    def _execute(
        self, row, device, hardware, descriptors, descriptor_error, log,
    ):
        name = row["profile"]
        info = descriptors or {}
        interfaces = info.get("interfaces", [])
        if name == "Descriptor Validation" and hardware and not descriptors:
            row.update(status="BLOCKED", details=[descriptor_error])
            return
        if name == "Endpoint Validation":
            if not info.get("interfaces_available"):
                row.update(status="BLOCKED", details=[
                    descriptor_error or "Interface/endpoint descriptors unavailable; no metadata-only pass."
                ])
                return
            endpoints = [ep for interface in interfaces for ep in interface.get("endpoints", [])]
            row.update(
                status="PASS" if endpoints else "FAIL",
                evidence="Live USB configuration descriptors (snapshot this run)",
                details=[f"Endpoints: {endpoints}"],
            )
            return
        class_codes = {"CDC Validation": (2, 10), "HID Validation": (3,), "Storage Validation": (8,)}
        class_names = {"CDC Validation": "CDC", "HID Validation": "HID", "Storage Validation": "Mass Storage"}
        if name in class_codes:
            if info.get("interfaces_available"):
                found = any(i.get("bInterfaceClass") in class_codes[name] for i in interfaces)
                if not found:
                    row.update(status="SKIPPED", details=["No matching interface in live descriptors."])
                    return
                device = dict(device, usb_class=class_names[name])
                row["evidence"] = "Live interface descriptors + fresh OS port metadata; no serial open/probe"
            elif hardware:
                if name == "CDC Validation":
                    driver = inspect_cdc_driver(device)
                    row["driver_evidence"] = driver
                    if driver["confirmed"]:
                        row.update(
                            status="PASS",
                            evidence=f"Fresh exact-port Windows CDC driver evidence: {driver.get('service', '')}",
                            details=[driver["details"]],
                        )
                        return
                    row.update(status="BLOCKED", details=[
                        driver["details"], "Raw interface descriptors also unavailable.",
                    ])
                else:
                    row.update(status="BLOCKED", details=[
                        "OS class label alone does not verify presence/absence of this USB interface; "
                        "live descriptors unavailable. CDC evidence does not rule out composite HID/storage interfaces."
                    ])
                return
            elif device.get("usb_class") != class_names[name]:
                row.update(
                    status="BLOCKED" if device.get("usb_class") in ("Unknown", "Vendor Specific", "Composite", "N/A", None) else "SKIPPED",
                    details=["Matching interface not established; interface descriptors unavailable."],
                )
                return
        # Common plugins here validate metadata; hardware evidence is appended explicitly.
        outcome = self.plugins[name]().execute(device, log, False)
        if outcome.get("status") not in ("PASS", "FAIL", "ERROR", "BLOCKED", "CANCELLED"):
            raise ValueError(f"Invalid plugin result: {outcome}")
        row.update(status=outcome["status"], details=list(outcome.get("details", [])))
        if name == "Descriptor Validation" and hardware:
            row["evidence"] = "Live USB descriptors + fresh OS identity + selected-device metadata"
            row["descriptor_snapshot"] = deepcopy(descriptors)
