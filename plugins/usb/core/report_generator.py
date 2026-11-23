# core/report_generator.py

import os
import csv
import ast
import re
from pathlib import Path
from dataclasses import asdict
from xml.sax.saxutils import escape

from datetime import datetime
from core.packet_analysis import AnalysisResult

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
    ,Table,
    TableStyle,
)
from reportlab.lib import colors

from reportlab.lib.styles import (
    getSampleStyleSheet
)

ABBREVIATIONS = (
    ("USB", "Universal Serial Bus"), ("OS", "Operating System"),
    ("VID", "Vendor Identifier"), ("PID", "Product Identifier"),
    ("COM", "Serial communications port"), ("CDC", "Communications Device Class"),
    ("ACM", "Abstract Control Model"), ("HID", "Human Interface Device"),
    ("PnP", "Plug and Play"), ("WMI", "Windows Management Instrumentation"),
    ("I/O", "Input/Output"), ("RX", "Received data"), ("TX", "Transmitted data"),
    ("PDF", "Portable Document Format"), ("CSV", "Comma-Separated Values"),
    ("ID", "Identifier"), ("Mfr", "Manufacturer"), ("HEX", "Hexadecimal"),
    ("pyusb", "Python USB access library"),
    ("N/A", "Not available / not applicable"), ("INFO", "Information"),
    ("WARN", "Warning"), ("s", "Seconds"), ("ms", "Milliseconds"),
    ("bcd", "Binary-Coded Decimal"), ("usbser", "Windows USB serial class driver"),
)
FIELD_LABELS = {
    "vid": "VID", "pid": "PID", "usb_class": "USB class", "pnp_class": "PnP class",
    "device_id": "Device identity", "idVendor": "Vendor ID", "idProduct": "Product ID",
    "bDeviceClass": "Device class", "bDeviceSubClass": "Device subclass",
    "bDeviceProtocol": "Device protocol", "bcdUSB": "USB version",
    "bcdDevice": "Device release", "bMaxPacketSize0": "Maximum packet size (endpoint 0)",
    "bNumConfigurations": "Number of configurations", "bInterfaceClass": "Interface class",
    "bEndpointAddress": "Endpoint address",
}


def readable_lines(value, prefix=""):
    """Flatten structured evidence into labelled lines, never an inline dictionary."""
    if isinstance(value, dict):
        lines = []
        for key, child in value.items():
            label = FIELD_LABELS.get(key)
            if label is None:
                label = str(key).replace("_", " ")
                label = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", label)
            lines.extend(readable_lines(child, f"{prefix} / {label}" if prefix else label))
        return lines or [f"{prefix}: None recorded"]
    if isinstance(value, (list, tuple)):
        lines = []
        for index, child in enumerate(value, 1):
            lines.extend(readable_lines(child, f"{prefix} / item {index}"))
        return lines or [f"{prefix}: None recorded"]
    if isinstance(value, str):
        if value.rstrip().endswith(("}", "]")) and len(value) <= 65536:
            for start in sorted({value.find(char) for char in ("{", "[") if char in value}):
                try:
                    parsed = ast.literal_eval(value[start:])
                except (ValueError, SyntaxError, TypeError, RecursionError):
                    continue
                if isinstance(parsed, (dict, list, tuple)):
                    heading = value[:start].strip().rstrip(":")
                    return readable_lines(parsed, f"{prefix} / {heading}" if prefix and heading else prefix or heading)
    if isinstance(value, bool):
        value = "Yes" if value else "No"
    elif value is None:
        value = "Not available"
    return [f"{prefix}: {value}" if prefix else str(value)]


def readable_text(value):
    return "\n".join(f"- {line}" for line in readable_lines(value))


class ReportGenerator:

    def __init__(self):

        os.makedirs(
            "reports",
            exist_ok=True
        )

    def export_packet_analysis(self, result: AnalysisResult, base: Path, logger):
        """Export local packet evidence as PDF/CSV; report every export failure."""
        paths = {}
        errors = []
        summary = {
            "Source capture": result.source, "Capture SHA256": result.sha256,
            "Analysis completed (UTC)": result.analyzed_at,
            "Scope": "Whole hub; no target identity asserted",
            "Packets parsed": result.packets,
            "Payload records scanned": result.payload_records_scanned,
            "Payload bytes scanned": result.payload_bytes_scanned,
            "Payload records skipped": result.skipped_payload_records,
            "Truncated records": result.truncated_records,
            "Malformed records": result.malformed_records,
            "Finding groups": len(result.findings),
            "Bus/address pairs": sorted(result.devices),
            "Assessment": "Observations only; not a security PASS or certification",
        }
        try:
            styles = getSampleStyleSheet()
            story = []

            def paragraph(value, style="Normal"):
                story.append(Paragraph(escape(str(value)).replace("\n", "<br/>"), styles[style]))
                story.append(Spacer(1, 6))

            def bullets(value):
                for line in readable_lines(value):
                    story.append(Paragraph(escape(line), styles["Normal"], bulletText="-"))
                    story.append(Spacer(1, 3))

            paragraph("USB Packet Security Analysis Report", "Title")
            bullets(summary)
            paragraph("Coverage and limitations", "Heading2")
            bullets(result.limitations)
            paragraph("Evidence reference guide", "Heading2")
            bullets({
                "Frame": "1-based original PCAP frame number (Wireshark frame.number).",
                "File offset": "Byte offset of the PCAP record header, not the USB payload.",
                "Packet SHA256": "SHA-256 of captured USBPcap pseudoheader plus captured packet bytes.",
                "Payload SHA256": "SHA-256 of captured payload bytes after the USBPcap pseudoheader.",
                "Evidence samples": "Up to five examples per rule/bus/address/endpoint; occurrences counts matches.",
                "Severity": "MEDIUM is a triage priority for credential-like patterns, not confirmed impact.",
                "URB": "USB Request Block; not a device-protocol sequence number.",
                "UTC": "Coordinated Universal Time. SHA-256: Secure Hash Algorithm, 256-bit.",
                "USB / PCAP": "Universal Serial Bus / Packet Capture.",
            })
            paragraph("Findings and observations", "Heading2")
            if not result.findings:
                paragraph("No configured-rule matches. This does not establish that the device is secure.")
            for index, finding in enumerate(result.findings, 1):
                paragraph(f"{index}. {finding.title} [{finding.severity}] - {finding.verification}", "Heading2")
                bullets({
                    "Rule": finding.rule, "Bus": finding.bus, "Address": finding.address,
                    "Endpoint": f"0x{finding.endpoint:02x}" if finding.endpoint is not None else "Unknown",
                    "Occurrences": finding.occurrences, "Explanation": finding.explanation,
                    "Development follow-up": finding.recommendation,
                    "Packet evidence": [asdict(item) for item in finding.evidence],
                })
            SimpleDocTemplate(str(base.with_suffix(".pdf"))).build(story)
            paths["pdf"] = str(base.with_suffix(".pdf").resolve())
        except Exception as error:
            errors.append(f"PDF analysis report failed: {error}")
            logger(f"[ERROR] {errors[-1]}")
        fields = [
            "source", "capture_sha256", "analyzed_at", "scope", "packets",
            "payload_records_scanned", "payload_bytes_scanned", "skipped_payload_records",
            "truncated_records", "malformed_records", "rule", "severity", "verification",
            "title", "bus", "address", "endpoint", "occurrences",
            "explanation", "recommendation", "evidence", "limitations", "report_errors",
        ]
        try:
            with base.with_suffix(".csv").open("w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=fields)
                writer.writeheader()
                for finding in result.findings or [None]:
                    writer.writerow({
                        "source": result.source, "capture_sha256": result.sha256,
                        "analyzed_at": result.analyzed_at, "scope": "Whole hub; target identity unverified",
                        **{key: getattr(result, key) for key in (
                            "packets", "payload_records_scanned", "payload_bytes_scanned",
                            "skipped_payload_records", "truncated_records", "malformed_records",
                        )},
                        **({key: getattr(finding, key) for key in (
                            "rule", "severity", "verification", "title", "bus", "address",
                            "endpoint", "occurrences", "explanation", "recommendation",
                        )} if finding else {
                            "verification": "NOT ASSESSED", "title": "No configured-rule matches; not a security pass",
                        }),
                        "evidence": readable_text(
                            [asdict(item) for item in finding.evidence] if finding else []
                        ),
                        "limitations": readable_text(result.limitations),
                        "report_errors": "\n".join(errors),
                    })
            paths["csv"] = str(base.with_suffix(".csv").resolve())
        except (OSError, csv.Error) as error:
            errors.append(f"CSV analysis report failed: {error}")
            logger(f"[ERROR] {errors[-1]}")
        for kind, path in paths.items():
            logger(f"[INFO] Packet analysis {kind.upper()} report: {path}")
        return paths, errors

    def export_suite(self, result, logger):
        """Replace the latest suite PDF/CSV reports, preserving evidence and outcomes."""
        base = Path("reports") / "USB_Suite_Validation_Report"
        paths = {}
        result["report_paths"] = paths
        rows = result["results"]
        try:
            styles = getSampleStyleSheet()
            story = []

            def paragraph(text, style="Normal"):
                story.append(Paragraph(escape(str(text)).replace("\n", "<br/>"), styles[style]))
                story.append(Spacer(1, 8))

            def bullets(value):
                for line in readable_lines(value):
                    story.append(Paragraph(escape(line), styles["Normal"], bulletText="-"))
                    story.append(Spacer(1, 3))

            paragraph(f"{result.get('suite', 'USB Device Suite')} Report", "Title")
            paragraph("Run summary", "Heading2")
            bullets({key: result[key] for key in ("run_id", "status", "mode", "started", "finished")})
            if "validation" in result:
                bullets({"Revalidation schedule and coverage": result["validation"]})
            paragraph("Checks at a glance", "Heading2")
            overview = Table(
                [[Paragraph(value, styles["Normal"]) for value in ("Check", "Outcome", "Samples")]] +
                [[Paragraph(escape(str(value)), styles["Normal"]) for value in (
                    row["profile"], row["status"], row.get("sample_count", 1)
                )] for row in rows],
                colWidths=[270, 110, 70], repeatRows=1, hAlign="LEFT",
            )
            overview.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(overview)
            paragraph(
                "Repeated observations do not verify device commands, measurements or protocol correctness. "
                "Unavailable descriptors remain BLOCKED; earlier failures remain visible."
            )
            paragraph("Device identity", "Heading2")
            bullets(result["device"])
            paragraph("Abbreviations", "Heading2")
            table = Table(
                [[Paragraph("Short form", styles["Normal"]), Paragraph("Meaning", styles["Normal"])]] +
                [[Paragraph(escape(key), styles["Normal"]), Paragraph(escape(value), styles["Normal"])]
                 for key, value in ABBREVIATIONS],
                colWidths=[90, 360], repeatRows=1, hAlign="LEFT",
            )
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(table)
            paragraph("Result meanings", "Heading2")
            bullets({
                "PASS": "The stated check succeeded; not proof of device-protocol acceptance.",
                "FAIL": "An evaluated requirement failed.",
                "BLOCKED": "Insufficient evidence or access; no pass is claimed.",
                "SKIPPED": "A verified interface is not applicable.",
                "ERROR": "An operation or report failed.",
                "CANCELLED": "The requested observation window was stopped.",
            })
            for row in rows:
                paragraph(f"{row['profile']} - {row['status']} ({row['duration']}s active checks)", "Heading2")
                paragraph(f"Evidence: {row['evidence']}")
                if row.get("samples"):
                    paragraph("Revalidation samples", "Heading3")
                    bullets([
                        {
                            "Sample": index, "Observed at": sample.get("observed_at", "Not recorded"),
                            "Status": sample["status"], "Evidence": sample["evidence"],
                            "Details": sample["details"],
                        }
                        for index, sample in enumerate(row["samples"], 1)
                    ])
                for key in ("observed_at", "driver_evidence", "descriptor_snapshot"):
                    if key in row:
                        bullets({key: row[key]})
                changes = {
                    key: value for key, value in row.get("observed_device", {}).items()
                    if result["device"].get(key) != value
                }
                if changes:
                    bullets({"Observed identity differences from selected device": changes})
                else:
                    paragraph("Observed identity matches the device identity above.")
                for detail in row["details"]:
                    bullets(detail)
            paragraph("Diagnostic log appendix (duplicate lines omitted)", "Heading2")
            for row in rows:
                paragraph(row["profile"], "Heading3")
                samples = row.get("samples") or [row]
                lines = dict.fromkeys(line for sample in samples for line in sample["log"])
                for line in lines:
                    if line.strip("- "):
                        bullets(line)
            for error in result["report_errors"]:
                paragraph(f"REPORT ERROR: {error}")
            SimpleDocTemplate(str(base.with_suffix(".pdf"))).build(story)
            paths["pdf"] = str(base.with_suffix(".pdf").resolve())
        except Exception as error:
            self._suite_report_error(result, logger, "PDF", error)
        fields = [
            "run_id", "suite", "mode", "started", "finished", "overall_status",
            "device_name", "port", "vid", "pid", "serial",
            "profile", "status", "duration", "evidence", "details", "log",
            "observed_at", "observed_device", "driver_evidence", "report_errors",
            "descriptor_snapshot", "revalidation", "samples", "abbreviations",
        ]
        try:
            with base.with_suffix(".csv").open("w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=fields)
                writer.writeheader()
                for row in rows:
                    writer.writerow({
                        **{key: result[key] for key in ("run_id", "suite", "mode", "started", "finished")},
                        "overall_status": result["status"],
                        "device_name": result["device"].get("name"),
                        **{key: result["device"].get(key) for key in ("port", "vid", "pid", "serial")},
                        **{key: row[key] for key in ("profile", "status", "duration", "evidence")},
                        "details": readable_text(row["details"]),
                        "log": readable_text(row["log"]),
                        **{key: readable_text(row.get(key, "")) for key in (
                            "observed_at", "observed_device", "driver_evidence", "descriptor_snapshot"
                        )},
                        "report_errors": "\n".join(result["report_errors"]),
                        "revalidation": readable_text(result.get("validation", {})),
                        "samples": readable_text(row.get("samples", [])),
                        "abbreviations": "\n".join(f"{key}: {value}" for key, value in ABBREVIATIONS),
                    })
            paths["csv"] = str(base.with_suffix(".csv").resolve())
        except (OSError, csv.Error) as error:
            self._suite_report_error(result, logger, "CSV", error)
        for kind, path in paths.items():
            logger(f"[INFO] Combined suite {kind.upper()} report: {path}")
        return paths

    @staticmethod
    def _suite_report_error(result, logger, kind, error):
        message = f"{kind} report failed: {error}"
        result["report_errors"].append(message)
        result["status"] = "ERROR"
        logger(f"[ERROR] {message}")

    def export_csv(
        self,
        device,
        profile,
        result
    ):

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        filename = os.path.join(
            "reports",
            f"USB_Report_{timestamp}.csv"
        )

        with open(
            filename,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Timestamp",
                "Device Name",
                "VID",
                "PID",
                "USB Class",
                "Port",
                "Status",
                "Profile",
                "Result",
                "Passed",
                "Total"
            ])

            writer.writerow([
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                device.get("name", "Unknown"),
                device.get("vid", "N/A"),
                device.get("pid", "N/A"),
                device.get("usb_class", "Unknown"),
                device.get("port", "N/A"),
                device.get("status", "Unknown"),
                profile,
                result.get("status", "UNKNOWN"),
                result.get("passed", 0),
                result.get("total", 0)
            ])

        return filename

    def export_pdf(
        self,
        device,
        profile,
        result
    ):

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        filename = os.path.join(
            "reports",
            f"USB_Report_{timestamp}.pdf"
        )

        doc = SimpleDocTemplate(
            filename
        )

        styles = getSampleStyleSheet()

        story = []

        #
        # Header
        #

        story.append(
            Paragraph(
                "USB VALIDATION TEST REPORT",
                styles["Title"]
            )
        )

        story.append(
            Spacer(1, 20)
        )

        #
        # Test Information
        #

        story.append(
            Paragraph(
                "Test Information",
                styles["Heading2"]
            )
        )

        story.append(
            Paragraph(
                f"<b>Timestamp:</b> "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                styles["Normal"]
            )
        )

        story.append(
            Paragraph(
                f"<b>Profile:</b> {profile}",
                styles["Normal"]
            )
        )

        story.append(
            Paragraph(
                f"<b>Result:</b> "
                f"{result.get('status', 'UNKNOWN')}",
                styles["Normal"]
            )
        )

        story.append(
            Spacer(1, 15)
        )

        #
        # Device Information
        #

        story.append(
            Paragraph(
                "Device Information",
                styles["Heading2"]
            )
        )

        story.append(
            Paragraph(
                f"Device Name : "
                f"{device.get('name', 'Unknown')}",
                styles["Normal"]
            )
        )

        story.append(
            Paragraph(
                f"VID : "
                f"{device.get('vid', 'N/A')}",
                styles["Normal"]
            )
        )

        story.append(
            Paragraph(
                f"PID : "
                f"{device.get('pid', 'N/A')}",
                styles["Normal"]
            )
        )

        story.append(
            Paragraph(
                f"USB Class : "
                f"{device.get('usb_class', 'Unknown')}",
                styles["Normal"]
            )
        )

        story.append(
            Paragraph(
                f"Port : "
                f"{device.get('port', 'N/A')}",
                styles["Normal"]
            )
        )

        story.append(
            Paragraph(
                f"Status : "
                f"{device.get('status', 'Unknown')}",
                styles["Normal"]
            )
        )

        story.append(
            Spacer(1, 15)
        )

        #
        # Validation Summary
        #

        story.append(
            Paragraph(
                "Validation Summary",
                styles["Heading2"]
            )
        )

        story.append(
            Paragraph(
                f"Passed Checks : "
                f"{result.get('passed', 0)}",
                styles["Normal"]
            )
        )

        story.append(
            Paragraph(
                f"Total Checks : "
                f"{result.get('total', 0)}",
                styles["Normal"]
            )
        )

        story.append(
            Spacer(1, 15)
        )

        #
        # Validation Details
        #

        story.append(
            Paragraph(
                "Validation Details",
                styles["Heading2"]
            )
        )

        details = result.get(
            "details",
            []
        )

        if details:

            for item in details:

                story.append(
                    Paragraph(
                        f"✓ {item}",
                        styles["Normal"]
                    )
                )

        else:

            story.append(
                Paragraph(
                    "No validation details available.",
                    styles["Normal"]
                )
            )

        story.append(
            Spacer(1, 20)
        )

        #
        # Final Status
        #

        story.append(
            Paragraph(
                "Final Result",
                styles["Heading2"]
            )
        )

        story.append(
            Paragraph(
                f"<b>{result.get('status', 'UNKNOWN')}</b>",
                styles["Normal"]
            )
        )

        story.append(
            Spacer(1, 20)
        )

        # story.append(
        #     Paragraph(
        #         "Generated By USB Validation & Security Testing Console",
        #         styles["Italic"]
        #     )
        #)

        doc.build(
            story
        )

        return filename