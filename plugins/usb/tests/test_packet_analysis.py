import csv
import hashlib
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtPdf import QPdfDocument

from core.firmware_capture import FirmwareCapture, SNAPLEN
from core.packet_analysis import AnalysisCancelled, AnalysisError, analyze_capture
from core.report_generator import ReportGenerator
from ui.firmware_capture_panel import FirmwareCapturePanel
from ui.packet_analysis_dialog import AnalysisWorker, PacketAnalysisDialog


def header(endian="<", nano=False):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    return struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, SNAPLEN, 249)


def record(
    payload=b"password=TestSecret123", *, endian="<", endpoint=1, urb=1,
    info=0, status=0, bus=2, address=7, transfer=3, stage=None, truncated=0,
):
    extra = b"" if stage is None else bytes([stage])
    packet = struct.pack(
        "<HQIHBHHBBI", 27 + len(extra), urb, status, 9, info,
        bus, address, endpoint, transfer, len(payload),
    ) + extra + payload
    return struct.pack(endian + "IIII", 123, 456, len(packet), len(packet) + truncated) + packet


class AnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "capture.pcap"

    def analyze(self, records=b"", prefix=None, **kwargs):
        self.source.write_bytes((header() if prefix is None else prefix) + records)
        return analyze_capture(str(self.source), **kwargs)

    def test_hash_frame_offsets_and_redacted_credentials(self):
        data = record()
        result = self.analyze(data)
        finding = next(item for item in result.findings if item.rule == "CREDENTIAL_PATTERN")
        self.assertEqual(result.sha256, hashlib.sha256(header() + data).hexdigest())
        self.assertEqual(self.source.read_bytes(), header() + data)
        self.assertEqual((finding.bus, finding.address, finding.endpoint), (2, 7, 1))
        self.assertEqual(finding.verification, "NEEDS REVIEW")
        evidence = finding.evidence[0]
        self.assertEqual((evidence.frame, evidence.file_offset), (1, 24))
        self.assertEqual(evidence.timestamp, "1970-01-01T00:02:03.000456Z")
        self.assertEqual(evidence.packet_sha256, hashlib.sha256(data[16:]).hexdigest())
        self.assertEqual(evidence.payload_sha256, hashlib.sha256(b"password=TestSecret123").hexdigest())
        self.assertIn("[REDACTED]", evidence.note)
        self.assertNotIn("TestSecret123", repr(result))

    def test_endianness_and_timestamp_resolutions(self):
        for endian in ("<", ">"):
            for nano in (False, True):
                with self.subTest(endian=endian, nano=nano):
                    result = self.analyze(record(endian=endian), prefix=header(endian, nano))
                    self.assertEqual(result.payload_records_scanned, 1)
                    self.assertTrue(result.findings)
                    stamp = result.findings[0].evidence[0].timestamp
                    self.assertIn(".000000456Z" if nano else ".000456Z", stamp)

    def test_authorization_and_json_style_patterns(self):
        for payload in (
            b"Authorization: Bearer HiddenTestToken", b'{"api_key": "HiddenTestToken"}',
            b"password = HiddenTestToken", b"Authorization: Basic dXNlcjpwYXNz",
        ):
            with self.subTest(payload=payload):
                result = self.analyze(record(payload))
                self.assertIn("CREDENTIAL_PATTERN", [finding.rule for finding in result.findings])
                self.assertNotIn("HiddenTestToken", repr(result))

    def test_whole_hub_findings_do_not_merge_addresses(self):
        result = self.analyze(record(address=7) + record(address=8, urb=2) + record(bus=3, urb=3))
        self.assertEqual(result.devices, {(2, 7), (2, 8), (3, 7)})
        credentials = [item for item in result.findings if item.rule == "CREDENTIAL_PATTERN"]
        self.assertEqual(len(credentials), 3)

    def test_submission_completion_pairs_are_not_repeated_transfers(self):
        result = self.analyze(
            record() + record(info=1) + record(endpoint=0x81, info=0, urb=2)
            + record(endpoint=0x81, info=1, urb=2),
        )
        self.assertEqual(result.payload_records_scanned, 2)
        self.assertEqual(result.skipped_payload_records, 2)
        self.assertNotIn("REPEATED_PAYLOAD", [item.rule for item in result.findings])

    def test_repeat_evidence_references_first_frame_not_replay_claim(self):
        result = self.analyze(record() + record(urb=2))
        finding = next(item for item in result.findings if item.rule == "REPEATED_PAYLOAD")
        self.assertIn("Earlier matching frame: 1", finding.evidence[0].note)
        self.assertEqual(finding.evidence[0].frame, 2)
        self.assertEqual(finding.severity, "INFO")
        self.assertIn("not proof", finding.explanation)

    def test_same_urb_is_not_counted_as_a_distinct_repeat(self):
        result = self.analyze(record() + record())
        self.assertNotIn("REPEATED_PAYLOAD", [item.rule for item in result.findings])

    def test_control_setup_and_isochronous_are_not_scanned_but_data_stage_is(self):
        result = self.analyze(
            record(transfer=2, stage=0) + record(transfer=0)
            + record(transfer=2, stage=1, urb=2),
        )
        self.assertEqual(result.payload_records_scanned, 1)
        self.assertEqual(result.skipped_payload_records, 2)

    def test_transfer_errors_and_truncation_are_observations_not_security_failures(self):
        result = self.analyze(record(status=0xC0000001) + record(truncated=8))
        self.assertEqual(result.payload_records_scanned, 0)
        self.assertEqual(result.truncated_records, 1)
        self.assertEqual({item.rule for item in result.findings}, {
            "USB_TRANSFER_STATUS", "CAPTURE_TRUNCATED",
        })
        self.assertTrue(all(item.severity == "INFO" for item in result.findings))
        self.assertIn("c0000001", result.findings[0].evidence[0].note)

    def test_malformed_pseudoheaders_are_reported_with_frame_evidence(self):
        short = struct.pack("<IIII", 123, 0, 2, 2) + b"ab"
        mismatch = bytearray(record())
        struct.pack_into("<I", mismatch, 16 + 23, 0)
        result = self.analyze(short + bytes(mismatch) + record(transfer=2))
        self.assertEqual(result.malformed_records, 3)
        self.assertEqual(result.payload_records_scanned, 0)
        self.assertIn("MALFORMED_USBPCAP", [item.rule for item in result.findings])

    def test_incomplete_or_unsupported_files_fail_explicitly(self):
        for data in (
            b"", b"\x0a\x0d\x0d\x0a" + bytes(20), header()[:12],
            header() + b"abc", header() + record()[:-1],
            header()[:20] + struct.pack("<I", 1),
            header() + struct.pack("<IIII", 1, 0, SNAPLEN + 1, SNAPLEN + 1),
            header() + struct.pack("<IIII", 1, 1_000_000, 0, 0),
        ):
            with self.subTest(data=data[:30]):
                self.source.write_bytes(data)
                with self.assertRaises(AnalysisError):
                    analyze_capture(str(self.source))

    def test_wireshark_large_declared_snaplen_accepts_normal_packets(self):
        for endian in ("<", ">"):
            for snaplen in (134217728, 0xFFFFFFFF):
                with self.subTest(endian=endian, snaplen=snaplen):
                    prefix = bytearray(header(endian))
                    struct.pack_into(endian + "I", prefix, 16, snaplen)
                    result = self.analyze(record(endian=endian), prefix=bytes(prefix))
                    self.assertEqual(result.packets, 1)
                    self.assertEqual(result.payload_records_scanned, 1)

    def test_large_snaplen_does_not_allow_oversized_packet_allocation(self):
        prefix = bytearray(header())
        struct.pack_into("<I", prefix, 16, 134217728)
        oversized_record = struct.pack("<IIII", 123, 0, SNAPLEN + 1, SNAPLEN + 1)
        with self.assertRaisesRegex(AnalysisError, "per-packet safety limit"):
            self.analyze(oversized_record, prefix=bytes(prefix))

    def test_header_errors_identify_the_specific_rejected_field(self):
        for offset, fmt, value, message in (
            (4, "H", 3, "version 3.4"),
            (16, "I", 0, "snapshot length 0"),
            (20, "I", 1, "link type 1"),
        ):
            with self.subTest(message=message):
                prefix = bytearray(header())
                struct.pack_into("<" + fmt, prefix, offset, value)
                with self.assertRaisesRegex(AnalysisError, message):
                    self.analyze(prefix=bytes(prefix))

    def test_empty_capture_and_no_matches_never_claim_security_pass(self):
        empty = self.analyze()
        self.assertEqual(empty.packets, 0)
        self.assertTrue(any("no packets" in item for item in empty.limitations))
        result = self.analyze(record(bytes(range(16))))
        self.assertEqual(result.findings, [])
        self.assertTrue(any("not a security pass" in item for item in result.limitations))

    def test_evidence_samples_and_repeat_tracking_are_bounded_and_disclosed(self):
        result = self.analyze(b"".join(record(urb=index) for index in range(20)))
        finding = next(item for item in result.findings if item.rule == "CREDENTIAL_PATTERN")
        self.assertEqual(finding.occurrences, 20)
        self.assertEqual(len(finding.evidence), 5)
        result = self.analyze(b"".join(
            record(struct.pack("<I", index), urb=index) for index in range(4097)
        ))
        self.assertTrue(any("evicted 1 entries" in item for item in result.limitations))

    def test_group_limit_is_disclosed(self):
        result = self.analyze(b"".join(
            record(b"abcdefghijklmnopqrstuvwxyz", address=index) for index in range(501)
        ))
        self.assertEqual(len(result.findings), 500)
        self.assertTrue(any("Finding-group limit" in item for item in result.limitations))

    def test_cancellation_and_file_mutation_do_not_return_completed_results(self):
        self.source.write_bytes(header() + record())
        with self.assertRaises(AnalysisCancelled):
            analyze_capture(str(self.source), cancelled=lambda: True)
        self.source.write_bytes(header() + record() * 250)

        def append_packet(_value):
            with self.source.open("ab") as output:
                output.write(record())

        with self.assertRaisesRegex(AnalysisError, "changed during analysis"):
            analyze_capture(str(self.source), progress=append_packet)

    def test_midstream_cancellation_stops_before_completion(self):
        self.source.write_bytes(header() + record() * 300)
        stop = False

        def progress(value):
            nonlocal stop
            stop = value > 0

        with self.assertRaises(AnalysisCancelled):
            analyze_capture(str(self.source), cancelled=lambda: stop, progress=progress)

    def test_device_inventory_limit_is_disclosed(self):
        result = self.analyze(b"".join(
            record(b"", address=index) for index in range(4097)
        ))
        self.assertEqual(len(result.devices), 4096)
        self.assertTrue(any("inventory limit" in item for item in result.limitations))

    def test_missing_source_is_an_explicit_error(self):
        with self.assertRaises(AnalysisError):
            analyze_capture(str(self.root / "absent.pcap"))

    def test_pdf_csv_evidence_exports_omit_raw_credentials(self):
        result = self.analyze(record())
        paths, errors = ReportGenerator().export_packet_analysis(
            result, self.root / "USB_Packet_Analysis_Report.pdf", Mock(),
        )
        self.assertEqual(errors, [])
        self.assertEqual(set(paths), {"pdf", "csv"})
        with Path(paths["csv"]).open(newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source))
        self.assertEqual(rows[0]["rule"], "CREDENTIAL_PATTERN")
        self.assertIn("frame: 1", rows[0]["evidence"])
        self.assertEqual(rows[0]["capture_sha256"], result.sha256)
        doc = QPdfDocument()
        self.assertEqual(doc.load(paths["pdf"]), QPdfDocument.Error.None_)
        text = "\n".join(doc.getAllText(page).text() for page in range(doc.pageCount()))
        doc.close()
        self.assertIn(result.sha256, text.replace("\n", ""))
        self.assertIn("NEEDS REVIEW", text)
        self.assertNotIn("TestSecret123", text)
        self.assertNotIn("TestSecret123", Path(paths["csv"]).read_text(encoding="utf-8"))
        self.assertFalse(list(self.root.glob("*.json")))

    def test_report_errors_are_explicit_and_pdf_failure_is_in_csv(self):
        result = self.analyze(record())
        logger = Mock()
        with patch("core.report_generator.SimpleDocTemplate", side_effect=OSError("PDF denied")):
            paths, errors = ReportGenerator().export_packet_analysis(
                result, self.root / "failed.pdf", logger,
            )
        self.assertEqual(set(paths), {"csv"})
        self.assertEqual(len(errors), 1)
        self.assertIn("PDF denied", Path(paths["csv"]).read_text(encoding="utf-8"))
        self.assertTrue(logger.called)

    def test_no_match_reports_keep_coverage_information(self):
        result = self.analyze(record(b"\x00"))
        paths, errors = ReportGenerator().export_packet_analysis(result, self.root / "none.pdf", Mock())
        self.assertFalse(errors)
        with Path(paths["csv"]).open(newline="", encoding="utf-8") as source:
            row = next(csv.DictReader(source))
        self.assertEqual(row["verification"], "NOT ASSESSED")
        self.assertIn("not a security pass", row["title"])
        self.assertEqual(row["payload_records_scanned"], "1")

    def test_csv_report_failure_is_not_reported_as_success(self):
        result = self.analyze(record())
        with patch.object(Path, "open", side_effect=PermissionError("CSV denied")):
            paths, errors = ReportGenerator().export_packet_analysis(
                result, self.root / "failed.pdf", Mock(),
            )
        self.assertEqual(set(paths), {"pdf"})
        self.assertEqual(len(errors), 1)
        self.assertIn("CSV denied", errors[0])


class AnalysisUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "capture.pcap"
        self.source.write_bytes(header() + record())

    def test_worker_runs_offline_and_produces_reports(self):
        worker = AnalysisWorker(str(self.source), self.root / "analysis.pdf")
        completed, failed = [], []
        worker.result_ready.connect(lambda *args: completed.append(args))
        worker.failed.connect(failed.append)
        worker.start()
        self.assertTrue(worker.wait(5000))
        QApplication.processEvents()
        self.assertEqual(failed, [])
        self.assertEqual(len(completed), 1)
        result, paths, errors = completed[0]
        self.assertEqual(result.packets, 1)
        self.assertFalse(errors)
        self.assertEqual(set(paths), {"pdf", "csv"})

    def test_worker_failure_does_not_create_reports(self):
        self.source.write_bytes(b"not a capture")
        worker = AnalysisWorker(str(self.source), self.root / "analysis.pdf")
        completed, failed = [], []
        worker.result_ready.connect(lambda *args: completed.append(args))
        worker.failed.connect(failed.append)
        worker.start()
        self.assertTrue(worker.wait(5000))
        QApplication.processEvents()
        self.assertEqual(completed, [])
        self.assertEqual(len(failed), 1)
        self.assertFalse((self.root / "analysis.pdf").exists())
        self.assertFalse((self.root / "analysis.csv").exists())

    def test_dialog_analysis_finish_and_evidence_selection(self):
        dialog = PacketAnalysisDialog(capture_path=str(self.source))
        self.addCleanup(dialog.close)
        with patch(
            "ui.packet_analysis_dialog.QFileDialog.getSaveFileName",
            return_value=(str(self.root / "analysis.pdf"), ""),
        ):
            dialog.start_analysis()
        for _ in range(500):
            QApplication.processEvents()
            if dialog.worker is None:
                break
            QTest.qWait(10)
        self.assertIsNone(dialog.worker)
        self.assertIsNotNone(dialog.analysis_result)
        self.assertTrue(dialog.btn_analyze.isEnabled())
        self.assertGreater(dialog.table.rowCount(), 0)
        dialog.table.selectRow(0)
        self.assertIn("frame.number == 1", dialog.evidence.toPlainText())
        self.assertIn("Capture SHA256", dialog.evidence.toPlainText())
        self.assertNotIn("TestSecret123", dialog.evidence.toPlainText())

    def test_active_capture_is_blocked_and_original_cannot_be_overwritten(self):
        dialog = PacketAnalysisDialog(capture_busy=lambda: True)
        with patch("ui.packet_analysis_dialog.QMessageBox.warning") as warning:
            dialog.start_analysis()
        warning.assert_called_once()
        self.assertIsNone(dialog.worker)
        dialog = PacketAnalysisDialog(capture_path=str(self.root / "capture.pdf"))
        Path(dialog.source_box.text()).write_bytes(header() + record())
        with (
            patch("ui.packet_analysis_dialog.QFileDialog.getSaveFileName",
                  return_value=(dialog.source_box.text(), "")),
            patch("ui.packet_analysis_dialog.QMessageBox.warning") as warning,
        ):
            dialog.start_analysis()
        warning.assert_called_once()
        self.assertIsNone(dialog.worker)

    def test_overwrite_requires_confirmation_for_either_report(self):
        dialog = PacketAnalysisDialog(capture_path=str(self.source))
        report = self.root / "existing.pdf"
        report.with_suffix(".csv").write_text("keep", encoding="utf-8")
        with (
            patch("ui.packet_analysis_dialog.QFileDialog.getSaveFileName",
                  return_value=(str(report), "")),
            patch("ui.packet_analysis_dialog.QMessageBox.question",
                  return_value=QMessageBox.StandardButton.No),
        ):
            dialog.start_analysis()
        self.assertIsNone(dialog.worker)
        self.assertEqual(report.with_suffix(".csv").read_text(encoding="utf-8"), "keep")

    def test_capture_panel_analysis_button_and_busy_close_guard(self):
        capture = FirmwareCapture(executable="USBPcapCMD.exe")
        capture.output_path = self.source
        panel = FirmwareCapturePanel(capture=capture)
        self.addCleanup(panel.timer.stop)
        panel.open_analysis()
        dialog = panel.analysis_dialog
        assert dialog is not None
        self.assertEqual(dialog.source_box.text(), str(self.source))
        worker = Mock()
        dialog.worker = worker
        panel.update_controls()
        self.assertFalse(panel.btn_start.isEnabled())
        with patch.object(panel, "report_error") as error:
            panel.start_capture()
        error.assert_called_once()
        dialog.show()
        self.assertFalse(dialog.close())
        worker.requestInterruption.assert_called()
        dialog.worker = None
        dialog.close()
        capture.active = True
        panel.update_controls()
        self.assertFalse(panel.btn_analyze.isEnabled())
        with patch.object(panel, "report_error") as error:
            panel.open_analysis()
        error.assert_called_once()
        capture.active = False
        panel.close()


if __name__ == "__main__":
    unittest.main()
