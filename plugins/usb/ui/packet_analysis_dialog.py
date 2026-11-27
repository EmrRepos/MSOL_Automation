from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QDialog, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout,
)

from core.packet_analysis import AnalysisCancelled, AnalysisError, AnalysisResult, analyze_capture
from core.report_generator import ReportGenerator, readable_text
from core.report_paths import REPORT_DIR
from dataclasses import asdict


class AnalysisWorker(QThread):
    progress = Signal(int)
    result_ready = Signal(object, object, object)
    failed = Signal(str)
    cancelled = Signal()
    log_requested = Signal(str)

    def __init__(self, source: str, report_path: Path, parent=None):
        super().__init__(parent)
        self.source = source
        self.report_path = report_path

    def run(self):
        try:
            result = analyze_capture(
                self.source, self.isInterruptionRequested, self.progress.emit,
            )
            if self.isInterruptionRequested():
                raise AnalysisCancelled()
            paths, errors = ReportGenerator().export_packet_analysis(
                result, self.report_path, self.log_requested.emit,
            )
            self.result_ready.emit(result, paths, errors)
        except AnalysisCancelled:
            self.cancelled.emit()
        except (AnalysisError, OSError) as error:
            self.failed.emit(str(error))
        except Exception as error:
            self.failed.emit(f"Unexpected analysis failure ({type(error).__name__}): {error}")


class PacketAnalysisDialog(QDialog):
    log_requested = Signal(str)

    def __init__(self, parent=None, capture_path="", capture_busy=lambda: False):
        super().__init__(parent)
        self.setWindowTitle("USB Packet Security Analysis - Offline")
        self.setWindowFlags(
            self.windowFlags() | Qt.WindowType.WindowMinMaxButtonsHint
        )
        self.resize(1050, 780)
        self.capture_busy = capture_busy
        self.worker = None
        self.analysis_result: AnalysisResult | None = None
        self.report_paths = {}
        layout = QVBoxLayout(self)
        intro = QLabel(
            "Local, passive analysis of completed USBPcap .pcap files (not PCAPNG). "
            "Whole-hub scope: every observation is labelled by USB bus/address, not target identity. "
            "Findings are evidence for review, not proof of exploitability or a security pass. "
            "No capture data is uploaded. PDF/CSV reports omit raw payloads and credential values."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)
        source_row = QHBoxLayout()
        self.source_box = QLineEdit(str(capture_path or ""))
        self.btn_browse = QPushButton("Browse Capture")
        self.btn_browse.clicked.connect(self.browse_capture)
        source_row.addWidget(self.source_box, 1)
        source_row.addWidget(self.btn_browse)
        layout.addLayout(source_row)
        self.status = QLabel("Choose a completed capture, then Analyze and Save Reports.")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.progress = QProgressBar()
        layout.addWidget(self.progress)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "Priority", "Verification", "Observation", "Bus", "Address", "Endpoint", "Count",
        ])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self.show_evidence)
        layout.addWidget(self.table, 1)
        self.evidence = QPlainTextEdit()
        self.evidence.setReadOnly(True)
        layout.addWidget(self.evidence, 1)
        buttons = QHBoxLayout()
        self.btn_analyze = QPushButton("Analyze and Save PDF/CSV")
        self.btn_cancel = QPushButton("Cancel Analysis")
        self.btn_cancel.setEnabled(False)
        self.btn_close = QPushButton("Close")
        self.btn_analyze.clicked.connect(self.start_analysis)
        self.btn_cancel.clicked.connect(self.cancel_analysis)
        self.btn_close.clicked.connect(self.close)
        for button in (self.btn_analyze, self.btn_cancel, self.btn_close):
            buttons.addWidget(button)
        layout.addLayout(buttons)

    def browse_capture(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Completed USBPcap capture", self.source_box.text(), "USBPcap (*.pcap)",
        )
        if path:
            self.source_box.setText(path)

    def start_analysis(self):
        if self.worker is not None:
            return
        if self.capture_busy():
            self.analysis_error("Stop recording and wait for the capture file to close before analysis.")
            return
        source = Path(self.source_box.text().strip()).resolve()
        if not source.is_file():
            self.analysis_error("Choose an existing completed capture file.")
            return
        try:
            REPORT_DIR.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            self.analysis_error(f"Cannot create USB report directory: {error}")
            return
        output, _ = QFileDialog.getSaveFileName(
            self, "Save packet analysis PDF and CSV",
            str(REPORT_DIR.resolve() / f"USB_Packet_Analysis_Report_{datetime.now():%Y%m%d_%H%M%S}.pdf"),
            "PDF report (*.pdf)", options=QFileDialog.Option.DontConfirmOverwrite,
        )
        if not output:
            return
        report_path = Path(output).resolve().with_suffix(".pdf")
        outputs = (report_path, report_path.with_suffix(".csv"))
        if source in outputs:
            self.analysis_error("Report destinations must not overwrite the source capture.")
            return
        if any(path.exists() for path in outputs):
            answer = QMessageBox.question(
                self, "Replace analysis reports?",
                "A PDF or CSV with this name exists. Replace the report pair?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.analysis_result = None
        self.report_paths = {}
        self.table.setRowCount(0)
        self.evidence.clear()
        self.progress.setValue(0)
        self.status.setText("Analyzing locally; no commands are sent to any device.")
        self.log_requested.emit(f"[INFO] Packet analysis started: {source}")
        self.worker = AnalysisWorker(str(source), report_path, self)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.result_ready.connect(self.analysis_complete)
        self.worker.failed.connect(self.analysis_error)
        self.worker.cancelled.connect(self.analysis_cancelled)
        self.worker.log_requested.connect(self.log_requested.emit)
        self.worker.finished.connect(self.analysis_stopped)
        for widget in (self.source_box, self.btn_browse, self.btn_analyze):
            widget.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.worker.start()

    def cancel_analysis(self):
        if self.worker is not None:
            self.worker.requestInterruption()
            self.status.setText("Cancel requested; waiting for parsing or report writing to finish.")
            self.btn_cancel.setEnabled(False)

    def analysis_complete(self, result: AnalysisResult, paths, errors):
        self.analysis_result = result
        self.report_paths = paths
        summary = (
            f"Parsing completed: {result.packets} packets; "
            f"{result.payload_records_scanned} payload records scanned; "
            f"{result.skipped_payload_records} payload records skipped; "
            f"{result.truncated_records} truncated; {result.malformed_records} malformed. "
            f"{len(result.findings)} observation groups. NOT a security pass."
        )
        self.status.setText(summary + (" Report export errors; see details." if errors else " PDF/CSV saved."))
        self.log_requested.emit(f"[INFO] {summary}")
        self.table.setRowCount(len(result.findings))
        for row, finding in enumerate(result.findings):
            values = (
                finding.severity, finding.verification, finding.title, finding.bus, finding.address,
                f"0x{finding.endpoint:02x}" if finding.endpoint is not None else "Unknown",
                finding.occurrences,
            )
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(str(value) if value is not None else "Unknown"))
        self.table.resizeColumnsToContents()
        self.evidence.setPlainText(readable_text({
            "Capture": result.source, "Capture SHA256": result.sha256,
            "Coverage and limitations": result.limitations,
            "Reports": paths, "Export errors": errors,
            "Next step": "Select an observation row for packet evidence and development follow-up.",
        }))
        if errors:
            QMessageBox.warning(self, "Analysis report export", "\n".join(errors))

    def show_evidence(self):
        row = self.table.currentRow()
        if self.analysis_result is None or not 0 <= row < len(self.analysis_result.findings):
            return
        finding = self.analysis_result.findings[row]
        self.evidence.setPlainText(readable_text({
            "Capture": self.analysis_result.source, "Capture SHA256": self.analysis_result.sha256,
            "Finding": asdict(finding),
            "Wireshark filter": " || ".join(
                f"frame.number == {item.frame}" for item in finding.evidence
            ),
            "Evidence guide": "Frame numbers are 1-based. File offsets point to PCAP record headers. "
            "Packet SHA256 includes USBPcap pseudoheader bytes. Up to five examples per group.",
            "Coverage and limitations": self.analysis_result.limitations, "Reports": self.report_paths,
        }))

    def analysis_error(self, message):
        self.status.setText(f"ERROR: {message}")
        self.log_requested.emit(f"[ERROR] Packet analysis: {message}")
        QMessageBox.warning(self, "Packet analysis", message)

    def analysis_cancelled(self):
        self.status.setText("Analysis cancelled. No completed result or new reports were produced.")
        self.log_requested.emit("[INFO] Packet analysis cancelled.")

    def analysis_stopped(self):
        worker = self.worker
        self.worker = None
        if worker is not None:
            worker.deleteLater()
        for widget in (self.source_box, self.btn_browse, self.btn_analyze):
            widget.setEnabled(True)
        self.btn_cancel.setEnabled(False)

    def closeEvent(self, event):
        if self.worker is not None:
            self.cancel_analysis()
            event.ignore()
            return
        super().closeEvent(event)

    def reject(self):
        self.close()
