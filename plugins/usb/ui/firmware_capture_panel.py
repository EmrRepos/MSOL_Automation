from datetime import datetime

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFileDialog, QHBoxLayout, QLabel,
    QLineEdit, QMessageBox, QPushButton, QPlainTextEdit, QVBoxLayout,
)

from core.firmware_capture import CaptureError, FirmwareCapture
from ui.packet_analysis_dialog import PacketAnalysisDialog


class FirmwareCapturePanel(QDialog):
    log_requested = Signal(str)
    active_changed = Signal(bool)

    def __init__(self, parent=None, capture=None, start_guard=None):
        super().__init__(parent)
        self.setWindowTitle("Firmware Update - Passive USB Traffic Capture")
        self.resize(850, 720)
        self.capture = capture or FirmwareCapture(self)
        self.start_guard = start_guard
        self.analysis_dialog = None
        self.capture.log_requested.connect(self.log)
        self.capture.active_changed.connect(self._active_changed)
        self.capture.hubs_ready.connect(self._hubs_ready)
        self.capture.topology_ready.connect(self._topology_ready)
        self.capture.discovery_finished.connect(self.update_controls)

        layout = QVBoxLayout(self)
        intro = QLabel(
            "Record USB traffic while YOU update firmware in ProLink. This tool "
            "does not launch ProLink, open the COM port, send commands, or flash firmware.\n"
            "1. Select the target's USB root hub and a NEW capture file.\n"
            "2. Start Capture. Wait for CAPTURE READY and check USB activity.\n"
            "3. Perform the vendor-approved update manually in ProLink.\n"
            "4. After ProLink finishes and reconnects, Stop Capture. Verify the version in ProLink."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        hub_row = QHBoxLayout()
        self.hub_box = QComboBox()
        self.btn_refresh = QPushButton("Refresh USB Hubs")
        self.btn_refresh.clicked.connect(self.refresh_hubs)
        hub_row.addWidget(QLabel("USB root hub"))
        hub_row.addWidget(self.hub_box, 1)
        hub_row.addWidget(self.btn_refresh)
        layout.addLayout(hub_row)
        self.hub_box.currentTextChanged.connect(self.inspect_hub)
        self.topology = QPlainTextEdit()
        self.topology.setReadOnly(True)
        self.topology.setMaximumHeight(110)
        self.topology.setPlaceholderText("Refresh hubs, then inspect the attached device tree.")
        layout.addWidget(self.topology)

        file_row = QHBoxLayout()
        self.output_box = QLineEdit()
        self.output_box.setPlaceholderText("Choose a new .pcap file (existing files are never overwritten)")
        self.btn_browse = QPushButton("Save As")
        self.btn_browse.clicked.connect(self.choose_output)
        file_row.addWidget(self.output_box, 1)
        file_row.addWidget(self.btn_browse)
        layout.addLayout(file_row)

        self.consent = QCheckBox(
            "I am authorized to capture ALL devices on this hub, including sensitive payloads."
        )
        self.consent.toggled.connect(self.update_controls)
        layout.addWidget(self.consent)
        warning = QLabel(
            "Whole-hub capture follows address changes on the SAME hub during reboot/bootloader "
            "entry. It can include keyboards, storage and unrelated devices: isolate the target "
            "where possible and protect the file. Moving to another hub is not followed.\n"
            "STOP TEST does not stop capture. Stop Capture/closing this panel stops only recording, "
            "never ProLink or flashing. Do not disconnect power/cables during an update."
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)
        self.filter_label = QLabel(
            "Wireshark: locate VID:PID descriptors, then filter usb.bus_id == N && "
            "usb.device_address == M. Re-check addresses/VID/PID after reboot. "
            "Do not filter only usb.idVendor: most data packets have no VID/PID."
        )
        self.filter_label.setWordWrap(True)
        layout.addWidget(self.filter_label)

        self.preview = QLabel("No USB records observed.")
        self.preview.setWordWrap(True)
        layout.addWidget(self.preview)
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(1000)
        self.console.setStyleSheet("QPlainTextEdit { background: black; color: white; }")
        layout.addWidget(self.console, 1)
        buttons = QHBoxLayout()
        self.btn_start = QPushButton("Start Capture")
        self.btn_stop = QPushButton("Stop Capture")
        self.btn_analyze = QPushButton("Analyze Capture")
        self.btn_close = QPushButton("Close")
        self.btn_start.clicked.connect(self.start_capture)
        self.btn_stop.clicked.connect(self.capture.stop)
        self.btn_analyze.clicked.connect(self.open_analysis)
        self.btn_close.clicked.connect(self.close)
        for button in (self.btn_start, self.btn_stop, self.btn_analyze, self.btn_close):
            buttons.addWidget(button)
        layout.addLayout(buttons)
        self.timer = QTimer(self)
        self.timer.setInterval(250)
        self.timer.timeout.connect(self.update_controls)
        self.timer.start()
        self.update_controls()

    def log(self, message):
        self.console.appendPlainText(message)
        self.log_requested.emit(message)

    def report_error(self, error):
        self.log(f"[ERROR] {error}")
        QMessageBox.warning(self, "USB Capture", str(error))

    def refresh_hubs(self):
        self.hub_box.clear()
        self.topology.clear()
        try:
            self.capture.discover()
        except CaptureError as error:
            self.report_error(error)
        self.update_controls()

    def _hubs_ready(self, hubs):
        self.hub_box.blockSignals(True)
        self.hub_box.clear()
        self.hub_box.addItems(hubs)
        self.hub_box.setCurrentIndex(-1)
        self.hub_box.blockSignals(False)
        self.log("[INFO] Select the target's hub explicitly; a COM number does not identify a hub.")

    def inspect_hub(self, hub):
        if not hub:
            return
        self.topology.clear()
        try:
            self.capture.inspect_hub(hub)
        except CaptureError as error:
            self.report_error(error)
        self.update_controls()

    def _topology_ready(self, text):
        self.topology.setPlainText(text)

    def choose_output(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "New USB capture",
            f"firmware_usb_{datetime.now():%Y%m%d_%H%M%S}.pcap",
            "USB capture (*.pcap)",
        )
        if path:
            self.output_box.setText(path)

    def start_capture(self):
        if self.analysis_dialog is not None and self.analysis_dialog.worker is not None:
            self.report_error("Wait for offline analysis to finish before starting a new capture.")
            return
        if not self.consent.isChecked():
            self.report_error("Confirm authorization for whole-hub capture first.")
            return
        try:
            if self.start_guard:
                self.start_guard()
            self.capture.start(self.hub_box.currentText(), self.output_box.text().strip())
        except CaptureError as error:
            self.report_error(error)
        self.update_controls()

    def _active_changed(self, active):
        self.active_changed.emit(active)
        self.update_controls()

    def open_analysis(self):
        if self.capture.active:
            self.report_error("Stop Capture before analyzing the file.")
            return
        if self.analysis_dialog is None:
            self.analysis_dialog = PacketAnalysisDialog(
                self, capture_busy=lambda: self.capture.active,
            )
            self.analysis_dialog.log_requested.connect(self.log)
        if self.analysis_dialog.worker is None:
            self.analysis_dialog.source_box.setText(
                str(self.capture.output_path or self.output_box.text().strip())
            )
        self.analysis_dialog.show()
        self.analysis_dialog.raise_()
        self.analysis_dialog.activateWindow()

    def update_controls(self):
        busy = self.capture.active
        discovering = self.capture.discovering
        analyzing = self.analysis_dialog is not None and self.analysis_dialog.worker is not None
        for widget in (self.hub_box, self.btn_refresh, self.output_box, self.btn_browse, self.consent):
            widget.setEnabled(not busy and not discovering)
        self.btn_start.setEnabled(
            not busy and not discovering and not analyzing and self.consent.isChecked()
            and bool(self.hub_box.currentText()) and bool(self.capture.executable)
        )
        self.btn_stop.setEnabled(busy and not self.capture.stopping)
        self.btn_analyze.setEnabled(not busy and not discovering)
        state = "STOPPING" if self.capture.stopping and busy else (
            "CAPTURE READY" if self.capture.ready else "STARTING" if busy else "IDLE"
        )
        self.status_label.setText(
            f"{state} | Backend: {self.capture.executable or 'USBPcap not found'}"
        )
        recorder = self.capture.recorder
        if recorder:
            self.preview.setText(
                f"{recorder.packets} USB records | {recorder.bytes_written} saved bytes | "
                f"{recorder.truncated_packets} snaplen-truncated records\n{recorder.preview}"
            )

    def closeEvent(self, event):
        if self.analysis_dialog is not None and not self.analysis_dialog.close():
            event.ignore()
            return
        if self.capture.active:
            answer = QMessageBox.question(
                self, "Stop recording?",
                "Stop USB recording and close this panel?\n"
                "ProLink and any firmware update will CONTINUE. This does not cancel flashing.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.capture.stop()
            if not self.capture.process.waitForFinished(3000) and self.capture.active:
                self.report_error("USBPcap has not stopped yet. Wait before closing.")
                event.ignore()
                return
        self.capture.shutdown_discovery()
        super().closeEvent(event)

    def reject(self):
        if self.capture.active or (
            self.analysis_dialog is not None and self.analysis_dialog.worker is not None
        ):
            self.close()
        else:
            self.capture.shutdown_discovery()
            super().reject()
