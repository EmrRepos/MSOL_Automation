from PySide6.QtWidgets import (
    QGroupBox,
    QVBoxLayout,
    QLabel,
    QComboBox,
    QProgressBar
    ,QCheckBox,
    QMessageBox,
    QPushButton,
)
from PySide6.QtCore import Signal, Qt
from core.test_runner import TestRunner
from plugins.serial_console import SerialConsole
from core.test_suite import SUITE_NAME, STANDARD, STRESS
from ui.suite_results_panel import SuiteResultsPanel
from ui.dashboard_panel import DashboardPanel


class TestPanel(QGroupBox):

    log_requested = Signal(str)
    progress_requested = Signal(int)
    test_passed = Signal()
    suite_row_changed = Signal(dict)
    suite_completed = Signal(dict)

    def __init__(self):
        
        super().__init__("Test Execution")

        self.runner = TestRunner()

        self.selected_device = {}
        self.serial_console = None
        self.firmware_capture_active = False
        self.suite_panel = None
        self.suite_active = False
        self.dashboard: DashboardPanel | None = None
        self.suite_row_changed.connect(self.update_suite_row)
        self.suite_completed.connect(self.finish_suite)


        layout = QVBoxLayout()
        layout.setSpacing(6)

        title = QLabel("Test Profile")
        title.setStyleSheet(
            "font-weight:bold;font-size:12pt;"
        )

        self.profile = QComboBox()

        self.profile.addItems([
            SUITE_NAME,
            "Enumeration Stress Test",
            "CDC Security Review",
            "Serial Console",
            "HID Attack Surface Review",
            "Storage Exposure Review",
            "Reconnect Validation",
            "Stability Validation",
        ])

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        self.progress_requested.connect(self.progress.setValue)

        self.hardware_checkbox = QCheckBox("Hardware mode")
        self.hardware_checkbox.setToolTip("Enable real device interactions (pyusb/pyserial required)")
        self.suite_description = QLabel(
            "<ul style='margin: 0px; padding-left: 18px;'>" +
            "".join(f"<li>{name}</li>" for name in STANDARD) + "</ul>"
        )
        self.suite_description.setTextFormat(Qt.TextFormat.RichText)
        self.suite_description.setWordWrap(True)
        self.suite_description.setStyleSheet("font-size: 10pt;")
        self.suite_description.setToolTip(
            "Live results and combined PDF/CSV reports. Absent interfaces are skipped; "
            "unavailable evidence is blocked. 30 seconds total, with start/end observations. "
            "Serial, stress and firmware workflows are separate."
        )
        self.profile.currentTextChanged.connect(
            lambda text: self.suite_description.setVisible(text == SUITE_NAME)
        )

        layout.addWidget(title)
        layout.addWidget(self.profile)
        layout.addWidget(self.hardware_checkbox)
        layout.addWidget(self.suite_description)
        self.view_results_btn = QPushButton("View Results")
        self.view_results_btn.setEnabled(False)
        self.view_results_btn.clicked.connect(self.show_suite_results)
        layout.addWidget(self.view_results_btn)
        layout.addWidget(QLabel("Progress"))
        layout.addWidget(self.progress)
        layout.addStretch()

        self.setLayout(layout)

    def start_test(self):

        self.log_message("[INFO] START BUTTON PRESSED")
        if self.suite_active:
            self.log_message("[WARN] Wait for the current suite and its reports to finish.")
            return
        if self.firmware_capture_active:
            self.log_message(
                "[WARN] USB capture is active. Local tests and serial connections "
                "are blocked to avoid interfering with ProLink."
            )
            return
        if not self.selected_device:
            self.log_message(
                "[FAIL] Please select a device first"
            )
            return

        # Log selected device info
        self.log_message(f"[INFO] Device Selected: {self.selected_device.get('name','Unknown')}")
        self.log_message(f"[INFO] VID : {self.selected_device.get('vid','N/A')}")
        self.log_message(f"[INFO] PID : {self.selected_device.get('pid','N/A')}")
        profile = self.profile.currentText()
        if self.runner.running:
            self.log_message("[WARN] Stop the running test before opening the console or starting another test.")
            return

        if profile == "Serial Console":
            if self.serial_console is None:
                self.serial_console = SerialConsole(self)
            self.serial_console.select_port(self.selected_device.get("port", ""))
            self.serial_console.show()
            self.serial_console.raise_()
            self.serial_console.activateWindow()
            self.log_message("[INFO] Manual serial console opened. Select settings and click Connect; hardware mode is not required.")
            return

        if self.serial_console is not None and self.serial_console.is_connected:
            self.log_message("[WARN] Disconnect the serial console before starting automated tests.")
            return

        if self.serial_console is not None:
            self.serial_console.close()

        suite = profile == SUITE_NAME
        if profile in STRESS:
            answer = QMessageBox.question(
                self, "Run stress profile?",
                "Repeated live descriptor reads may load the device. Run only in an "
                "authorized maintenance window. Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        if suite:
            if self.suite_panel is None:
                self.suite_panel = SuiteResultsPanel(self)
            self.suite_panel.reset(self.hardware_checkbox.isChecked())
            self.view_results_btn.setEnabled(True)
            self.show_suite_results()
            self.suite_active = True
            self.update_serial_lock()
            self.profile.setEnabled(False)
            self.hardware_checkbox.setEnabled(False)

        if self.dashboard is not None:
             self.dashboard.increment_test_runs()

        suite_options = {}
        if suite:
            suite_options = {
                "suite_update": self.suite_row_changed.emit,
                "suite_finished": self.suite_completed.emit,
            }
        self.runner.start(
            profile,
            self.selected_device,
            self.log_message,
            self.update_progress,
            use_hardware=self.hardware_checkbox.isChecked(),
            pass_callback=self.test_passed.emit,
            **suite_options,
        )

    def update_suite_row(self, row):
        if self.suite_panel is not None:
            self.suite_panel.update_result(row)

    def show_suite_results(self):
        if self.suite_panel is not None:
            if self.suite_panel.isMinimized():
                self.suite_panel.showNormal()
            else:
                self.suite_panel.show()
            self.suite_panel.raise_()
            self.suite_panel.activateWindow()

    def finish_suite(self, result):
        if self.suite_panel is not None:
            self.suite_panel.finish(result)
        self.profile.setEnabled(True)
        self.hardware_checkbox.setEnabled(True)
        self.suite_active = False
        self.update_serial_lock()

    def stop_test(self):

        self.log_message("[INFO] STOP BUTTON PRESSED")
        if self.firmware_capture_active:
            self.log_message(
                "[INFO] STOP TEST does not stop USB capture or ProLink. "
                "Use Stop Capture to stop recording only."
            )

        self.runner.stop()
        if self.runner.running:
            self.log_message(
                "[INFO] Safe stop requested. Waiting for current suite operation and report save; "
                "new tests/capture remain blocked."
            )
        if self.serial_console is not None:
            self.serial_console.disconnect_port()

    def set_firmware_capture_active(self, active):
        self.firmware_capture_active = active
        self.update_serial_lock()

    def update_serial_lock(self):
        if self.serial_console is not None:
            self.serial_console.connection_blocked_reason = (
                "USB capture is active; leave the COM port available for ProLink."
                if self.firmware_capture_active else
                "Device suite is active; wait for operations and reports to finish."
                if self.suite_active else None
            )
            self.serial_console.setEnabled(not (self.firmware_capture_active or self.suite_active))


    def update_progress(self, value):

        self.progress_requested.emit(value)


    def log_message(self, message):

        print(message)
        self.log_requested.emit(message)

    def set_selected_device(self, device):

        self.selected_device = device