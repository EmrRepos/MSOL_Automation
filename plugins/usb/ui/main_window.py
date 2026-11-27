from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QSplitter,
    QScrollArea,
    QFrame,
    QSizePolicy,
    QMessageBox,
    QLabel,
    QTabWidget,
)
from PySide6.QtCore import Qt
from ui.header import Header
from ui.top_toolbar import TopToolbar
from ui.dashboard_panel import DashboardPanel
from ui.com_port_panel import COMPortPanel
from ui.test_panel import TestPanel
from ui.suite_results_panel import SuiteResultsPanel
from ui.log_panel import LogPanel
from ui.settings_dialog import SettingsDialog
from ui.report_center import ReportCenter
from core.firmware_capture import CaptureError
from ui.firmware_capture_panel import FirmwareCapturePanel


class MainWindow(QMainWindow):

    SIDEBAR_WIDTH = 400

    def __init__(self):

        super().__init__()

        self.setWindowTitle(
            "USB Validation & Security Testing Console"
        )

        self.resize(1400, 900)

        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout()

        self.header = Header()
        self.toolbar = TopToolbar()
        self.dashboard = DashboardPanel()
        self.com_port_panel = COMPortPanel()
        self.test_panel = TestPanel()
        self.log_panel = LogPanel()
        self.results_panel = SuiteResultsPanel(self, embedded=True)
        self.test_panel.suite_panel = self.results_panel
        self.report_center = ReportCenter()
        self.firmware_panel = None

        self.test_panel.dashboard = self.dashboard
        self.test_panel.log_requested.connect(self.log_panel.log)
        self.test_panel.activity_changed.connect(self.update_actions)
        self.test_panel.suite_results_requested.connect(self.show_suite_results)
        self.run_status = QLabel("Ready - select a device and test profile.")
        self.run_status.setWordWrap(True)
        self.test_panel.phase_updated.connect(self.run_status.setText)

        # Left sidebar: COM port selection and test execution.
        sidebar = QWidget()
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(10)
        sidebar_layout.addWidget(self.com_port_panel)
        sidebar_layout.addWidget(self.test_panel)
        sidebar_layout.addStretch()
        sidebar.setLayout(sidebar_layout)
        self.sidebar_scroll = QScrollArea()
        self.sidebar_scroll.setWidgetResizable(True)
        self.sidebar_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.sidebar_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.sidebar_scroll.setMinimumWidth(self.SIDEBAR_WIDTH)
        self.sidebar_scroll.setMaximumWidth(self.SIDEBAR_WIDTH + 80)
        self.sidebar_scroll.setWidget(sidebar)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.sidebar_scroll)
        self.output_tabs = QTabWidget()
        self.output_tabs.addTab(self.log_panel, "Live Event Log")
        self.output_tabs.addTab(self.results_panel, "Standard USB Validation")
        splitter.addWidget(self.output_tabs)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([self.SIDEBAR_WIDTH, 1080])

        layout.addWidget(self.header)
        layout.addWidget(self.dashboard)
        layout.addWidget(self.toolbar)
        layout.addWidget(self.run_status)
        layout.addWidget(splitter, 1)

        self.header.setSizePolicy(
            QSizePolicy.Preferred, QSizePolicy.Fixed
        )
        self.dashboard.setSizePolicy(
            QSizePolicy.Preferred, QSizePolicy.Fixed
        )

        central.setLayout(layout)

        self.toolbar.settings_btn.clicked.connect(
            self.open_settings
        )

        self.toolbar.start_btn.clicked.connect(self.test_panel.start_test)
        self.toolbar.stop_btn.clicked.connect(self.test_panel.stop_test)
        self.toolbar.report_btn.clicked.connect(self.export_report)
        self.toolbar.report_btn.clicked.connect(self.show_reports)
        self.toolbar.firmware_btn.clicked.connect(self.open_firmware_capture)

        self.com_port_panel.log_requested.connect(self.log_panel.log)
        self.com_port_panel.device_selected.connect(
            self.test_panel.set_selected_device
        )
        self.com_port_panel.device_selected.connect(
            self.on_device_selected
        )

        self.com_port_panel.start_monitoring()
        self.update_actions()

    def on_device_selected(self, device):
        self.dashboard.set_total_devices(len(self.com_port_panel.devices))
        self.update_actions()

    def update_actions(self):
        self.toolbar.start_btn.setEnabled(
            bool(self.test_panel.selected_device)
            and not self.test_panel.runner.running
            and not self.test_panel.firmware_capture_active
        )

    def show_suite_results(self):
        self.output_tabs.setCurrentWidget(self.results_panel)

    def open_settings(self):

        dialog = SettingsDialog()

        dialog.exec()

    def export_report(self):

        self.log_panel.log(
            "[INFO] Reports are generated automatically after each test"
        )

    def show_reports(self):

        self.report_center.load_reports()
        self.report_center.show()

    def prepare_firmware_capture(self):
        if self.test_panel.runner.running:
            raise CaptureError("Stop the running test before capturing a firmware update.")
        console = self.test_panel.serial_console
        if console is not None and console.is_connected:
            raise CaptureError(
                "Disconnect the Serial Console first so ProLink can use the COM port."
            )

    def open_firmware_capture(self):
        if self.firmware_panel is None:
            self.firmware_panel = FirmwareCapturePanel(
                self, start_guard=self.prepare_firmware_capture
            )
            self.firmware_panel.log_requested.connect(self.log_panel.log)
            self.firmware_panel.active_changed.connect(
                self.test_panel.set_firmware_capture_active
            )

        self.firmware_panel.show()
        self.firmware_panel.raise_()
        self.firmware_panel.activateWindow()
        if not self.firmware_panel.capture.active and not self.firmware_panel.capture.discovering:
            self.firmware_panel.refresh_hubs()

    def closeEvent(self, event):

        if self.test_panel.runner.running:
            self.test_panel.runner.stop()
            QMessageBox.information(
                self, "Test still running",
                "Stop requested. Wait for the current operation and suite reports "
                "to finish, then close the application.",
            )
            event.ignore()
            return
        if self.firmware_panel is not None and not self.firmware_panel.close():
            event.ignore()
            return
        if self.test_panel.serial_console is not None:
            self.test_panel.serial_console.close()
        self.com_port_panel.stop_monitoring()

        super().closeEvent(event)
