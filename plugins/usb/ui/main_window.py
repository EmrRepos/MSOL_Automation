from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QSplitter,
    QSizePolicy,
    QMessageBox,
)
from PySide6.QtCore import Qt
from ui.header import Header
from ui.top_toolbar import TopToolbar
from ui.dashboard_panel import DashboardPanel
from ui.com_port_panel import COMPortPanel
from ui.device_details_panel import DeviceDetailsPanel
from ui.test_panel import TestPanel
from ui.log_panel import LogPanel
from ui.settings_dialog import SettingsDialog
from ui.report_center import ReportCenter
from core.firmware_capture import CaptureError
from ui.firmware_capture_panel import FirmwareCapturePanel


class MainWindow(QMainWindow):

    SIDEBAR_WIDTH = 320

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
        self.details_panel = DeviceDetailsPanel()
        self.report_center = ReportCenter()
        self.firmware_panel = None

        self.test_panel.dashboard = self.dashboard
        self.test_panel.log_requested.connect(self.log_panel.log)
        self.test_panel.test_passed.connect(
            self.dashboard.increment_passed
        )

        # Left sidebar: actions, COM port selection, test execution.
        sidebar = QWidget()
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(10)
        sidebar_layout.addWidget(self.toolbar)
        sidebar_layout.addWidget(self.com_port_panel)
        sidebar_layout.addWidget(self.test_panel)
        sidebar_layout.addStretch()
        sidebar.setLayout(sidebar_layout)
        sidebar.setMinimumWidth(self.SIDEBAR_WIDTH)
        sidebar.setMaximumWidth(self.SIDEBAR_WIDTH + 80)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(sidebar)
        splitter.addWidget(self.log_panel)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([self.SIDEBAR_WIDTH, 1080])

        layout.addWidget(self.header)
        layout.addWidget(self.dashboard)
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

    def on_device_selected(self, device):
        """Keep the details panel and dashboard counters in step."""

        self.details_panel.update_device(device or {})

        ports = self.com_port_panel.devices

        self.dashboard.set_total_devices(len(ports))

        self.dashboard.set_authorized_devices(
            sum(
                1 for d in ports
                if d.get("authorized", "No") == "Yes"
            )
        )

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
