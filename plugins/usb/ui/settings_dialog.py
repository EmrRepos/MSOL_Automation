from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QTabWidget,
    QWidget,
    QLabel,
    QFormLayout,
    QCheckBox,
    QSpinBox,
    QPushButton
)


class SettingsDialog(QDialog):

    def __init__(self):

        super().__init__()

        self.setWindowTitle("Settings")
        self.resize(700, 500)

        layout = QVBoxLayout()

        tabs = QTabWidget()

        # General Tab
        general_tab = QWidget()
        general_layout = QFormLayout()

        self.auto_scan = QCheckBox()
        self.auto_scan.setChecked(True)

        self.refresh_interval = QSpinBox()
        self.refresh_interval.setValue(5)

        general_layout.addRow(
            "Auto Scan",
            self.auto_scan
        )

        general_layout.addRow(
            "Refresh Interval",
            self.refresh_interval
        )

        general_tab.setLayout(general_layout)

        tabs.addTab(
            general_tab,
            "General"
        )

        layout.addWidget(tabs)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)

        layout.addWidget(close_btn)

        self.setLayout(layout)