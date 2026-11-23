from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QPushButton,
    QSizePolicy,
)


class TopToolbar(QWidget):

    def __init__(self):

        super().__init__()

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        self.start_btn = QPushButton("START TEST")
        self.stop_btn = QPushButton("STOP TEST")
        self.report_btn = QPushButton("EXPORT REPORT")
        self.firmware_btn = QPushButton("FIRMWARE USB CAPTURE")
        self.settings_btn = QPushButton("SETTINGS")

        for button in (
            self.start_btn,
            self.stop_btn,
            self.report_btn,
            self.firmware_btn,
            self.settings_btn
        ):
            button.setMinimumHeight(30)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            layout.addWidget(button)

        self.setLayout(layout)