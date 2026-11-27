from PySide6.QtWidgets import (
    QGroupBox,
    QVBoxLayout,
    QHBoxLayout,
    QTextEdit,
    QPushButton
)

class LogPanel(QGroupBox):

    def __init__(self):

        super().__init__("Live Event Log")

        layout = QVBoxLayout()

        self.logs = QTextEdit()
        self.logs.setMinimumHeight(150)
        self.logs.setReadOnly(True)
        self.logs.setStyleSheet("""
            background-color: #000000;
            color: #FFFFFF;
            border: 1px solid #D7E0E9;
        """)

        layout.addWidget(self.logs)

        button_layout = QHBoxLayout()

        self.clear_btn = QPushButton("CLEAR LOGS")
        self.clear_btn.setToolTip("Clear all terminal logs")

        button_layout.addStretch()
        button_layout.addWidget(self.clear_btn)

        layout.addLayout(button_layout)

        self.setLayout(layout)

        self.clear_btn.clicked.connect(self.clear_logs)

    def log(self, message):
        self.logs.append(message)

    def clear_logs(self):
        self.logs.clear()