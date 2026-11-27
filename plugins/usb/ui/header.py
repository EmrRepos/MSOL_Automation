from PySide6.QtWidgets import QLabel
from PySide6.QtCore import Qt


class Header(QLabel):

    def __init__(self):

        super().__init__(
            "USB VALIDATION & SECURITY TESTING CONSOLE"
        )

        self.setAlignment(Qt.AlignCenter)

        self.setStyleSheet("""
            font-size: 16pt;
            font-weight: bold;
            color: #243247;
            padding: 4px;
        """)