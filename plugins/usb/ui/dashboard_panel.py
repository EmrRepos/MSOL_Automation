from PySide6.QtWidgets import (
    QWidget,
    QHBoxLayout,
    QFrame,
    QLabel,
    QVBoxLayout
)


class StatCard(QFrame):

    def __init__(self, title, value="0", color="#0078D4"):

        super().__init__()

        self.setObjectName("StatCard")
        self.setFixedHeight(80)
        self.setMinimumWidth(180)

        self.setStyleSheet(f"""
            QFrame {{
                background-color: {color};
                border-radius: 12px;
                color: white;
            }}
        """)

        layout = QVBoxLayout()

        self.title = QLabel(title)
        self.title.setStyleSheet("""
            font-size:18px;
            font-weight:bold;
            color:white;
        """)

        self.value = QLabel(value)
        self.value.setStyleSheet("""
            font-size:10px;
            font-weight:bold;
            color:white;
        """)

        layout.addWidget(self.title)
        layout.addWidget(self.value)

        self.setLayout(layout)


class DashboardPanel(QWidget):

    def __init__(self):

        super().__init__()

        layout = QHBoxLayout()

        self.devices_card = StatCard(
            "TOTAL DEVICES",
            "0",
            "#0078D4"
        )

        self.failed_card = StatCard(
            "FAILED",
            "0",
            "#FF0000"
        )

        self.tests_card = StatCard(
            "TEST RUNS",
            "0",
            "#FF8C00"
        )

        self.pass_card = StatCard(
            "PASSED",
            "0",
            "#006400"
        )

        layout.addWidget(self.devices_card)
        layout.addWidget(self.failed_card)
        layout.addWidget(self.tests_card)
        layout.addWidget(self.pass_card)

        self.setLayout(layout)

    def set_total_devices(self, count):

        self.devices_card.value.setText(
            str(count)
        )

    def set_authorized_devices(self, count):

        self.failed_card.value.setText(
            str(count)
        )

    def increment_test_runs(self):

        current = int(
            self.tests_card.value.text()
        )

        self.tests_card.value.setText(
            str(current + 1)
        )

    def increment_passed(self):

        current = int(
            self.pass_card.value.text()
        )

        self.pass_card.value.setText(
            str(current + 1)
        )