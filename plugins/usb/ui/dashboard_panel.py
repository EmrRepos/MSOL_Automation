from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget


class StatCard(QFrame):
    def __init__(self, title):
        super().__init__()
        self.setObjectName("StatCard")
        self.setMinimumWidth(120)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)
        self.title = QLabel(title)
        self.title.setObjectName("CardTitle")
        self.value = QLabel("0")
        self.value.setObjectName("CardValue")
        layout.addWidget(self.title)
        layout.addWidget(self.value)


class DashboardPanel(QWidget):
    def __init__(self):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self.devices_card = StatCard("COM ports")
        self.tests_card = StatCard("Runs started")
        self.pass_card = StatCard("Passed runs")
        self.failed_card = StatCard("Failed runs")
        self.other_card = StatCard("Other outcomes")
        self.other_card.setToolTip("Blocked, skipped, cancelled, error or unknown runs")
        for card in (
            self.devices_card, self.tests_card, self.pass_card,
            self.failed_card, self.other_card,
        ):
            layout.addWidget(card)

    def set_total_devices(self, count):
        self.devices_card.value.setText(str(count))

    @staticmethod
    def _increment(card):
        card.value.setText(str(int(card.value.text()) + 1))

    def increment_test_runs(self):
        self._increment(self.tests_card)

    def record_run(self, status):
        if status == "PASS":
            card = self.pass_card
        elif status == "FAIL":
            card = self.failed_card
        else:
            card = self.other_card
        self._increment(card)
