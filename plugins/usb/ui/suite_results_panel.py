from PySide6.QtWidgets import (
    QDialog, QLabel, QTableWidget, QTableWidgetItem, QVBoxLayout, QHeaderView,
    QAbstractItemView,
)
from core.test_suite import SUITE_NAME
from PySide6.QtCore import Qt


class SuiteResultsPanel(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            self.windowFlags() | Qt.WindowMinMaxButtonsHint | Qt.WindowCloseButtonHint
        )
        self.setWindowTitle(f"{SUITE_NAME} - Live Results")
        self.resize(1050, 600)
        layout = QVBoxLayout(self)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Profile", "Status", "Seconds", "Evidence", "Details"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setWordWrap(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)
        note = QLabel(
            "Closing only hides results; use View Results to reopen during this session. "
            "30-second total revalidation checks at the start and end. STOP TEST requests safe cancellation; "
            "an in-flight operation must return before stopping. No firmware workflow is included."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        self.rows = {}

    def reset(self, hardware):
        self.rows.clear()
        self.table.setRowCount(0)
        self.summary.setText(
            f"{SUITE_NAME} (7 checks): LIVE HARDWARE + OS METADATA; revalidating for 30 seconds." if hardware
            else f"{SUITE_NAME} (7 checks): METADATA ONLY - no live serial/USB I/O; hardware-dependent checks blocked."
        )

    def update_result(self, result):
        name = result["profile"]
        if name not in self.rows:
            self.rows[name] = self.table.rowCount()
            self.table.insertRow(self.table.rowCount())
        row = self.rows[name]
        values = (
            name, result["status"], str(result["duration"]), result["evidence"],
            "\n".join(map(str, result["details"])),
        )
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setToolTip(value)
            self.table.setItem(row, column, item)
        self.table.resizeRowToContents(row)

    def finish(self, result):
        counts = {}
        for row in result.get("results", []):
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        reports = "\n".join(
            f"{kind.upper()}: {path}" for kind, path in result.get("report_paths", {}).items()
        )
        self.summary.setText(
            f"Suite {result.get('run_id', '')}: {result['status']} | " +
            ", ".join(f"{status}: {count}" for status, count in counts.items()) + "\n"
            + (
                f"Samples: {result['validation']['rounds']}; "
                f"elapsed: {result['validation']['elapsed_seconds']} seconds; "
                f"window completed: {result['validation']['completed']}\n"
                if "validation" in result else ""
            ) +
            f"{reports}\n" + "\n".join(result.get("report_errors", []))
        )
