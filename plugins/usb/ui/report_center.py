# ui/report_center.py

import os

from PySide6.QtWidgets import (
    QGroupBox,
    QVBoxLayout,
    QHBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QHeaderView,
    QAbstractItemView
)


class ReportCenter(QGroupBox):

    def __init__(self):

        super().__init__("REPORT CENTER")

        self.base_dir = os.path.dirname(
            os.path.dirname(
                os.path.abspath(__file__)
            )
        )

        self.reports_dir = os.path.abspath("reports")

        layout = QVBoxLayout()

        self.table = QTableWidget()

        self.table.setColumnCount(3)

        self.table.setHorizontalHeaderLabels([
            "FILE NAME",
            "TYPE",
            "SIZE (KB)"
        ])

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        self.table.setSelectionBehavior(
            QAbstractItemView.SelectRows
        )

        self.table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        self.table.setAlternatingRowColors(True)

        layout.addWidget(
            self.table
        )

        button_layout = QHBoxLayout()

        self.refresh_btn = QPushButton(
            "REFRESH"
        )

        self.open_btn = QPushButton(
            "OPEN REPORT"
        )

        button_layout.addWidget(
            self.refresh_btn
        )

        button_layout.addWidget(
            self.open_btn
        )

        layout.addLayout(
            button_layout
        )

        self.setLayout(layout)

        self.refresh_btn.clicked.connect(
            self.load_reports
        )

        self.open_btn.clicked.connect(
            self.open_report
        )

        self.load_reports()

    def load_reports(self):


        if not os.path.exists(
            self.reports_dir
        ):
            os.makedirs(
                self.reports_dir,
                exist_ok=True
            )

        reports = []

        for file_name in os.listdir(
            self.reports_dir
        ):

            if (
                file_name.lower().endswith(".pdf")
                or
                file_name.lower().endswith(".csv")
            ):

                reports.append(
                    file_name
                )



        self.table.clearContents()

        self.table.setRowCount(
            len(reports)
        )

        for row, file_name in enumerate(
            reports
        ):

            full_path = os.path.join(
                self.reports_dir,
                file_name
            )

            size_kb = round(
                os.path.getsize(
                    full_path
                ) / 1024,
                2
            )

            report_type = (
                file_name.split(".")[-1]
                .upper()
            )

            self.table.setItem(
                row,
                0,
                QTableWidgetItem(
                    file_name
                )
            )

            self.table.setItem(
                row,
                1,
                QTableWidgetItem(
                    report_type
                )
            )

            self.table.setItem(
                row,
                2,
                QTableWidgetItem(
                    str(size_kb)
                )
            )

    def open_report(self):

        row = self.table.currentRow()

        if row < 0:
            return

        file_name = self.table.item(
            row,
            0
        ).text()

        if not file_name.lower().endswith(
            (".pdf", ".csv")
        ):
            return

        full_path = os.path.join(
            self.reports_dir,
            file_name
        )

        if not os.path.isfile(
            full_path
        ):
            return

        os.startfile(
            full_path
        )