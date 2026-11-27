import os
import sqlite3
import sys
from pathlib import Path


def history_database_path():
    if getattr(sys, "frozen", False):
        return Path(os.environ["LOCALAPPDATA"]) / "USB_Pentest_Framework" / "usb_tests.db"
    return Path(__file__).resolve().parent.parent / "usb_tests.db"


class TestHistoryDB:

    def __init__(self):

        self.path = history_database_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.create_tables()

    def create_tables(self):

        conn = sqlite3.connect(
            self.path
        )

        cur = conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS test_history (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,

            device_name TEXT,

            profile TEXT,

            result TEXT
        )
        """)

        conn.commit()

        conn.close()

    def save_result(
        self,
        timestamp,
        device_name,
        profile,
        result
    ):

        conn = sqlite3.connect(
            self.path
        )

        cur = conn.cursor()

        cur.execute("""

        INSERT INTO test_history (

            timestamp,
            device_name,
            profile,
            result

        )

        VALUES (?, ?, ?, ?)

        """,
        (
            timestamp,
            device_name,
            profile,
            result
        ))

        conn.commit()

        conn.close()