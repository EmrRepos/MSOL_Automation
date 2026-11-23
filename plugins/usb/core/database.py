import sqlite3


class TestHistoryDB:

    def __init__(self):

        self.create_tables()

    def create_tables(self):

        conn = sqlite3.connect(
            "usb_tests.db"
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
            "usb_tests.db"
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