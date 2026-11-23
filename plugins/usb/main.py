import os
import sys

sys.dont_write_bytecode = True

from pathlib import Path
from core.theme import LIGHT_THEME
from PySide6.QtWidgets import QApplication
from ui.main_window import MainWindow


def main():
    if getattr(sys, "frozen", False):
        data_dir = Path(os.environ["LOCALAPPDATA"]) / "USB_Pentest_Framework"
        data_dir.mkdir(parents=True, exist_ok=True)
        os.chdir(data_dir)

    app = QApplication(sys.argv)
    app.setStyleSheet(LIGHT_THEME)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()