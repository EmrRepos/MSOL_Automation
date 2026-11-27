LIGHT_THEME = """
QMainWindow, QDialog {
    background-color: #F4F7FA;
}

QWidget {
    color: #243247;
    font-family: "Segoe UI";
    font-size: 10pt;
}

QLabel {
    background: transparent;
}

QGroupBox {
    background-color: #FFFFFF;
    border: 1px solid #D7E0E9;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 14px;
    font-size: 11pt;
    font-weight: bold;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 2px 6px;
    color: #243247;
}

QPushButton {
    background-color: #E8EEF5;
    color: #243247;
    font-weight: bold;
    border: 1px solid #CBD6E2;
    border-radius: 6px;
    min-height: 32px;
    padding: 2px 10px;
}

QPushButton:hover { background-color: #D8E5F2; }
QPushButton:pressed { background-color: #C4D5E6; }
QPushButton:focus { border: 2px solid #1769AA; }
QPushButton:disabled {
    background-color: #F0F2F4;
    color: #788493;
    border: 1px solid #DDE3E8;
}
QPushButton#StartButton { background-color: #18764A; color: white; border: 1px solid #18764A; }
QPushButton#StartButton:hover { background-color: #125C39; }
QPushButton#StartButton:disabled { background-color: #E3E9E6; color: #788493; border: 1px solid #DDE3E8; }
QPushButton#StopButton { background-color: #A83333; color: white; border: 1px solid #A83333; }
QPushButton#StopButton:hover { background-color: #852727; }

QComboBox, QLineEdit {
    background-color: white;
    border: 1px solid #BAC7D4;
    border-radius: 5px;
    padding: 5px;
}
QComboBox:focus, QLineEdit:focus { border: 2px solid #1769AA; }

QTableWidget {
    background-color: white;
    alternate-background-color: #F4F7FA;
    gridline-color: #D7E0E9;
}
QHeaderView::section {
    background-color: #E8EEF5;
    color: #243247;
    font-weight: bold;
    padding: 6px;
    border: 1px solid #D7E0E9;
}
QTextEdit {
    background-color: #FFFFFF;
    border: 1px solid #D7E0E9;
}
QProgressBar {
    border: 1px solid #BAC7D4;
    border-radius: 5px;
    text-align: center;
}
QProgressBar::chunk {
    background-color: #1769AA;
    border-radius: 4px;
}
QFrame#StatCard {
    background-color: white;
    border: 1px solid #D7E0E9;
    border-radius: 8px;
}
QLabel#CardTitle { color: #52657A; font-size: 9pt; }
QLabel#CardValue { color: #243247; font-size: 16pt; font-weight: bold; }
"""
