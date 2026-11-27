LIGHT_THEME = """
QMainWindow {
    background-color: #FFFFFF;
}

QWidget {
    background-color: #FFFFFF;
    color: #1F1F1F;
    font-size: 10pt;
}

QGroupBox {
    background-color: #F8F9FA;
    border: 1px solid #D0D7DE;
    border-radius: 12px;
    margin-top: 10px;
    font-size: 14pt;
    font-weight: bold;
    padding-top: 15px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 15px;
    padding: 3px 8px;
    color: black;
    font-weight: bold;
}

QPushButton {
    background-color: #000000;
    color: white;
    font-weight: bold;
    border-radius: 6px;
    border: none;
    min-height: 30px;
    min-width: 100px;
    font-size: 10pt;
}

QPushButton:hover {
    background-color: #1F1F1F;
}

QPushButton:pressed {
    background-color: #404040;
}

QComboBox,
QLineEdit {
    background-color: white;
    border: 1px solid #C5C5C5;
    border-radius: 6px;
    padding: 6px;
}

QTableWidget {
    background-color: white;
    alternate-background-color: #F6F8FA;
    gridline-color: #D0D7DE;
}

QHeaderView::section {
    background-color: black;
    color: white;
    font-weight: bold;
    padding: 6px;
}

QTextEdit {
    background-color: #FAFAFA;
    border: 1px solid #D0D7DE;
    font-family: Consolas;
}

QProgressBar {
    border: 1px solid #D0D7DE;
    border-radius: 6px;
    text-align: center;
}

QProgressBar::chunk {
    background-color: #0078D4;
    border-radius: 4px;
}

QFrame#StatCard {

    background: white;
    border: 1px solid #D0D7DE;
    border-radius: 12px;

    padding: 10px;
}

QLabel#CardTitle {

    font-size: 10pt;
    font-weight: bold;
    color: #666666;
}

QLabel#CardValue {

    font-size: 24pt;
    font-weight: bold;
    color: black;
}
"""