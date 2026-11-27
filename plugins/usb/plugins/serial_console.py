import serial
import serial.tools.list_ports

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QTextEdit,
    QLabel,
    QComboBox,
    QLineEdit,
    QMessageBox,
    QFileDialog,
    QCheckBox,
    QSpinBox,
)


class SerialConsole(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent, Qt.Window)
        self.setWindowTitle("Serial Console - Manual Device Communication")
        self.resize(850, 500)
        self.ser = None
        self.connection_blocked_reason: str | None = None
        self.response_pending = False
        self.response_timer = QTimer(self)
        self.response_timer.setSingleShot(True)
        self.response_timer.setTimerType(Qt.PreciseTimer)
        self.response_timer.timeout.connect(self.finish_response_check)
        self.rx_timer = QTimer(self)
        self.rx_timer.setInterval(25)
        self.rx_timer.timeout.connect(self.read_loop)
        self.setup_ui()
        self.refresh_ports()
        self.update_controls()

    @property
    def is_connected(self):
        return self.ser is not None and self.ser.is_open

    def setup_ui(self):
        layout = QVBoxLayout(self)
        port_layout = QHBoxLayout()
        self.port_combo = QComboBox()
        self.baud_combo = QComboBox()
        self.baud_combo.setEditable(True)
        self.baud_combo.addItems([
            "9600", "19200", "38400", "57600", "115200", "230400"
        ])
        self.baud_combo.setCurrentText("115200")
        self.btn_refresh = QPushButton("Refresh")
        self.btn_connect = QPushButton("Connect")
        self.btn_disconnect = QPushButton("Disconnect")
        self.btn_refresh.clicked.connect(self.refresh_ports)
        self.btn_connect.clicked.connect(self.connect_port)
        self.btn_disconnect.clicked.connect(self.disconnect_port)
        for widget in (
            QLabel("Port"), self.port_combo, QLabel("Baud"), self.baud_combo,
            self.btn_refresh, self.btn_connect, self.btn_disconnect,
        ):
            port_layout.addWidget(widget)
        layout.addLayout(port_layout)
        framing_layout = QHBoxLayout()
        self.data_bits_combo = QComboBox()
        for bits in (5, 6, 7, 8):
            self.data_bits_combo.addItem(str(bits), bits)
        self.data_bits_combo.setCurrentText("8")
        self.parity_combo = QComboBox()
        for label, parity in (
            ("None", serial.PARITY_NONE), ("Even", serial.PARITY_EVEN),
            ("Odd", serial.PARITY_ODD), ("Mark", serial.PARITY_MARK),
            ("Space", serial.PARITY_SPACE),
        ):
            self.parity_combo.addItem(label, parity)
        self.stop_bits_combo = QComboBox()
        for label, bits in (
            ("1", serial.STOPBITS_ONE), ("1.5", serial.STOPBITS_ONE_POINT_FIVE),
            ("2", serial.STOPBITS_TWO),
        ):
            self.stop_bits_combo.addItem(label, bits)
        self.start_bits_combo = QComboBox()
        self.start_bits_combo.addItem("1 (fixed)")
        self.start_bits_combo.setEnabled(False)
        self.start_bits_combo.setToolTip(
            "Standard asynchronous UART uses one start bit; pyserial does not configure it."
        )
        for label, widget in (
            ("Data bits", self.data_bits_combo), ("Parity", self.parity_combo),
            ("Stop bits", self.stop_bits_combo), ("Start bits", self.start_bits_combo),
        ):
            framing_layout.addWidget(QLabel(label))
            framing_layout.addWidget(widget)
        layout.addLayout(framing_layout)
        layout.addWidget(QLabel(
            "Real device I/O: select the documented framing before connecting; no flow control. "
            "Available settings depend on your serial adapter/driver."
        ))

        self.tx_box = QLineEdit()
        self.tx_box.setPlaceholderText("Text command or HEX bytes (example: 41 54 0D)")
        layout.addWidget(self.tx_box)
        button_layout = QHBoxLayout()
        self.line_ending = QComboBox()
        for label, ending in (
            ("None", b""), ("CR", b"\r"), ("LF", b"\n"), ("CRLF", b"\r\n")
        ):
            self.line_ending.addItem(label, ending)
        self.btn_send_ascii = QPushButton("Send ASCII")
        self.btn_send_hex = QPushButton("Send HEX")
        self.btn_save_log = QPushButton("Save Log")
        self.btn_clear = QPushButton("Clear")
        self.btn_send_ascii.clicked.connect(self.send_ascii)
        self.btn_send_hex.clicked.connect(self.send_hex)
        self.btn_save_log.clicked.connect(self.save_log)
        self.btn_clear.clicked.connect(self.clear_console)
        for widget in (
            QLabel("ASCII ending"), self.line_ending, self.btn_send_ascii,
            self.btn_send_hex, self.btn_save_log, self.btn_clear,
        ):
            button_layout.addWidget(widget)
        layout.addLayout(button_layout)
        response_layout = QHBoxLayout()
        self.check_response = QCheckBox("Check reply after send")
        self.check_response.setChecked(True)
        self.response_timeout = QSpinBox()
        self.response_timeout.setRange(100, 60000)
        self.response_timeout.setValue(2000)
        self.response_timeout.setSuffix(" ms")
        self.expected_response = QLineEdit()
        self.expected_response.setPlaceholderText("Optional documented ACK / response in HEX")
        self.expected_response.setMaxLength(12288)
        for widget in (
            self.check_response, QLabel("Wait"), self.response_timeout,
            QLabel("Expected HEX"), self.expected_response,
        ):
            response_layout.addWidget(widget)
        layout.addLayout(response_layout)
        self.response_status = QLabel("No command checked. TX alone does not prove device acceptance.")
        self.response_status.setWordWrap(True)
        layout.addWidget(self.response_status)
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet(
            "QTextEdit { background-color: #000000; color: #ffffff; "
            "font-family: Consolas, monospace; }"
        )
        layout.addWidget(self.console)

    def log(self, message):
        self.console.moveCursor(QTextCursor.End)
        self.console.insertPlainText(message + "\n")
        self.console.ensureCursorVisible()

    def update_controls(self):
        connected = self.is_connected
        self.btn_connect.setEnabled(not connected and bool(self.port_combo.currentText()))
        self.btn_disconnect.setEnabled(connected)
        self.btn_refresh.setEnabled(not connected)
        self.port_combo.setEnabled(not connected)
        self.baud_combo.setEnabled(not connected)
        for widget in (self.data_bits_combo, self.parity_combo, self.stop_bits_combo):
            widget.setEnabled(not connected)
        self.btn_send_ascii.setEnabled(connected and not self.response_pending)
        self.btn_send_hex.setEnabled(connected and not self.response_pending)
        for widget in (
            self.check_response, self.response_timeout, self.expected_response,
        ):
            widget.setEnabled(not self.response_pending)

    def set_response_status(self, message):
        self.response_status.setText(message)
        self.log(f"[CHECK] {message}")

    def record_response(self, data):
        self.response_bytes += len(data)
        if self.response_bytes > len(self.sent_payload):
            self.echo_only = False
        elif data != self.sent_payload[
            self.response_bytes - len(data):self.response_bytes
        ]:
            self.echo_only = False
        if self.expected_bytes:
            combined = self.response_tail + data
            self.expected_matched |= self.expected_bytes in combined
            self.response_tail = combined[-(len(self.expected_bytes) - 1):] if len(self.expected_bytes) > 1 else b""

    def finish_response_check(self):
        if not self.response_pending:
            return
        self.read_loop()
        if not self.response_pending:
            return
        self.response_pending = False
        self.response_timer.stop()
        if not self.response_bytes:
            result = "NO REPLY: acceptance unconfirmed (not proof of rejection)."
        elif self.echo_only and self.response_bytes == len(self.sent_payload):
            result = "ECHO ONLY: sent bytes returned; command acceptance unconfirmed."
        elif self.expected_bytes and self.expected_matched:
            result = (
                "EXPECTED RESPONSE MATCHED: configured HEX sequence observed. "
                "Acceptance requires a documented ACK for this command; unrelated traffic can match."
            )
        elif self.expected_bytes:
            result = "REPLY OBSERVED, EXPECTED RESPONSE NOT MATCHED: acceptance unconfirmed."
        else:
            result = "REPLY OBSERVED: acceptance unconfirmed without a documented ACK."
        self.set_response_status(f"{result} RX: {self.response_bytes} bytes.")
        self.update_controls()

    def refresh_ports(self):
        selected = self.port_combo.currentText()
        try:
            ports = list(serial.tools.list_ports.comports())
        except (serial.SerialException, OSError) as error:
            self.report_error("Port discovery failed", str(error))
            return
        self.port_combo.clear()
        for port in ports:
            self.port_combo.addItem(port.device)
        index = self.port_combo.findText(selected)
        if index >= 0:
            self.port_combo.setCurrentIndex(index)
        self.update_controls()

    def select_port(self, port):
        if self.is_connected:
            return
        self.refresh_ports()
        index = self.port_combo.findText(port)
        if index >= 0:
            self.port_combo.setCurrentIndex(index)
        else:
            self.port_combo.setCurrentIndex(-1)
            self.log(f"[WARN] Selected port {port} is no longer available; refresh ports.")
        self.update_controls()

    def connect_port(self):
        if self.connection_blocked_reason:
            self.report_error("Connection blocked", self.connection_blocked_reason)
            return
        if self.is_connected:
            return
        port = self.port_combo.currentText()
        if not port:
            self.report_error("Connection error", "Select an available COM port.")
            return
        try:
            baud = int(self.baud_combo.currentText())
            if baud <= 0:
                raise ValueError("Baud rate must be a positive integer.")
            data_bits = self.data_bits_combo.currentData()
            parity = self.parity_combo.currentData()
            stop_bits = self.stop_bits_combo.currentData()
            if (
                data_bits not in (5, 6, 7, 8)
                or parity not in serial.PARITY_NAMES
                or stop_bits not in (1, 1.5, 2)
            ):
                raise ValueError("Select valid data bits, parity and stop bits.")
            self.ser = serial.Serial(
                port=port, baudrate=baud, bytesize=data_bits,
                parity=parity, stopbits=stop_bits,
                timeout=0, write_timeout=1,
                xonxoff=False, rtscts=False, dsrdtr=False,
            )
        except (ValueError, serial.SerialException, OSError) as error:
            self.report_error("Connection error", str(error))
            return
        self.rx_timer.start()
        self.update_controls()
        self.log(
            f"[INFO] Connected to {port} at {baud} baud "
            f"({data_bits}-{parity}-{stop_bits}; 1 start bit)"
        )
        self.set_response_status("No command checked on this connection. Device acceptance unconfirmed.")

    def disconnect_port(self):
        self.rx_timer.stop()
        self.response_timer.stop()
        if self.response_pending:
            self.response_pending = False
            self.set_response_status("CHECK CANCELLED: disconnected; acceptance unconfirmed.")
        connection = self.ser
        self.ser = None
        if connection is not None:
            try:
                connection.close()
            except (serial.SerialException, OSError) as error:
                self.report_error("Disconnect error", str(error))
            self.log("[INFO] Disconnected")
        self.update_controls()

    def read_loop(self):
        if not self.is_connected:
            self.disconnect_port()
            return
        try:
            waiting = self.ser.in_waiting
            if waiting:
                data = self.ser.read(min(waiting, 4096))
                if data:
                    self.log(f"RX HEX -> {data.hex(' ')} | TEXT -> {data!r}")
                    if self.response_pending:
                        self.record_response(data)
        except (serial.SerialException, OSError) as error:
            self.disconnect_port()
            self.report_error("Receive error", str(error))

    def send_payload(self, payload):
        if not self.is_connected:
            self.report_error("Send error", "Connect to a COM port first.")
            return
        if not payload:
            self.report_error("Send error", "Enter data to send.")
            return
        if self.response_pending:
            self.report_error("Send error", "Wait for the current response check to finish.")
            return
        expected = b""
        if self.check_response.isChecked():
            try:
                expected = bytes.fromhex(self.expected_response.text())
            except ValueError as error:
                self.report_error("Expected HEX error", str(error))
                return
            self.read_loop()
            if not self.is_connected:
                return
        try:
            if self.check_response.isChecked() and self.ser.in_waiting:
                self.report_error(
                    "Send error",
                    "Incoming data is still queued. Wait for it to drain or disable reply checking "
                    "for streaming devices. No command sent.",
                )
                return
            written = self.ser.write(payload)
            if written != len(payload):
                raise serial.SerialTimeoutException(
                    f"Only {written} of {len(payload)} bytes written. "
                    "Check the device before retrying."
                )
        except (serial.SerialException, OSError) as error:
            self.disconnect_port()
            self.report_error("Send error", str(error))
            return
        self.log(f"TX HEX -> {payload.hex(' ')} | TEXT -> {payload!r}")
        if self.check_response.isChecked():
            self.sent_payload = payload
            self.expected_bytes = expected
            self.expected_matched = False
            self.response_tail = b""
            self.response_bytes = 0
            self.echo_only = True
            self.response_pending = True
            self.response_timer.start(self.response_timeout.value())
            self.set_response_status(
                f"WAITING up to {self.response_timeout.value()} ms: "
                f"driver accepted {written} bytes; device acceptance unconfirmed."
            )
        else:
            self.set_response_status(
                f"NOT CHECKED: driver accepted {written} bytes; device acceptance unconfirmed."
            )
        self.update_controls()

    def send_ascii(self):
        try:
            payload = self.tx_box.text().encode("ascii")
        except UnicodeEncodeError:
            self.report_error("ASCII error", "Use ASCII text or send raw bytes with Send HEX.")
            return
        self.send_payload(payload + self.line_ending.currentData())

    def send_hex(self):
        try:
            payload = bytes.fromhex(self.tx_box.text())
        except ValueError as error:
            self.report_error("HEX error", str(error))
            return
        self.send_payload(payload)

    def report_error(self, title, message):
        self.log(f"[ERROR] {title}: {message}")
        QMessageBox.warning(self, title, message)

    def save_log(self):
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Log", "", "Log Files (*.txt)"
        )
        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as output:
                    output.write(self.console.toPlainText())
            except OSError as error:
                self.report_error("Save log error", str(error))

    def clear_console(self):
        self.console.clear()

    def closeEvent(self, event):
        self.disconnect_port()
        super().closeEvent(event)
