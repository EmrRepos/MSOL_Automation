# ui/com_port_panel.py

import sys
import threading

from PySide6.QtCore import QObject, Signal, Slot, QTimer
from PySide6.QtWidgets import (
    QGroupBox,
    QVBoxLayout,
    QLabel,
    QComboBox,
    QPushButton
)

from core.com_port_manager import COMPortManager


class _PortScanner(QObject):
    completed = Signal(object, str)

    def __init__(self, manager):
        super().__init__()
        self.manager = manager

    def run(self):
        result = None
        error = ""
        com_initialized = False
        try:
            if sys.platform == "win32":
                import pythoncom
                pythoncom.CoInitialize()
                com_initialized = True
            result = self.manager.scan()
        except Exception as ex:
            error = f"{type(ex).__name__}: {ex}"
        finally:
            if com_initialized:
                pythoncom.CoUninitialize()
        self.completed.emit(result, error)


class COMPortPanel(QGroupBox):
    """
    COM-port selector.

    Polls for serial ports, announces newly connected ones on the live event
    log, and emits the selected port's device record for the test runner.
    """

    device_selected = Signal(dict)
    log_requested = Signal(str)

    POLL_INTERVAL_MS = 2000

    def __init__(self):

        super().__init__("COM PORT")

        self.manager = COMPortManager()
        self.devices = []
        self._scan_in_progress = False
        self._accept_results = True
        self._announce_all = False
        self._scanner = _PortScanner(self.manager)
        self._scanner.completed.connect(self._scan_finished)

        layout = QVBoxLayout()

        label = QLabel("Select COM Port")
        label.setStyleSheet("font-weight:bold;")

        self.port_combo = QComboBox()
        self.port_combo.setToolTip(
            "Serial ports currently connected to this system"
        )

        self.refresh_btn = QPushButton("REFRESH PORTS")
        self.refresh_btn.setToolTip("Re-scan for connected COM ports")

        self.status_lbl = QLabel("No COM ports detected")
        self.status_lbl.setWordWrap(True)
        self.status_lbl.setStyleSheet("color:#555;")

        layout.addWidget(label)
        layout.addWidget(self.port_combo)
        layout.addWidget(self.refresh_btn)
        layout.addWidget(self.status_lbl)

        self.setLayout(layout)

        self.refresh_btn.clicked.connect(self.refresh_ports)
        self.port_combo.currentIndexChanged.connect(
            self.on_port_selected
        )

        self.timer = QTimer(self)
        self.timer.setInterval(self.POLL_INTERVAL_MS)
        self.timer.timeout.connect(self.poll_ports)

    def start_monitoring(self):
        """Begin automatic detection of newly connected COM ports."""

        if self.timer.isActive():
            return

        self._accept_results = True
        self.refresh_ports(announce_all=True)
        self.timer.start()

    def stop_monitoring(self):
        self.timer.stop()
        self._accept_results = False

    def poll_ports(self):
        """Timer tick: refresh quietly, announcing only new arrivals."""
        self.refresh_ports(announce_all=False)

    def refresh_ports(self, announce_all=False):

        if self._scan_in_progress or not self._accept_results:
            return

        self._scan_in_progress = True
        self._announce_all = announce_all
        self.refresh_btn.setEnabled(False)
        self.status_lbl.setText("Scanning COM ports...")
        # A daemon scan cannot hold up window closure if a Windows driver hangs.
        threading.Thread(
            target=self._scanner.run,
            name="COM-port-scan",
            daemon=True,
        ).start()

    @Slot(object, str)
    def _scan_finished(self, result, error):
        self._scan_in_progress = False
        if not self._accept_results:
            return
        self.refresh_btn.setEnabled(True)
        if error:
            self.status_lbl.setText("COM port scan failed; retry available")
            self.log_requested.emit(f"[FAIL] COM port scan error: {error}")
            return
        self._apply_scan(result, self._announce_all)

    def _apply_scan(self, result, announce_all):
        try:
            previous = {d.get("port") for d in self.devices}
            selected = self.port_combo.currentText()

            ports, new_ports = result

            removed = sorted(
                p for p in previous
                if p and p not in {d["port"] for d in ports}
            )

            for port in removed:
                self.log_requested.emit(
                    f"[WARN] COM Port Disconnected : {port}"
                )

            changed = (
                [d.get("port") for d in ports]
                != [d.get("port") for d in self.devices]
            )

            self.devices = ports

            if changed:
                self.port_combo.blockSignals(True)
                self.port_combo.clear()
                self.port_combo.addItems(
                    [d["port"] for d in ports]
                )
                self.port_combo.blockSignals(False)

            if ports:
                self.status_lbl.setText(
                    f"{len(ports)} COM port(s) detected"
                )
            else:
                self.status_lbl.setText("No COM ports detected")
                self.device_selected.emit({})

            for dev in new_ports:
                self.log_requested.emit(
                    f"[INFO] New COM Port Detected : {dev['port']}"
                )
                self.describe_device(dev)

            if not ports:
                return

            # Prefer a newly arrived port, otherwise keep the user's choice.
            target = (
                new_ports[0]["port"] if new_ports
                else (
                    selected
                    if selected in [d["port"] for d in ports]
                    else ports[0]["port"]
                )
            )

            index = self.port_combo.findText(target)

            if index >= 0 and index != self.port_combo.currentIndex():
                self.port_combo.setCurrentIndex(index)
            elif changed or announce_all:
                self.on_port_selected()

        except Exception as ex:
            self.log_requested.emit(
                f"[FAIL] COM port scan error: {ex}"
            )

    def current_device(self):

        index = self.port_combo.currentIndex()

        if index < 0 or index >= len(self.devices):
            return {}

        return self.devices[index]

    def on_port_selected(self):

        device = self.current_device()

        if not device:
            return

        self.device_selected.emit(device)
        self.describe_device(device)

    def describe_device(self, device):
        """Print the full device record for a COM port to the event log."""

        emit = self.log_requested.emit

        emit("--------------------------------")
        emit(f"[INFO] COM Port Device : {device.get('port', 'N/A')}")
        emit(f"Device Name : {device.get('name', 'Unknown')}")
        emit(f"VID         : {device.get('vid', 'N/A')}")
        emit(f"PID         : {device.get('pid', 'N/A')}")
        emit(f"USB Class   : {device.get('usb_class', 'N/A')}")
        emit(f"Sub Class   : {device.get('subclass', 'N/A')}")
        emit(f"Port        : {device.get('port', 'N/A')}")
        emit(f"Protocol    : {device.get('protocol', 'N/A')}")
        emit("--------------------------------")

        if not device.get("usb_backed", True):
            emit(
                "[WARN] This is not a USB serial port "
                "(no USB descriptors available); "
                "USB-specific checks will not apply."
            )
