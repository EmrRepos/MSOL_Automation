from PySide6.QtWidgets import (
    QGroupBox,
    QLabel,
    QGridLayout
)


class DeviceDetailsPanel(QGroupBox):

    def __init__(self):

        super().__init__("DEVICE DETAILS")

        layout = QGridLayout()

        self.name_lbl = QLabel("-")
        self.vid_lbl = QLabel("-")
        self.pid_lbl = QLabel("-")
        self.class_lbl = QLabel("-")
        self.subclass_lbl = QLabel("-")
        self.port_lbl = QLabel("-")
        self.protocol_lbl = QLabel("-")
        self.manufacturer_lbl = QLabel("-")
        self.serial_lbl = QLabel("-")
        self.status_lbl = QLabel("-")
        self.authorized_lbl = QLabel("-")


        value_labels = [
            self.name_lbl,
            self.vid_lbl,
            self.pid_lbl,
            self.class_lbl,
            self.subclass_lbl,
            self.port_lbl,
            self.protocol_lbl,
            self.manufacturer_lbl,
            self.serial_lbl,
            self.status_lbl,
            self.authorized_lbl,
        ]

        for lbl in value_labels:
            lbl.setStyleSheet("""
                font-size: 11pt;
                font-weight: bold;
                color: #0078D4;
            """)

        layout.addWidget(QLabel("Name :"), 0, 0)
        layout.addWidget(self.name_lbl, 0, 1)

        layout.addWidget(QLabel("VID :"), 1, 0)
        layout.addWidget(self.vid_lbl, 1, 1)

        layout.addWidget(QLabel("PID :"), 2, 0)
        layout.addWidget(self.pid_lbl, 2, 1)

        layout.addWidget(QLabel("USB Class :"), 3, 0)
        layout.addWidget(self.class_lbl, 3, 1)

        layout.addWidget(QLabel("Subclass :"), 4, 0)
        layout.addWidget(self.subclass_lbl, 4, 1)

        layout.addWidget(QLabel("Port :"), 5, 0)
        layout.addWidget(self.port_lbl, 5, 1)

        layout.addWidget(QLabel("Protocol :"), 6, 0)
        layout.addWidget(self.protocol_lbl, 6, 1)

        layout.addWidget(QLabel("Manufacturer :"), 7, 0)
        layout.addWidget(self.manufacturer_lbl, 7, 1)

        layout.addWidget(QLabel("Serial :"), 8, 0)
        layout.addWidget(self.serial_lbl, 8, 1)

        layout.addWidget(QLabel("Status :"), 9, 0)
        layout.addWidget(self.status_lbl, 9, 1)

        layout.addWidget(QLabel("Authorized :"), 10, 0)
        layout.addWidget(self.authorized_lbl, 10, 1)

        layout.setColumnStretch(0, 1)
        layout.setColumnStretch(1, 4)

        self.setLayout(layout)

    def update_device(self, device):

        self.name_lbl.setText(str(device.get("name", "-")))
        self.vid_lbl.setText(str(device.get("vid", "-")))
        self.pid_lbl.setText(str(device.get("pid", "-")))
        self.class_lbl.setText(str(device.get("usb_class", "-")))
        self.subclass_lbl.setText(str(device.get("subclass", "-")))
        self.port_lbl.setText(str(device.get("port", "-")))
        self.protocol_lbl.setText(str(device.get("protocol", "-")))
        self.manufacturer_lbl.setText(str(device.get("manufacturer", "-")))
        self.serial_lbl.setText(str(device.get("serial", "-")))
        self.status_lbl.setText(str(device.get("status", "-")))
        self.authorized_lbl.setText(str(device.get("authorized", "-")))