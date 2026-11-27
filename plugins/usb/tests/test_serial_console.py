import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, PropertyMock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import serial
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QPalette, QTextCursor
from PySide6.QtTest import QTest

from plugins.serial_console import SerialConsole
from ui.test_panel import TestPanel


class SerialConsoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        ports = patch(
            "plugins.serial_console.serial.tools.list_ports.comports",
            return_value=[SimpleNamespace(device="COM6")],
        )
        ports.start()
        self.addCleanup(ports.stop)
        warnings = patch("plugins.serial_console.QMessageBox.warning")
        self.warning = warnings.start()
        self.addCleanup(warnings.stop)
        self.console = SerialConsole()
        self.addCleanup(self.console.close)

    def connect_loopback(self):
        connection = serial.serial_for_url(
            "loop://", baudrate=115200, timeout=0, write_timeout=1
        )
        self.addCleanup(connection.close)
        with patch(
            "plugins.serial_console.serial.Serial", return_value=connection
        ) as factory:
            self.console.connect_port()
        return connection, factory

    def test_connect_uses_selected_port_and_nonblocking_8n1(self):
        self.console.baud_combo.setCurrentText("9600")
        connection, factory = self.connect_loopback()
        factory.assert_called_once_with(
            port="COM6", baudrate=9600, bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
            timeout=0, write_timeout=1,
            xonxoff=False, rtscts=False, dsrdtr=False,
        )
        self.assertEqual(connection.in_waiting, 0)
        self.assertTrue(self.console.rx_timer.isActive())
        self.assertFalse(self.console.btn_connect.isEnabled())
        self.assertTrue(self.console.btn_send_ascii.isEnabled())

    def test_ascii_sends_exact_bytes_for_every_line_ending(self):
        connection, _ = self.connect_loopback()
        self.console.tx_box.setText("STATUS")
        for index, ending in enumerate((b"", b"\r", b"\n", b"\r\n")):
            with self.subTest(ending=ending):
                self.console.line_ending.setCurrentIndex(index)
                self.console.send_ascii()
                self.assertEqual(connection.read(100), b"STATUS" + ending)
                self.console.finish_response_check()

    def test_all_framing_selections_are_passed_to_serial_driver(self):
        self.console.baud_combo.setCurrentText("38400")
        for data_index in range(4):
            for parity_index in range(5):
                for stop_index in range(3):
                    with self.subTest(data=data_index, parity=parity_index, stop=stop_index):
                        self.console.data_bits_combo.setCurrentIndex(data_index)
                        self.console.parity_combo.setCurrentIndex(parity_index)
                        self.console.stop_bits_combo.setCurrentIndex(stop_index)
                        connection = Mock(is_open=True)
                        with patch(
                            "plugins.serial_console.serial.Serial", return_value=connection
                        ) as factory:
                            self.console.connect_port()
                        settings = factory.call_args.kwargs
                        self.assertEqual(settings["baudrate"], 38400)
                        self.assertEqual(settings["bytesize"], (5, 6, 7, 8)[data_index])
                        self.assertEqual(settings["parity"], ("N", "E", "O", "M", "S")[parity_index])
                        self.assertEqual(settings["stopbits"], (1, 1.5, 2)[stop_index])
                        for combo in (
                            self.console.data_bits_combo, self.console.parity_combo,
                            self.console.stop_bits_combo, self.console.baud_combo,
                        ):
                            self.assertFalse(combo.isEnabled())
                        self.assertFalse(self.console.start_bits_combo.isEnabled())
                        self.console.disconnect_port()
                        connection.close.assert_called_once()
                        self.assertTrue(self.console.parity_combo.isEnabled())

    def test_even_parity_connection_log_and_fixed_start_bit(self):
        self.console.baud_combo.setCurrentText("38400")
        self.console.parity_combo.setCurrentText("Even")
        self.connect_loopback()
        self.assertIn("8-E-1; 1 start bit", self.console.console.toPlainText())
        self.assertEqual(self.console.start_bits_combo.count(), 1)
        self.assertFalse(self.console.start_bits_combo.isEnabled())

    def test_unsupported_framing_error_keeps_controls_editable(self):
        self.console.parity_combo.setCurrentText("Mark")
        with patch(
            "plugins.serial_console.serial.Serial",
            side_effect=ValueError("Unsupported parity on adapter"),
        ):
            self.console.connect_port()
        self.warning.assert_called_once()
        self.assertFalse(self.console.is_connected)
        self.assertTrue(self.console.parity_combo.isEnabled())
        self.assertFalse(self.console.rx_timer.isActive())
        self.assertIn("Unsupported parity", self.console.console.toPlainText())

    def test_missing_framing_selection_is_rejected_before_open(self):
        self.console.data_bits_combo.setCurrentIndex(-1)
        with patch("plugins.serial_console.serial.Serial") as factory:
            self.console.connect_port()
        factory.assert_not_called()
        self.warning.assert_called_once()

    def test_hex_ignores_ascii_ending_and_receive_logs_exact_bytes(self):
        connection, _ = self.connect_loopback()
        self.console.line_ending.setCurrentText("CRLF")
        self.console.tx_box.setText("00 41 ff 0d")
        self.console.send_hex()
        self.assertEqual(connection.in_waiting, 4)
        self.console.read_loop()
        log = self.console.console.toPlainText()
        self.assertIn("TX HEX -> 00 41 ff 0d", log)
        self.assertIn("RX HEX -> 00 41 ff 0d", log)
        self.assertIn(r"\xff", log)
        self.assertEqual(connection.in_waiting, 0)

    def test_invalid_input_is_reported_without_writing(self):
        connection, _ = self.connect_loopback()
        for method, text in (
            (self.console.send_hex, "GG"),
            (self.console.send_hex, "A"),
            (self.console.send_hex, ""),
            (self.console.send_ascii, "\u00e9"),
            (self.console.send_ascii, ""),
        ):
            with self.subTest(text=text, method=method.__name__):
                self.warning.reset_mock()
                self.console.tx_box.setText(text)
                method()
                self.warning.assert_called_once()
                self.assertEqual(connection.in_waiting, 0)

    def test_send_disconnected_reports_error(self):
        self.console.tx_box.setText("STATUS")
        self.console.send_ascii()
        self.warning.assert_called_once()
        self.assertIn("Connect to a COM port first", self.console.console.toPlainText())

    def test_invalid_baud_and_failed_open_are_reported(self):
        with patch("plugins.serial_console.serial.Serial") as factory:
            for baud in ("bad", "0", "-1"):
                self.console.baud_combo.setCurrentText(baud)
                self.console.connect_port()
            factory.assert_not_called()
            self.console.baud_combo.setCurrentText("115200")
            factory.side_effect = serial.SerialException("Access denied")
            self.console.connect_port()
        self.assertFalse(self.console.is_connected)
        self.assertFalse(self.console.rx_timer.isActive())
        self.assertIn("Access denied", self.console.console.toPlainText())
        self.assertEqual(self.warning.call_count, 4)

    def test_discovery_failure_is_visible(self):
        with patch(
            "plugins.serial_console.serial.tools.list_ports.comports",
            side_effect=OSError("Cannot enumerate"),
        ):
            self.console.refresh_ports()
        self.warning.assert_called_once()
        self.assertIn("Cannot enumerate", self.console.console.toPlainText())

    def test_missing_selected_port_does_not_select_another_device(self):
        self.console.select_port("COM99")
        self.assertEqual(self.console.port_combo.currentText(), "")
        self.assertFalse(self.console.btn_connect.isEnabled())
        with patch("plugins.serial_console.serial.Serial") as factory:
            self.console.connect_port()
            factory.assert_not_called()

    def test_close_releases_connection_and_stops_polling(self):
        connection, _ = self.connect_loopback()
        self.console.close()
        self.assertFalse(connection.is_open)
        self.assertIsNone(self.console.ser)
        self.assertFalse(self.console.rx_timer.isActive())
        self.assertFalse(self.console.btn_send_hex.isEnabled())

    def test_write_failure_or_partial_write_disconnects_and_is_not_success(self):
        for result in (serial.SerialTimeoutException("Timed out"), 1):
            with self.subTest(result=result):
                connection = Mock(is_open=True, in_waiting=0)
                if isinstance(result, Exception):
                    connection.write.side_effect = result
                else:
                    connection.write.return_value = result
                self.console.ser = connection
                self.console.send_payload(b"ABC")
                connection.close.assert_called_once()
                self.assertIsNone(self.console.ser)
                self.assertNotIn("TX HEX ->", self.console.console.toPlainText())

    def test_receive_failure_disconnects_and_reports_error(self):
        connection = Mock(is_open=True)
        type(connection).in_waiting = PropertyMock(
            side_effect=serial.SerialException("Unplugged")
        )
        self.console.ser = connection
        self.console.read_loop()
        connection.close.assert_called_once()
        self.assertFalse(self.console.is_connected)
        self.assertIn("Unplugged", self.console.console.toPlainText())

    def test_text_is_not_interpreted_as_html(self):
        self.connect_loopback()
        self.console.tx_box.setText("<status>")
        self.console.send_ascii()
        self.console.read_loop()
        self.assertEqual(self.console.console.toPlainText().count("<status>"), 2)

    def test_save_log_failure_is_visible(self):
        with (
            patch(
                "plugins.serial_console.QFileDialog.getSaveFileName",
                return_value=("serial-log.txt", ""),
            ),
            patch("builtins.open", side_effect=OSError("Disk full")),
        ):
            self.console.save_log()
        self.assertIn("Disk full", self.console.console.toPlainText())

    def start_checked_send(self, expected=""):
        connection, _ = self.connect_loopback()
        self.console.expected_response.setText(expected)
        self.console.send_payload(b"STATUS\r")
        self.assertEqual(connection.read(100), b"STATUS\r")
        return connection

    def test_terminal_colors_and_log_appends_after_cursor_moves(self):
        self.console.show()
        self.app.processEvents()
        palette = self.console.console.viewport().palette()
        self.assertEqual(palette.color(QPalette.Base).name(), "#000000")
        self.assertEqual(palette.color(QPalette.Text).name(), "#ffffff")
        self.console.log("first")
        self.console.console.moveCursor(QTextCursor.Start)
        self.console.log("second")
        self.assertEqual(self.console.console.toPlainText(), "first\nsecond\n")

    def test_real_timeout_reports_no_reply_and_unlocks_send(self):
        self.console.response_timeout.setValue(100)
        self.start_checked_send()
        self.assertTrue(self.console.response_pending)
        self.assertFalse(self.console.btn_send_ascii.isEnabled())
        self.assertFalse(self.console.expected_response.isEnabled())
        QTest.qWait(180)
        self.assertFalse(self.console.response_pending)
        self.assertIn("NO REPLY", self.console.response_status.text())
        self.assertIn("not proof of rejection", self.console.response_status.text())
        self.assertTrue(self.console.btn_send_ascii.isEnabled())

    def test_loopback_echo_is_not_acceptance_even_when_expected_matches(self):
        self.connect_loopback()
        self.console.expected_response.setText("41 42 43")
        self.console.send_payload(b"ABC")
        self.console.finish_response_check()
        self.assertIn("ECHO ONLY", self.console.response_status.text())
        self.assertIn("acceptance unconfirmed", self.console.response_status.text())

    def test_fragmented_expected_response_matches(self):
        connection = self.start_checked_send("4F 4B 0D 0A")
        for chunk in (b"noiseO", b"K\r", b"\n"):
            connection.write(chunk)
            self.console.read_loop()
        self.console.finish_response_check()
        self.assertIn("EXPECTED RESPONSE MATCHED", self.console.response_status.text())
        self.assertIn("RX: 9 bytes", self.console.response_status.text())

    def test_unsolicited_data_before_send_does_not_count_as_reply(self):
        connection, _ = self.connect_loopback()
        connection.write(b"OLD")
        self.console.expected_response.setText("4F 4C 44")
        self.console.send_payload(b"STATUS")
        self.assertEqual(connection.read(100), b"STATUS")
        self.console.finish_response_check()
        self.assertIn("RX HEX -> 4f 4c 44", self.console.console.toPlainText())
        self.assertIn("NO REPLY", self.console.response_status.text())

    def test_reply_without_expected_ack_remains_unconfirmed(self):
        connection = self.start_checked_send()
        connection.write(b"hello")
        self.console.finish_response_check()
        self.assertIn("REPLY OBSERVED", self.console.response_status.text())
        self.assertIn("acceptance unconfirmed", self.console.response_status.text())

    def test_unmatched_expected_response_is_not_acceptance(self):
        connection = self.start_checked_send("06")
        connection.write(b"\x15")
        self.console.finish_response_check()
        self.assertIn("EXPECTED RESPONSE NOT MATCHED", self.console.response_status.text())

    def test_one_byte_match_and_bounded_matching_buffer(self):
        connection = self.start_checked_send("06")
        connection.write(b"x" * 4096)
        self.console.read_loop()
        self.assertEqual(self.console.response_tail, b"")
        connection.write(b"\x06")
        self.console.finish_response_check()
        self.assertIn("EXPECTED RESPONSE MATCHED", self.console.response_status.text())

    def test_invalid_expected_hex_prevents_transmission(self):
        connection, _ = self.connect_loopback()
        self.console.expected_response.setText("ZZ")
        self.console.send_payload(b"STATUS")
        self.assertEqual(connection.in_waiting, 0)
        self.assertFalse(self.console.response_pending)
        self.warning.assert_called_once()

    def test_pending_check_blocks_direct_send_and_disconnect_cancels(self):
        connection = self.start_checked_send()
        self.console.send_payload(b"SECOND")
        self.assertEqual(connection.in_waiting, 0)
        self.warning.assert_called_once()
        self.console.disconnect_port()
        self.assertFalse(self.console.response_pending)
        self.assertFalse(self.console.response_timer.isActive())
        self.assertIn("CHECK CANCELLED", self.console.response_status.text())

    def test_unchecked_send_does_not_wait_or_parse_expected_hex(self):
        connection, _ = self.connect_loopback()
        self.console.check_response.setChecked(False)
        self.console.expected_response.setText("ZZ")
        self.console.send_payload(b"ABC")
        self.assertEqual(connection.read(100), b"ABC")
        self.assertFalse(self.console.response_pending)
        self.assertIn("NOT CHECKED", self.console.response_status.text())
        self.assertTrue(self.console.btn_send_hex.isEnabled())

    def test_streaming_input_refuses_send_without_discarding_data(self):
        connection = Mock(is_open=True, in_waiting=5000)
        connection.read.return_value = b"x" * 4096
        self.console.ser = connection
        self.console.send_payload(b"STATUS")
        connection.write.assert_not_called()
        connection.reset_input_buffer.assert_not_called()
        self.assertIn("No command sent", self.console.console.toPlainText())
        self.assertFalse(self.console.response_pending)


class SerialConsoleIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        with patch("ui.test_panel.TestRunner") as factory:
            self.runner = factory.return_value
            self.runner.running = False
            self.panel = TestPanel()
        self.panel.set_selected_device({"port": "COM6", "name": "Target"})
        self.panel.dashboard = Mock()
        self.panel.log_message = Mock()
        self.addCleanup(self.panel.close)

    def test_console_opens_on_ui_path_without_running_a_test(self):
        self.panel.profile.setCurrentText("Serial Console")
        with patch("ui.test_panel.SerialConsole") as factory:
            console = factory.return_value
            self.panel.start_test()
            self.panel.start_test()
        factory.assert_called_once_with(self.panel)
        console.select_port.assert_called_with("COM6")
        self.assertEqual(console.show.call_count, 2)
        self.runner.start.assert_not_called()
        self.panel.dashboard.increment_test_runs.assert_not_called()

    def test_running_test_blocks_console_open(self):
        self.runner.running = True
        self.panel.profile.setCurrentText("Serial Console")
        with patch("ui.test_panel.SerialConsole") as factory:
            self.panel.start_test()
            factory.assert_not_called()
        self.runner.start.assert_not_called()

    def test_connected_console_blocks_tests_and_stop_disconnects(self):
        self.panel.serial_console = Mock(is_connected=True)
        self.panel.start_test()
        self.runner.start.assert_not_called()
        self.panel.stop_test()
        self.panel.serial_console.disconnect_port.assert_called_once()
        self.runner.stop.assert_called_once()

    def test_disconnected_console_preserves_automated_test_path(self):
        self.panel.serial_console = Mock(is_connected=False)
        self.panel.hardware_checkbox.setChecked(True)
        self.panel.start_test()
        self.runner.start.assert_called_once()
        self.assertTrue(self.runner.start.call_args.kwargs["use_hardware"])
        self.panel.serial_console.close.assert_called_once()
        self.panel.dashboard.increment_test_runs.assert_called_once()


if __name__ == "__main__":
    unittest.main()
