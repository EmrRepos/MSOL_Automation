import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from main import main
from modules.discovery import parse_identity_payload
from test_discovery import identity_payload


class CLITests(unittest.TestCase):
    def test_catalog_is_offline(self):
        output = io.StringIO()
        with redirect_stdout(output), patch('main.Discovery.discover') as discover:
            self.assertEqual(main(['assess']), 0)
            discover.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())[0]['identifier'], 'EIP-01')

    def test_missing_authorization_prevents_probe(self):
        with redirect_stderr(io.StringIO()), patch('main.Discovery.discover') as discover:
            with self.assertRaises(SystemExit) as error:
                main(['discover', '192.0.2.10'])
            self.assertEqual(error.exception.code, 2)
            discover.assert_not_called()

    def test_default_command_launches_ui(self):
        with patch('ui.launch') as launch:
            self.assertEqual(main([]), 0)
            launch.assert_called_once()

    def test_discovery_report(self):
        output = io.StringIO()
        with redirect_stdout(output), patch('main.Discovery.discover', return_value=parse_identity_payload(identity_payload())):
            code = main(['discover', '192.0.2.10', '--authorized', '--operator', 'Lab / ticket'])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report['scope']['mode'], 'live')
        self.assertEqual(report['identities'][0]['product_name'], 'Lab PLC')

    def test_cli_exports_pdf_and_json_and_rejects_unsupported_extension(self):
        with tempfile.TemporaryDirectory() as directory:
            pdf_path = Path(directory) / 'device.pdf'
            output = io.StringIO()
            with redirect_stdout(output), patch(
                'main.Discovery.discover', return_value=parse_identity_payload(identity_payload())
            ):
                code = main(['discover', '192.0.2.10', '--authorized', '--operator', 'Lab / ticket',
                             '--output', str(pdf_path)])
            self.assertEqual(code, 0)
            self.assertTrue(pdf_path.read_bytes().startswith(b'%PDF-'))
            report = json.loads(output.getvalue())
            self.assertIsNotNone(report['scope']['completed_at_utc'])
            json_path = Path(directory) / 'reports' / 'ethernetip' / 'discovery.json'
            with redirect_stdout(io.StringIO()), patch(
                'main.Discovery.discover', return_value=parse_identity_payload(identity_payload())
            ):
                code = main(['discover', '192.0.2.10', '--authorized', '--operator', 'Lab / ticket',
                             '--output', str(json_path)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(json_path.read_text(encoding='utf-8'))['scope']['mode'], 'live')
        with redirect_stderr(io.StringIO()), patch('main.Discovery.discover') as discover:
            with self.assertRaises(SystemExit):
                main(['discover', '192.0.2.10', '--authorized', '--operator', 'Lab',
                      '--output', 'device.txt'])
            discover.assert_not_called()

    def test_network_failure_is_inconclusive(self):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()), patch(
            'main.Discovery.discover', side_effect=TimeoutError('timed out')
        ):
            code = main(['discover', '192.0.2.10', '--authorized', '--operator', 'Lab / ticket'])
        self.assertEqual(code, 1)
        report = json.loads(output.getvalue())
        self.assertIn('inconclusive', report['scope']['outcome'])
        self.assertEqual(report['observations'], [])

    def test_live_suite_cli_authorization_and_report(self):
        from modules.live_tests import LiveTestRunner
        import threading
        cancel = threading.Event()
        cancel.set()
        run = LiveTestRunner().run('192.0.2.10', 'Lab / ticket', True, cancel)
        with redirect_stderr(io.StringIO()), patch('main.LiveTestRunner.run') as execute:
            with self.assertRaises(SystemExit):
                main(['test', '192.0.2.10'])
            execute.assert_not_called()
        output = io.StringIO()
        with redirect_stdout(output), patch('main.LiveTestRunner.run', return_value=run):
            self.assertEqual(main(['test', '192.0.2.10', '--authorized', '--operator', 'Lab / ticket']), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report['live_test_run']['outcome'], 'cancelled')
        self.assertEqual(report['reproduction']['cli_arguments'][2], 'test')

    def test_coverage_command_is_offline(self):
        output = io.StringIO()
        with redirect_stdout(output), patch('core.connection.socket.create_connection') as connect:
            self.assertEqual(main(['coverage']), 0)
            connect.assert_not_called()
        self.assertTrue(any(item['coverage'] == 'not_implemented' for item in json.loads(output.getvalue())))

    def test_single_case_cli_and_report_reproduction(self):
        from test_live_tests import DeviceSocket
        device = DeviceSocket()
        output = io.StringIO()
        with redirect_stdout(output), patch('core.connection.socket.create_connection', return_value=device), patch(
            'threading.Event.wait', return_value=False
        ):
            code = main(['test', '192.0.2.10', '--authorized', '--operator', 'Lab / ticket', '--case', 'CIP-03'])
        self.assertEqual(code, 0)
        self.assertEqual(device.commands, [0x65, 0x6F, 0x66])
        report = json.loads(output.getvalue())
        self.assertEqual(report['live_test_run']['selected_case'], 'CIP-03')
        self.assertEqual(report['reproduction']['cli_arguments'][-2:], ['--case', 'CIP-03'])

    def test_multiple_mixed_cases_report_reproduction(self):
        from test_live_tests import DeviceSocket
        from test_protocol import SimulatedSocket
        baseline, fuzz = DeviceSocket(), SimulatedSocket()
        output = io.StringIO()
        with redirect_stdout(output), patch('core.connection.socket.create_connection', side_effect=[baseline, fuzz]), patch(
            'threading.Event.wait', return_value=False
        ):
            code = main(['selected', '192.0.2.10', '--authorized', '--fuzz-authorized',
                         '--operator', 'Lab', '--case', 'CIP-01', '--case', 'FUZ-02'])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report['live_test_run']['selected_cases'], ['CIP-01', 'FUZ-02'])
        self.assertEqual(report['reproduction']['cli_arguments'][2], 'selected')
        self.assertIn('--fuzz-authorized', report['reproduction']['cli_arguments'])
        self.assertEqual(report['reproduction']['cli_arguments'][-4:], ['--case', 'CIP-01', '--case', 'FUZ-02'])

    def test_single_case_rejected_for_other_commands_and_invalid_ids(self):
        with redirect_stderr(io.StringIO()), patch('core.connection.socket.create_connection') as connect:
            with self.assertRaises(SystemExit):
                main(['coverage', '--case', 'CIP-01'])
            self.assertEqual(main(['test', '192.0.2.10', '--authorized', '--operator', 'Lab', '--case', 'FUZ-01']), 1)
        connect.assert_not_called()

    def test_single_fuzz_case_report_preserves_authorization_and_reproduction(self):
        from test_protocol import SimulatedSocket
        device = SimulatedSocket()
        output = io.StringIO()
        with redirect_stdout(output), patch('core.connection.socket.create_connection', return_value=device), patch(
            'threading.Event.wait', return_value=False
        ):
            code = main(['fuzz', '192.0.2.10', '--authorized', '--fuzz-authorized', '--operator', 'Lab',
                         '--case', 'FUZ-02'])
        self.assertEqual(code, 0)
        self.assertEqual(device.commands, [0x65, 0x6F, 0x66])
        report = json.loads(output.getvalue())
        self.assertEqual(report['live_test_run']['selected_case'], 'FUZ-02')
        self.assertIn('--fuzz-authorized', report['reproduction']['cli_arguments'])
        self.assertEqual(report['reproduction']['cli_arguments'][-2:], ['--case', 'FUZ-02'])

    def test_fuzz_requires_separate_authorization_and_reports_its_mode(self):
        import threading
        from modules.fuzz_tests import FuzzTestRunner
        cancel = threading.Event()
        cancel.set()
        run = FuzzTestRunner().run('192.0.2.10', 'Lab / ticket', True, cancel, fuzz_authorized=True)
        with redirect_stderr(io.StringIO()), patch('main.FuzzTestRunner.run') as execute:
            with self.assertRaises(SystemExit):
                main(['fuzz', '192.0.2.10', '--authorized', '--operator', 'Lab / ticket'])
            execute.assert_not_called()
        output = io.StringIO()
        with redirect_stdout(output), patch('main.FuzzTestRunner.run', return_value=run):
            self.assertEqual(main(['fuzz', '192.0.2.10', '--authorized', '--fuzz-authorized',
                                   '--operator', 'Lab / ticket']), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report['scope']['request'], 'Bounded CIP fuzz suite')
        self.assertEqual(report['reproduction']['cli_arguments'][2], 'fuzz')
        self.assertIn('--fuzz-authorized', report['reproduction']['cli_arguments'])


if __name__ == '__main__':
    unittest.main()