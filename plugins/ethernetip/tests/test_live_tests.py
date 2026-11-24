import struct
import threading
import unittest
from unittest.mock import patch

from modules.live_tests import LIVE_CASES, LiveTestRunner, SelectedTestRunner, coverage_matrix, parse_discovery_items
from modules.fuzz_tests import FUZZ_CASES, FuzzTestRunner
from modules.discovery import HEADER
from test_discovery import identity_payload
from test_protocol import SimulatedSocket


class DeviceSocket(SimulatedSocket):
    def __init__(self, cip_status=0, unsupported_interfaces=False):
        super().__init__()
        self.cip_status = cip_status
        self.unsupported_interfaces = unsupported_interfaces

    def sendall(self, request):
        super().sendall(request)
        command, size, session, status, context, options = HEADER.unpack(request[:24])
        payload = b'\x00\x00'
        if command == 0x0066:
            return
        if command == 0x0063:
            payload = identity_payload()
        elif command == 0x0004:
            data = struct.pack('<HH16s', 1, 0x20, b'Communications')
            payload = struct.pack('<HHH', 1, 0x100, len(data)) + data
        elif command == 0x0064 and self.unsupported_interfaces:
            status = 1
        elif command == 0x0065:
            payload, session = request[24:], 123
        elif command == 0x006F:
            attribute = request[-1]
            values = {1: b'\x01\x00', 2: b'\x0e\x00', 3: b'\x7b\x00', 4: b'\x02\x07',
                      5: b'\x00\x00', 6: bytes.fromhex('78563412'), 7: b'\x07Lab PLC'}
            cip = bytes((0x8E, 0, self.cip_status, 0)) + (values[attribute] if not self.cip_status else b'')
            payload = struct.pack('<IHHHHHH', 0, 0, 2, 0, 0, 0xB2, len(cip)) + cip
        self.buffer = HEADER.pack(command, len(payload), session, status, context, 0) + payload


class LiveSuiteTests(unittest.TestCase):
    def run_device(self, device):
        with patch('core.connection.socket.create_connection', return_value=device), patch('threading.Event.wait', return_value=False):
            return LiveTestRunner().run('192.0.2.10', 'Tester / lab ticket', authorized=True)

    def test_complete_live_suite_against_mock_device(self):
        device = DeviceSocket()
        run = self.run_device(device)
        self.assertEqual(run['outcome'], 'completed')
        self.assertEqual(len(run['test_results']), len(LIVE_CASES))
        self.assertTrue(all(result['status'] == 'observed' for result in run['test_results']))
        self.assertEqual(len(device.commands), 12)
        self.assertEqual(device.commands.count(0x65), 1)
        self.assertEqual(device.commands[-1], 0x66)
        self.assertTrue(device.closed)
        self.assertEqual(run['attribute_values']['product_name'], 'Lab PLC')
        self.assertEqual(run['consistency_observations'], [])
        self.assertEqual(len(run['evidence_sha256']), 64)

    def test_each_live_case_runs_only_selected_case_and_session_dependencies(self):
        commands = {'ENIP-01': [0x63], 'ENIP-02': [0x04], 'ENIP-03': [0x64],
                    'ENIP-04': [0x65, 0x66], 'ENIP-05': [0x65, 0x66]}
        commands.update({f'CIP-{attribute:02}': [0x65, 0x6F, 0x66] for attribute in range(1, 8)})
        for case_id, expected in commands.items():
            with self.subTest(case_id=case_id):
                device = DeviceSocket()
                with patch('core.connection.socket.create_connection', return_value=device), patch(
                    'threading.Event.wait', return_value=False
                ):
                    run = LiveTestRunner().run('192.0.2.10', 'Lab', True, case_id=case_id)
                self.assertEqual(device.commands, expected)
                self.assertEqual(run['selected_case'], case_id)
                results = {item['id']: item for item in run['test_results']}
                self.assertEqual(results[case_id]['status'], 'observed')
                if case_id.startswith('CIP-'):
                    self.assertEqual(device.requests[1][-1], int(case_id[-2:]))
                    self.assertEqual(run['supporting_cases'], ['ENIP-04', 'ENIP-05'])
                for identifier, result in results.items():
                    if identifier != case_id and identifier not in run['supporting_cases']:
                        self.assertEqual(result['status'], 'not_run')
                        self.assertEqual(result['detail'], 'Not selected for this run.')

    def test_unavailable_session_makes_selected_case_incomplete(self):
        device = DeviceSocket()
        original_send = device.sendall
        def reject_registration(request):
            original_send(request)
            if HEADER.unpack(request[:24])[0] == 0x65:
                packet = bytearray(device.buffer)
                struct.pack_into('<I', packet, 8, 1)
                device.buffer = bytes(packet)
        with patch.object(device, 'sendall', side_effect=reject_registration), patch(
            'core.connection.socket.create_connection', return_value=device
        ), patch('threading.Event.wait', return_value=False):
            run = LiveTestRunner().run('192.0.2.10', 'Lab', True, case_id='CIP-01')
        self.assertEqual(device.commands, [0x65])
        self.assertEqual(run['outcome'], 'incomplete')
        result = next(item for item in run['test_results'] if item['id'] == 'CIP-01')
        self.assertEqual(result['status'], 'not_run')
        self.assertIn('required session', result['detail'])

    def test_invalid_live_case_is_rejected_before_connection(self):
        with patch('core.connection.socket.create_connection') as connect, self.assertRaises(ValueError):
            LiveTestRunner().run('192.0.2.10', 'Lab', True, case_id='ETH-AUTH-001')
        connect.assert_not_called()

    def test_progress_reports_case_start_and_final_classification(self):
        messages = []
        with patch('core.connection.socket.create_connection', return_value=DeviceSocket(cip_status=0x0F)), patch(
            'threading.Event.wait', return_value=False
        ):
            LiveTestRunner().run('192.0.2.10', 'Lab', True, progress=messages.append)
        self.assertTrue(any(message.startswith('CIP-01: starting') for message in messages))
        self.assertTrue(any(message.startswith('CIP-01: access_denied') for message in messages))

    def test_unsupported_discovery_does_not_prevent_reads(self):
        run = self.run_device(DeviceSocket(unsupported_interfaces=True))
        self.assertEqual(run['test_results'][2]['status'], 'unsupported')
        self.assertEqual(run['attribute_values']['vendor_id'], 1)

    def test_access_denial_and_unsupported_are_not_findings(self):
        for status, expected in ((0x0F, 'access_denied'), (0x14, 'unsupported'), (0x01, 'inconclusive')):
            run = self.run_device(DeviceSocket(cip_status=status))
            self.assertEqual(run['test_results'][4]['status'], expected)
            self.assertEqual(run['attribute_values'], {})

    def test_authorization_and_cancel_precede_connection(self):
        with patch('core.connection.socket.create_connection') as connect:
            with self.assertRaises(ValueError):
                LiveTestRunner().run('192.0.2.10', 'Lab', authorized=False)
            cancel = threading.Event()
            cancel.set()
            run = LiveTestRunner().run('192.0.2.10', 'Lab', True, cancel)
            connect.assert_not_called()
        self.assertEqual(run['outcome'], 'cancelled')
        self.assertTrue(all(result['status'] == 'not_run' for result in run['test_results']))

    def test_unreachable_target_is_inconclusive(self):
        with patch('core.connection.socket.create_connection', side_effect=TimeoutError('timed out')):
            run = LiveTestRunner().run('192.0.2.10', 'Lab', True)
        self.assertEqual(run['outcome'], 'incomplete')
        self.assertEqual(run['exchanges'], [])
        self.assertTrue(all(result['status'] == 'not_run' for result in run['test_results']))

    def test_discovery_item_validation_and_coverage_gaps(self):
        for payload in (b'', b'\x01\x00', bytes.fromhex('01000001010000'), b'\x00\x00\x00'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                parse_discovery_items(payload, services=True)
        matrix = coverage_matrix()
        self.assertEqual(len({entry['id'] for entry in matrix}), len(matrix))
        self.assertTrue(any(entry['coverage'] == 'requires_device_profile' for entry in matrix))

    def test_workbook_cases_are_traced_without_enabling_unsafe_tests(self):
        matrix = {entry['id']: entry for entry in coverage_matrix()}
        workbook_cases = [entry for entry in matrix.values() if entry.get('source')]
        self.assertEqual(len(workbook_cases), 46)
        self.assertEqual(matrix['ETH-ENUM-001']['coverage'], 'partial_live_read_only')
        self.assertIn('CIP-01', matrix['ETH-ENUM-001']['related_live_tests'])
        self.assertEqual(matrix['ETH-AUTH-001']['coverage'], 'excluded_active_write')
        self.assertEqual(matrix['ETH-FUZ-001']['coverage'], 'excluded_isolated_lab')
        self.assertEqual(matrix['ETH-DOS-001']['coverage'], 'excluded_disruptive')
        self.assertTrue(all(entry['srs_mapping'] for entry in workbook_cases))

    def test_budget_expiry_after_pacing_sends_no_next_request(self):
        device = DeviceSocket()
        with patch('core.connection.socket.create_connection', return_value=device), patch(
            'modules.live_tests.time.monotonic', return_value=0.0
        ) as clock:
            def expire(_delay):
                clock.return_value = 31.0
                return False
            with patch('threading.Event.wait', side_effect=expire):
                run = LiveTestRunner().run('192.0.2.10', 'Lab', True)
        self.assertEqual(device.commands, [0x63])
        self.assertEqual(run['outcome'], 'incomplete')
        self.assertIn('budget', run['stop_reason'])

    def test_cancellation_after_read_still_cleans_up_session(self):
        device = DeviceSocket()
        cancel = threading.Event()
        original_send = device.sendall
        def send_and_cancel(request):
            original_send(request)
            if HEADER.unpack(request[:24])[0] == 0x6F:
                cancel.set()
        with patch('core.connection.socket.create_connection', return_value=device), patch(
            'threading.Event.wait', return_value=False
        ), patch.object(device, 'sendall', side_effect=send_and_cancel):
            run = LiveTestRunner().run('192.0.2.10', 'Lab', True, cancel)
        self.assertEqual(run['outcome'], 'cancelled')
        self.assertEqual(device.commands, [0x63, 0x04, 0x64, 0x65, 0x6F, 0x66])
        self.assertTrue(device.closed)
        self.assertEqual(run['test_results'][5]['status'], 'not_run')

    def test_malformed_cip_response_becomes_developer_candidate(self):
        from modules.discovery import Identity
        from modules.security import SecurityAssessment
        from reports.report import ReportGenerator
        device = DeviceSocket()
        original_send = device.sendall
        def corrupt_cip(request):
            original_send(request)
            if HEADER.unpack(request[:24])[0] == 0x6F:
                packet = bytearray(device.buffer)
                packet[40] = 0x8F
                device.buffer = bytes(packet)
        with patch('core.connection.socket.create_connection', return_value=device), patch(
            'threading.Event.wait', return_value=False
        ), patch.object(device, 'sendall', side_effect=corrupt_cip):
            run = LiveTestRunner().run('192.0.2.10', 'Lab', True)
        self.assertEqual(run['test_results'][4]['status'], 'protocol_anomaly')
        self.assertEqual(device.commands[-1], 0x66)
        report = ReportGenerator().build('192.0.2.10', 'Lab', True, 'live', run['outcome'],
                                         [Identity(**item) for item in run['identities']], SecurityAssessment(), live_run=run)
        self.assertEqual(report['developer_review_candidates'][0]['test_id'], 'CIP-01')
        self.assertTrue(report['developer_review_candidates'][0]['exchange_indices'])


class FuzzSuiteTests(unittest.TestCase):
    def run_device(self, device, cancel=None):
        with patch('core.connection.socket.create_connection', return_value=device), patch(
            'threading.Event.wait', return_value=False
        ):
            return FuzzTestRunner().run('192.0.2.10', 'Lab / ticket', True, cancel, fuzz_authorized=True)

    def test_fixed_cases_and_cleanup_on_simulated_device(self):
        device = SimulatedSocket()
        run = self.run_device(device)
        self.assertEqual(run['outcome'], 'completed')
        self.assertEqual(device.commands, [0x65] + [0x6F] * len(FUZZ_CASES) + [0x66])
        self.assertEqual([request[40:] for request in device.requests[1:-1]],
                         [case[2] for case in FUZZ_CASES])
        self.assertTrue(all(result['status'] == 'observed' for result in run['test_results']))
        self.assertEqual(run['limits']['max_requests'], 30)
        self.assertEqual(run['limits']['minimum_request_interval_seconds'], 1.0)
        self.assertTrue(device.closed)

    def test_each_fuzz_case_runs_only_selected_case_and_session_setup(self):
        for case_id, _, request in FUZZ_CASES:
            with self.subTest(case_id=case_id):
                device = SimulatedSocket()
                with patch('core.connection.socket.create_connection', return_value=device), patch(
                    'threading.Event.wait', return_value=False
                ):
                    run = FuzzTestRunner().run('192.0.2.10', 'Lab', True, fuzz_authorized=True, case_id=case_id)
                self.assertEqual(device.commands, [0x65, 0x6F, 0x66])
                self.assertEqual(device.requests[1][40:], request)
                self.assertEqual(run['selected_case'], case_id)
                for result in run['test_results']:
                    if result['id'] == case_id:
                        self.assertEqual(result['status'], 'observed')
                    else:
                        self.assertEqual(result['status'], 'not_run')
                        self.assertEqual(result['detail'], 'Not selected for this run.')

    def test_invalid_fuzz_case_is_rejected_before_connection(self):
        with patch('core.connection.socket.create_connection') as connect, self.assertRaises(ValueError):
            FuzzTestRunner().run('192.0.2.10', 'Lab', True, fuzz_authorized=True, case_id='FUZ-99')
        connect.assert_not_called()

    def test_progress_reports_fuzz_case_results(self):
        messages = []
        with patch('core.connection.socket.create_connection', return_value=SimulatedSocket()), patch(
            'threading.Event.wait', return_value=False
        ):
            FuzzTestRunner().run('192.0.2.10', 'Lab', True, fuzz_authorized=True, progress=messages.append)
        self.assertTrue(any(message.startswith('FUZ-01: starting') for message in messages))
        self.assertTrue(any(message.startswith('FUZ-01: observed') for message in messages))

    def test_authorization_and_cancel_precede_connection(self):
        with patch('core.connection.socket.create_connection') as connect:
            with self.assertRaises(ValueError):
                FuzzTestRunner().run('192.0.2.10', 'Lab', False)
            with self.assertRaises(ValueError):
                FuzzTestRunner().run('192.0.2.10', 'Lab', True)
            cancel = threading.Event()
            cancel.set()
            run = FuzzTestRunner().run('192.0.2.10', 'Lab', True, cancel, fuzz_authorized=True)
            connect.assert_not_called()
        self.assertEqual(run['outcome'], 'cancelled')
        self.assertTrue(all(result['status'] == 'not_run' for result in run['test_results']))

    def test_timeout_stops_without_retry_or_more_cases(self):
        device = SimulatedSocket()
        original_recv = device.recv
        def recv(size):
            if device.commands[-1] == 0x6F:
                raise TimeoutError('timed out')
            return original_recv(size)
        with patch.object(device, 'recv', side_effect=recv):
            run = self.run_device(device)
        self.assertEqual(run['outcome'], 'incomplete')
        self.assertEqual(device.commands, [0x65, 0x6F])
        self.assertEqual(run['test_results'][0]['status'], 'inconclusive')
        self.assertTrue(all(result['status'] == 'not_run' for result in run['test_results'][1:]))
        self.assertTrue(device.closed)

    def test_cip_rejections_are_observations_not_security_findings(self):
        device = SimulatedSocket()
        original_send = device.sendall
        def reject(request):
            original_send(request)
            if HEADER.unpack(request[:24])[0] == 0x6F:
                packet = bytearray(device.buffer)
                packet[42] = 0x05
                device.buffer = bytes(packet)
        with patch.object(device, 'sendall', side_effect=reject):
            run = self.run_device(device)
        self.assertEqual(run['outcome'], 'completed')
        self.assertTrue(all(result['status'] == 'observed' and result['general_status'] == '0x05'
                            for result in run['test_results']))

    def test_malformed_cip_response_stops_further_fuzz_requests(self):
        device = SimulatedSocket()
        original_send = device.sendall
        def corrupt(request):
            original_send(request)
            if HEADER.unpack(request[:24])[0] == 0x6F:
                packet = bytearray(device.buffer)
                packet[40] = 0x8F
                device.buffer = bytes(packet)
        with patch.object(device, 'sendall', side_effect=corrupt):
            run = self.run_device(device)
        self.assertEqual(run['outcome'], 'incomplete')
        self.assertEqual(device.commands, [0x65, 0x6F, 0x66])
        self.assertEqual(run['test_results'][0]['status'], 'protocol_anomaly')
        self.assertTrue(all(result['status'] == 'not_run' for result in run['test_results'][1:]))

    def test_cancel_after_request_attempts_cleanup(self):
        device = SimulatedSocket()
        cancel = threading.Event()
        original_send = device.sendall
        def send_and_cancel(request):
            original_send(request)
            if HEADER.unpack(request[:24])[0] == 0x6F:
                cancel.set()
        with patch.object(device, 'sendall', side_effect=send_and_cancel):
            run = self.run_device(device, cancel)
        self.assertEqual(run['outcome'], 'cancelled')
        self.assertEqual(device.commands, [0x65, 0x6F, 0x66])
        self.assertEqual(run['test_results'][1]['status'], 'not_run')

    def test_budget_expiry_after_pacing_sends_no_fuzz_request(self):
        device = SimulatedSocket()
        with patch('core.connection.socket.create_connection', return_value=device), patch(
            'modules.fuzz_tests.time.monotonic', return_value=0.0
        ) as clock:
            def expire(_delay):
                clock.return_value = 61.0
                return False
            with patch('threading.Event.wait', side_effect=expire):
                run = FuzzTestRunner().run('192.0.2.10', 'Lab', True, fuzz_authorized=True)
        self.assertEqual(device.commands, [0x65, 0x66])
        self.assertEqual(run['outcome'], 'incomplete')
        self.assertIn('budget', run['stop_reason'])


class SelectedSuiteTests(unittest.TestCase):
    def test_multiple_fuzz_cases_use_one_session(self):
        device = SimulatedSocket()
        with patch('core.connection.socket.create_connection', return_value=device), patch(
            'threading.Event.wait', return_value=False
        ):
            run = FuzzTestRunner().run('192.0.2.10', 'Lab', True, fuzz_authorized=True,
                                       case_ids=('FUZ-01', 'FUZ-04'))
        self.assertEqual(device.commands, [0x65, 0x6F, 0x6F, 0x66])
        self.assertEqual([device.requests[1][40:], device.requests[2][40:]],
                         [FUZZ_CASES[0][2], FUZZ_CASES[3][2]])
        self.assertEqual(run['selected_cases'], ['FUZ-01', 'FUZ-04'])
        self.assertEqual(run['test_results'][1]['detail'], 'Not selected for this run.')

    def test_mixed_results_combine_evidence_and_selected_cases(self):
        baseline, fuzz = DeviceSocket(), SimulatedSocket()
        selected = ('ENIP-01', 'CIP-03', 'FUZ-02', 'FUZ-04')
        with patch('core.connection.socket.create_connection', side_effect=[baseline, fuzz]), patch(
            'threading.Event.wait', return_value=False
        ):
            run = SelectedTestRunner().run('192.0.2.10', 'Lab', True, selected, fuzz_authorized=True)
        self.assertEqual(baseline.commands, [0x63, 0x65, 0x6F, 0x66])
        self.assertEqual(fuzz.commands, [0x65, 0x6F, 0x6F, 0x66])
        self.assertEqual(run['outcome'], 'completed')
        self.assertEqual(run['selected_cases'], list(selected))
        self.assertEqual(len(run['exchanges']), 8)
        results = {item['id']: item for item in run['test_results']}
        self.assertEqual(results['FUZ-02']['exchange_indices'], [5])
        self.assertEqual(results['FUZ-04']['exchange_indices'], [6])
        self.assertEqual(results['CIP-04']['status'], 'not_run')
        self.assertEqual(results['FUZ-01']['status'], 'not_run')

    def test_mixed_authorization_and_invalid_cases_block_all_traffic(self):
        with patch('core.connection.socket.create_connection') as connect:
            with self.assertRaises(ValueError):
                SelectedTestRunner().run('192.0.2.10', 'Lab', True, ('CIP-01', 'FUZ-01'))
            with self.assertRaises(ValueError):
                SelectedTestRunner().run('192.0.2.10', 'Lab', True, ('CIP-01', 'ETH-AUTH-001'),
                                         fuzz_authorized=True)
            with self.assertRaises(ValueError):
                SelectedTestRunner().run('192.0.2.10', 'Lab', True, ('CIP-01', 'CIP-01'))
            connect.assert_not_called()

    def test_mixed_run_stops_before_fuzz_on_baseline_failure(self):
        device = DeviceSocket()
        with patch('core.connection.socket.create_connection', return_value=device) as connect, patch.object(
            device, 'recv', side_effect=TimeoutError('timed out')
        ), patch('threading.Event.wait', return_value=False):
            run = SelectedTestRunner().run('192.0.2.10', 'Lab', True, ('ENIP-01', 'FUZ-01'),
                                           fuzz_authorized=True)
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(device.commands, [0x63])
        self.assertEqual(run['outcome'], 'incomplete')
        fuzz = next(item for item in run['test_results'] if item['id'] == 'FUZ-01')
        self.assertEqual(fuzz['status'], 'not_run')
        self.assertIn('Fuzz phase not started', fuzz['detail'])

    def test_mixed_run_stops_before_fuzz_if_cleanup_fails(self):
        device = DeviceSocket()
        original_send = device.sendall
        def fail_cleanup(request):
            if HEADER.unpack(request[:24])[0] == 0x66:
                raise OSError('cleanup failed')
            original_send(request)
        with patch.object(device, 'sendall', side_effect=fail_cleanup), patch(
            'core.connection.socket.create_connection', return_value=device
        ) as connect, patch('threading.Event.wait', return_value=False):
            run = SelectedTestRunner().run('192.0.2.10', 'Lab', True, ('CIP-01', 'FUZ-01'),
                                           fuzz_authorized=True)
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(run['outcome'], 'incomplete')
        self.assertIn('cleanup failed', run['stop_reason'])
        fuzz = next(item for item in run['test_results'] if item['id'] == 'FUZ-01')
        self.assertEqual(fuzz['status'], 'not_run')

    def test_cancellation_between_phases_does_not_start_fuzz(self):
        device = DeviceSocket()
        cancel = threading.Event()
        def progress(message):
            if message.startswith('Waiting one second'):
                cancel.set()
        with patch('core.connection.socket.create_connection', return_value=device) as connect, patch(
            'threading.Event.wait', return_value=False
        ):
            run = SelectedTestRunner().run('192.0.2.10', 'Lab', True, ('ENIP-01', 'FUZ-01'),
                                           cancel, fuzz_authorized=True, progress=progress)
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(run['outcome'], 'cancelled')
        self.assertIn('before the fuzz phase', run['stop_reason'])


if __name__ == '__main__':
    unittest.main()