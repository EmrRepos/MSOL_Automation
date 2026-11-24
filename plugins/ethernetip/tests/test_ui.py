import tkinter as tk
import unittest
from unittest.mock import patch

from ui import AssessmentApp


class UITests(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = AssessmentApp(self.root)

    def tearDown(self):
        self.root.destroy()

    def test_sample_review_and_report_without_network(self):
        with patch('modules.discovery.socket.create_connection') as connect:
            self.app.load_sample()
            self.app.catalog.selection_set('EIP-01')
            self.app._select_surface()
            self.app.review_status.set('Needs review')
            self.app.notes.insert('1.0', 'Synthetic review evidence')
            self.app.save_review()
            report = self.app.build_report()
            connect.assert_not_called()
        self.assertEqual(report['scope']['mode'], 'sample')
        self.assertFalse(report['scope']['authorization_attested'])
        self.assertEqual(report['attack_surface_reviews'][0]['status'], 'Needs review')

    def test_changed_scope_cannot_relabel_evidence(self):
        self.app.load_sample()
        self.app.target.set('192.0.2.11')
        with self.assertRaisesRegex(ValueError, 'Scope changed'):
            self.app.build_report()

    def test_unauthorized_probe_never_opens_socket(self):
        self.app.operator.set('Tester / lab ticket')
        with patch('ui.messagebox.showerror') as error, patch('modules.discovery.socket.create_connection') as connect:
            self.app.start_probe()
            error.assert_called_once()
            connect.assert_not_called()

    def test_queued_error_is_inconclusive(self):
        self.app.events.put(('error', 'timed out'))
        self.app._poll()
        self.assertFalse(self.app.busy)
        self.assertIn('inconclusive', self.app.outcome)
        self.assertEqual(self.app.assessment.observations(self.app.identities), [])

    def test_queued_suite_error_identifies_the_failed_operation(self):
        self.app.events.put(('suite_error', 'unexpected failure'))
        self.app._poll()
        self.assertIn('Suite failed', self.app.outcome)
        self.assertIn('unexpected failure', self.app.outcome)

    def test_unsaved_notes_are_not_lost_on_selection(self):
        self.app.catalog.selection_set('EIP-01')
        self.app._select_surface()
        self.app.notes.insert('1.0', 'Unsaved evidence')
        self.app.catalog.selection_set('EIP-02')
        with patch('ui.messagebox.askyesno', return_value=False):
            self.app._select_surface()
            self.app._select_surface()
        self.assertEqual(self.app.selected, 'EIP-01')
        self.assertEqual(self.app.notes.get('1.0', 'end').strip(), 'Unsaved evidence')

    def test_live_probe_scope_busy_state_and_success(self):
        self.app.operator.set('Tester / lab ticket')
        self.app.authorized.set(True)
        with patch('ui.messagebox.askyesno', return_value=True), patch('ui.threading.Thread') as thread:
            self.app.start_probe()
            self.assertTrue(self.app.busy)
            self.assertEqual(str(self.app.target_entry.cget('state')), 'disabled')
            self.app.start_probe()
            thread.assert_called_once()
        self.app.events.put(('success', []))
        self.app._poll()
        self.assertFalse(self.app.busy)
        self.assertIn('inconclusive', self.app.outcome)
        self.app.authorized.set(False)
        report = self.app.build_report()
        self.assertEqual(report['scope']['mode'], 'live')
        self.assertTrue(report['scope']['authorization_attested'])
        self.assertIsNotNone(report['scope']['observed_at_utc'])

    def test_desktop_window_layout(self):
        self.root.deiconify()
        for width, height in ((1180, 820), (820, 650)):
            self.root.geometry(f'{width}x{height}')
            self.root.update()
            for widget in (self.app.probe_button, self.app.export_button, self.app.surface_button,
                           self.app.suite_button, self.app.stop_button, self.app.fuzz_button,
                           self.app.selected_button,
                           self.app.live_tree, self.app.live_details, self.app.inventory):
                with self.subTest(size=(width, height), widget=widget):
                    self.assertTrue(widget.winfo_ismapped())
                    self.assertGreater(widget.winfo_height(), 20)
                    self.assertLessEqual(widget.winfo_rootx() + widget.winfo_width(),
                                         self.root.winfo_rootx() + self.root.winfo_width())
                    self.assertLessEqual(widget.winfo_rooty() + widget.winfo_height(),
                                         self.root.winfo_rooty() + self.root.winfo_height())
            self.assertLessEqual(self.app.live_tree.winfo_rootx() + self.app.live_tree.winfo_width(),
                                 self.app.inventory.winfo_rootx())
        self.app.surface_button.invoke()
        self.root.update()
        self.assertTrue(self.app.catalog.winfo_ismapped())
        self.assertTrue(self.app.notes.winfo_ismapped())
        self.assertTrue(self.app.save_button.winfo_ismapped())

    def test_surface_window_preserves_unsaved_review_when_hidden(self):
        self.app.show_surface()
        self.app.catalog.selection_set('EIP-01')
        self.app._select_surface()
        self.app.notes.insert('1.0', 'Unsaved evidence')
        self.app.surface_window.withdraw()
        self.app.show_surface()
        self.assertEqual(self.app.notes.get('1.0', 'end').strip(), 'Unsaved evidence')

    def test_progress_events_do_not_finish_run_or_erase_logs(self):
        import threading
        from modules.live_tests import LiveTestRunner
        self.app.operator.set('Lab / ticket')
        self.app.authorized.set(True)
        with patch('ui.messagebox.askyesno', return_value=True), patch('ui.threading.Thread'):
            self.app.start_suite()
        self.app.events.put(('progress', 'ENIP-01: starting identity test'))
        self.app._poll()
        self.assertTrue(self.app.busy)
        self.assertIn('ENIP-01: starting identity test', self.app.inventory.get('1.0', 'end'))
        cancel = threading.Event()
        cancel.set()
        run = LiveTestRunner().run('192.0.2.10', 'Lab / ticket', True, cancel)
        self.app.events.put(('suite', run))
        self.app._poll()
        self.assertFalse(self.app.busy)
        self.assertIn('ENIP-01: starting identity test', self.app.inventory.get('1.0', 'end'))
        self.assertIn('cancelled', self.app.inventory.get('1.0', 'end'))

    def test_worker_progress_reaches_live_logs(self):
        import threading
        from test_protocol import SimulatedSocket
        self.app.operator.set('Lab / ticket')
        self.app.authorized.set(True)
        with patch('ui.messagebox.askyesno', return_value=True), patch('ui.threading.Thread'):
            self.app.start_fuzz()
        with patch('core.connection.socket.create_connection', return_value=SimulatedSocket()), patch(
            'threading.Event.wait', return_value=False
        ):
            self.app._suite_worker('192.0.2.10', 'Lab / ticket', threading.Event(), True)
        self.app._poll()
        logs = self.app.inventory.get('1.0', 'end')
        self.assertIn('FUZ-01: starting', logs)
        self.assertIn('FUZ-01: observed', logs)
        self.assertIn('Live suite completed', logs)
        self.assertFalse(self.app.busy)

    def test_live_suite_results_and_stop(self):
        import threading
        from modules.live_tests import LiveTestRunner
        self.app.operator.set('Lab / ticket')
        self.app.authorized.set(True)
        with patch('ui.messagebox.askyesno', return_value=True), patch('ui.threading.Thread'):
            self.app.start_suite()
        self.assertTrue(self.app.busy)
        self.app.stop_suite()
        self.assertTrue(self.app.cancel_run.is_set())
        cancel = threading.Event()
        cancel.set()
        run = LiveTestRunner().run('192.0.2.10', 'Lab / ticket', True, cancel)
        self.app.events.put(('suite', run))
        self.app._poll()
        self.assertFalse(self.app.busy)
        self.assertEqual(self.app.build_report()['live_test_run']['outcome'], 'cancelled')
        self.app.live_tree.selection_set('CIP-01')
        self.app._select_live_test()
        self.assertIn('not_run', self.app.live_details.get('1.0', 'end'))

    def test_single_live_selection_starts_only_selected_case(self):
        self.app.operator.set('Lab / ticket')
        self.app.authorized.set(True)
        self.app.live_tree.selection_set('CIP-03')
        with patch('ui.messagebox.askyesno', return_value=True) as confirm, patch('ui.threading.Thread') as thread:
            self.app.start_selected()
        self.assertIn('CIP-03', confirm.call_args.args[1])
        self.assertEqual(thread.call_args.kwargs['args'][3:], (False, ('CIP-03',)))
        self.assertTrue(self.app.busy)
        self.assertEqual(str(self.app.selected_button.cget('state')), 'disabled')

    def test_selected_case_results_reach_ui_and_report(self):
        from test_live_tests import DeviceSocket
        self.app.operator.set('Lab / ticket')
        self.app.authorized.set(True)
        self.app.live_tree.selection_set('CIP-03')
        with patch('ui.messagebox.askyesno', return_value=True), patch('ui.threading.Thread') as thread:
            self.app.start_selected()
        device = DeviceSocket()
        with patch('core.connection.socket.create_connection', return_value=device), patch(
            'threading.Event.wait', return_value=False
        ):
            self.app._suite_worker(*thread.call_args.kwargs['args'])
        self.app._poll()
        self.assertEqual(device.commands, [0x65, 0x6F, 0x66])
        self.assertEqual(self.app.live_tree.item('CIP-03', 'values')[1], 'observed')
        self.assertEqual(self.app.live_tree.item('CIP-04', 'values')[1], 'not_run')
        report = self.app.build_report()
        self.assertEqual(report['live_test_run']['selected_case'], 'CIP-03')
        self.assertEqual(report['reproduction']['cli_arguments'][-2:], ['--case', 'CIP-03'])

    def test_selected_fuzz_case_requires_separate_confirmation(self):
        self.app.operator.set('Lab / ticket')
        self.app.authorized.set(True)
        self.app.live_tree.selection_set('FUZ-02')
        with patch('ui.messagebox.askyesno', return_value=False) as confirm, patch('ui.threading.Thread') as thread:
            self.app.start_selected()
        self.assertIn('FUZ-02', confirm.call_args.args[1])
        self.assertIn('Fuzzing can crash', confirm.call_args.args[1])
        thread.assert_not_called()
        with patch('ui.messagebox.askyesno', return_value=True), patch('ui.threading.Thread') as thread:
            self.app.start_selected()
        self.assertEqual(thread.call_args.kwargs['args'][3:], (True, ('FUZ-02',)))

    def test_multiple_cases_can_be_selected_and_run_together(self):
        from test_live_tests import DeviceSocket
        self.app.operator.set('Lab / ticket')
        self.app.authorized.set(True)
        self.app.live_tree.selection_set(('CIP-02', 'CIP-04'))
        with patch('ui.messagebox.askyesno', return_value=True) as confirm, patch('ui.threading.Thread') as thread:
            self.app.start_selected()
        self.assertIn('CIP-02', confirm.call_args.args[1])
        self.assertIn('CIP-04', confirm.call_args.args[1])
        device = DeviceSocket()
        with patch('core.connection.socket.create_connection', return_value=device), patch(
            'threading.Event.wait', return_value=False
        ):
            self.app._suite_worker(*thread.call_args.kwargs['args'])
        self.app._poll()
        self.assertEqual(device.commands, [0x65, 0x6F, 0x6F, 0x66])
        self.assertEqual([device.requests[1][-1], device.requests[2][-1]], [2, 4])
        report = self.app.build_report()
        self.assertEqual(report['live_test_run']['selected_cases'], ['CIP-02', 'CIP-04'])
        self.assertEqual(self.app.live_tree.item('CIP-02', 'values')[1], 'observed')
        self.assertEqual(self.app.live_tree.item('CIP-04', 'values')[1], 'observed')
        self.assertEqual(self.app.live_tree.item('CIP-03', 'values')[1], 'not_run')

    def test_ctrl_click_selects_multiple_test_rows(self):
        self.root.deiconify()
        self.root.update()
        tree = self.app.live_tree
        tree.see('CIP-03')
        self.root.update()
        for identifier, control in (('CIP-01', False), ('CIP-03', True)):
            x, y, width, height = tree.bbox(identifier)
            event = '<Control-Button-1>' if control else '<Button-1>'
            release = '<Control-ButtonRelease-1>' if control else '<ButtonRelease-1>'
            tree.event_generate(event, x=x + 5, y=y + height // 2)
            tree.event_generate(release, x=x + 5, y=y + height // 2)
            self.root.update()
        self.assertEqual(set(tree.selection()), {'CIP-01', 'CIP-03'})

    def test_mixed_selection_requires_additional_fuzz_confirmation(self):
        self.app.operator.set('Lab / ticket')
        self.app.authorized.set(True)
        self.app.live_tree.selection_set(('CIP-01', 'FUZ-02'))
        with patch('ui.messagebox.askyesno', side_effect=[True, False]) as confirm, patch('ui.threading.Thread') as thread:
            self.app.start_selected()
        self.assertEqual(confirm.call_count, 2)
        self.assertIn('Fuzzing can crash', confirm.call_args_list[1].args[1])
        thread.assert_not_called()
        with patch('ui.messagebox.askyesno', side_effect=[True, True]), patch('ui.threading.Thread') as thread:
            self.app.start_selected()
        self.assertEqual(thread.call_args.kwargs['args'][3:], (False, ('CIP-01', 'FUZ-02'), True))

    def test_mixed_selection_results_and_report_cover_both_phases(self):
        from test_live_tests import DeviceSocket
        from test_protocol import SimulatedSocket
        self.app.operator.set('Lab / ticket')
        self.app.authorized.set(True)
        self.app.live_tree.selection_set(('CIP-01', 'FUZ-02'))
        with patch('ui.messagebox.askyesno', side_effect=[True, True]), patch('ui.threading.Thread') as thread:
            self.app.start_selected()
        baseline, fuzz = DeviceSocket(), SimulatedSocket()
        with patch('core.connection.socket.create_connection', side_effect=[baseline, fuzz]), patch(
            'threading.Event.wait', return_value=False
        ):
            self.app._suite_worker(*thread.call_args.kwargs['args'])
        self.app._poll()
        self.assertEqual(self.app.live_tree.item('CIP-01', 'values')[1], 'observed')
        self.assertEqual(self.app.live_tree.item('FUZ-02', 'values')[1], 'observed')
        self.assertEqual(self.app.build_report()['live_test_run']['selected_cases'], ['CIP-01', 'FUZ-02'])
        self.app.live_tree.selection_set('FUZ-02')
        self.app._select_live_test()
        self.assertIn('"command": "0x006F"', self.app.live_details.get('1.0', 'end'))

    def test_non_executable_row_blocks_entire_multiple_selection(self):
        self.app.live_tree.selection_set(('CIP-01', 'ETH-AUTH-001'))
        with patch('ui.messagebox.showinfo') as info, patch('ui.threading.Thread') as thread:
            self.app.start_selected()
        self.assertIn('ETH-AUTH-001', info.call_args.args[1])
        thread.assert_not_called()

    def test_no_selection_or_non_executable_case_does_not_start_test(self):
        with patch('ui.messagebox.showinfo') as info, patch('ui.threading.Thread') as thread:
            self.app.start_selected()
            self.app.live_tree.selection_set('ETH-AUTH-001')
            self.app.start_selected()
        self.assertEqual(info.call_count, 2)
        thread.assert_not_called()

    def test_fuzz_requires_authorization_and_confirmation(self):
        self.app.operator.set('Lab / ticket')
        with patch('ui.messagebox.showerror'), patch('ui.threading.Thread') as thread:
            self.app.start_fuzz()
            thread.assert_not_called()
        self.app.authorized.set(True)
        with patch('ui.messagebox.askyesno', return_value=False), patch('ui.threading.Thread') as thread:
            self.app.start_fuzz()
            thread.assert_not_called()
        with patch('ui.messagebox.askyesno', return_value=True), patch('ui.threading.Thread') as thread:
            self.app.start_fuzz()
            self.assertTrue(self.app.busy)
            self.assertTrue(thread.call_args.kwargs['args'][3])
        self.app.stop_suite()
        self.assertTrue(self.app.cancel_run.is_set())

    def test_fuzz_results_are_visible_and_exportable(self):
        import threading
        from modules.fuzz_tests import FuzzTestRunner
        self.app.operator.set('Lab / ticket')
        self.app.authorized.set(True)
        with patch('ui.messagebox.askyesno', return_value=True), patch('ui.threading.Thread'):
            self.app.start_fuzz()
        cancel = threading.Event()
        cancel.set()
        run = FuzzTestRunner().run('192.0.2.10', 'Lab / ticket', True, cancel, fuzz_authorized=True)
        self.app.events.put(('suite', run))
        self.app._poll()
        self.app.live_tree.selection_set('FUZ-01')
        self.app._select_live_test()
        self.assertIn('not_run', self.app.live_details.get('1.0', 'end'))
        report = self.app.build_report()
        self.assertEqual(report['scope']['request'], 'Bounded CIP fuzz suite')
        self.assertTrue(report['live_test_run']['fuzz_authorization_attested'])

    def test_close_during_run_waits_for_cleanup(self):
        self.app._set_busy(True)
        with patch('ui.messagebox.askyesno', return_value=True), patch.object(self.root, 'destroy') as destroy:
            self.app.close_window()
            self.assertTrue(self.app.cancel_run.is_set())
            self.assertTrue(self.app.closing)
            destroy.assert_not_called()
            self.app.events.put(('error', 'Cancelled before connection'))
            self.app._poll()
            destroy.assert_called_once()


if __name__ == '__main__':
    unittest.main()