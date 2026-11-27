import threading
import unittest
from unittest.mock import Mock, call, patch

from core.test_runner import TestRunner
from core.test_suite import SUITE_NAME


DEVICE = {"name": "Synthetic device"}


class AutoFinishTests(unittest.TestCase):
    def setUp(self):
        with patch("core.test_runner.TestHistoryDB") as database, \
             patch("core.test_runner.ReportGenerator") as reporter:
            self.runner = TestRunner()
            self.database = database.return_value
            self.reporter = reporter.return_value

    def join_worker(self):
        worker = self.runner.worker_thread
        assert worker is not None
        worker.join(3)

    def start_profile(self, profile, status):
        if profile == SUITE_NAME:
            suite = patch("core.test_runner.ApplicableSuite")
            factory = suite.start()
            self.addCleanup(suite.stop)
            factory.return_value.run.return_value = {
                "status": status, "started": "now", "run_id": "id",
                "report_errors": [], "results": [],
            }
            return factory.return_value.run
        plugin = Mock()
        plugin.return_value.execute.return_value = {"status": status}
        self.runner.plugins[profile] = plugin
        return plugin.return_value.execute

    def test_completed_profiles_wait_ten_seconds_after_one_run_for_all_outcomes(self):
        for profile in (SUITE_NAME, "Descriptor Validation"):
            for status in ("PASS", "FAIL", "BLOCKED", "SKIPPED", "ERROR"):
                with self.subTest(profile=profile, status=status):
                    execute = self.start_profile(profile, status)
                    finished = Mock()
                    phases = []
                    with patch("core.test_runner.time.monotonic", return_value=100), \
                         patch.object(self.runner._stop_requested, "wait", return_value=False) as wait:
                        self.runner.start(
                            profile, DEVICE, Mock(), Mock(),
                            finished_callback=finished, phase_callback=phases.append,
                        )
                        self.join_worker()
                    self.assertFalse(self.runner.running)
                    finished.assert_called_once_with(status)
                    self.assertTrue(any("saving" in phase for phase in phases))
                    self.assertTrue(any("10 seconds" in phase for phase in phases))
                    execute.assert_called_once()
                    self.assertIn(call(10), wait.call_args_list)
                    if profile == SUITE_NAME:
                        result = self.runner.last_suite
                        assert result is not None
                        self.assertEqual(result["status"], status)

    def test_report_saving_time_counts_toward_post_check_wait(self):
        self.start_profile(SUITE_NAME, "PASS")
        with patch("core.test_runner.time.monotonic", side_effect=[100, 107]), \
             patch.object(self.runner._stop_requested, "wait", return_value=False) as wait:
            self.runner.start(SUITE_NAME, DEVICE, Mock(), Mock())
            self.join_worker()
        wait.assert_called_once_with(3)
        self.reporter.export_suite.assert_called_once()

    def test_stop_interrupts_wait_without_losing_completed_result(self):
        for profile in (SUITE_NAME, "Descriptor Validation"):
            with self.subTest(profile=profile):
                execute = self.start_profile(profile, "PASS")
                waiting = threading.Event()
                original_wait = self.runner._stop_requested.wait

                def wait(seconds):
                    if seconds > 1:
                        waiting.set()
                    return original_wait(seconds)

                with patch.object(self.runner._stop_requested, "wait", side_effect=wait):
                    self.runner.start(profile, DEVICE, Mock(), Mock())
                    try:
                        self.assertTrue(waiting.wait(5))
                        self.assertTrue(self.runner.running)
                        self.runner.stop()
                        self.join_worker()
                        self.assertFalse(self.runner.running)
                        execute.assert_called_once()
                        self.assertTrue(self.reporter.export_suite.called if profile == SUITE_NAME
                                        else self.reporter.export_pdf.called)
                    finally:
                        self.runner.stop()
                        self.join_worker()

    def test_manual_stop_does_not_unlock_while_profile_is_executing(self):
        entered = threading.Event()
        release = threading.Event()
        plugin = Mock()

        def execute(*args):
            entered.set()
            release.wait(5)
            return {"status": "PASS"}

        plugin.return_value.execute.side_effect = execute
        self.runner.plugins["Descriptor Validation"] = plugin
        with patch.object(self.runner._stop_requested, "wait", side_effect=lambda seconds: False):
            self.runner.start("Descriptor Validation", DEVICE, Mock(), Mock())
            try:
                self.assertTrue(entered.wait(3))
                self.runner.stop()
                self.assertTrue(self.runner.running)
                self.runner.start("Descriptor Validation", DEVICE, Mock(), Mock())
                plugin.assert_called_once()
            finally:
                release.set()
                self.join_worker()
        self.assertFalse(self.runner.running)

    def test_stop_after_profile_execution_still_saves_result(self):
        execute = self.start_profile("Descriptor Validation", "PASS")

        def progress(value):
            if value == 31:
                self.runner.stop()

        with patch.object(self.runner._stop_requested, "wait", return_value=False):
            self.runner.start("Descriptor Validation", DEVICE, Mock(), progress)
            self.join_worker()
        execute.assert_called_once()
        self.database.save_result.assert_called_once()
        self.reporter.export_pdf.assert_called_once()
        self.reporter.export_csv.assert_called_once()
        self.assertFalse(self.runner.running)

    def test_stop_during_initial_progress_does_not_execute_plugin(self):
        plugin = Mock()
        self.runner.plugins["Descriptor Validation"] = plugin

        def progress(value):
            if value == 30:
                self.runner.stop()

        finished = Mock()
        self.runner.start(
            "Descriptor Validation", DEVICE, Mock(), progress, finished_callback=finished
        )
        self.join_worker()
        plugin.assert_not_called()
        self.assertFalse(self.runner.running)
        finished.assert_called_once_with("CANCELLED")

    def test_execution_exception_is_reported_as_error(self):
        plugin = Mock()
        plugin.return_value.execute.side_effect = RuntimeError("device error")
        self.runner.plugins["Descriptor Validation"] = plugin
        finished, logger = Mock(), Mock()
        with patch.object(self.runner._stop_requested, "wait", return_value=False):
            self.runner.start(
                "Descriptor Validation", DEVICE, logger, Mock(), finished_callback=finished
            )
            self.join_worker()
        finished.assert_called_once_with("ERROR")
        self.assertTrue(any("device error" in args.args[0] for args in logger.call_args_list))


if __name__ == "__main__":
    unittest.main()
