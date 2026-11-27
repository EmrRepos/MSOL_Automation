import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import launcher
from framework.plugin_loader import FrameworkPlugin, discover_plugins, load_plugin


ROOT = Path(__file__).resolve().parents[1]


class LauncherTests(unittest.TestCase):
    def test_discovery_does_not_import_applications(self):
        with patch("framework.plugin_loader.loader.importlib.import_module") as import_module:
            self.assertTrue({"ethernetip", "usb"}.issubset(discover_plugins()))
            import_module.assert_not_called()

    def test_selected_plugin_is_loaded_and_arguments_are_preserved(self):
        plugin = load_plugin("ethernetip", ["assess"])
        self.assertIsInstance(plugin, FrameworkPlugin)
        self.assertEqual(plugin.arguments, ["assess"])

    def test_discovery_finds_new_plugin_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin_dir = Path(directory) / "new_plugin"
            plugin_dir.mkdir()
            (plugin_dir / "__init__.py").touch()
            (plugin_dir / "plugin.py").touch()
            (Path(directory) / "not_a_plugin").mkdir()
            with patch("framework.plugin_loader.loader.PLUGIN_DIRECTORY", Path(directory)):
                self.assertEqual(discover_plugins(), ["new_plugin"])

    def test_shutdown_runs_after_execution_failure(self):
        plugin = Mock()
        plugin.execute_tests.side_effect = ValueError("execution failed")
        with patch.object(launcher, "load_plugin", return_value=plugin):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(launcher.main(["usb"]), 1)
        plugin.initialize.assert_called_once_with()
        plugin.execute_tests.assert_called_once_with()
        plugin.shutdown.assert_called_once_with()

    def test_shutdown_runs_after_initialization_failure(self):
        plugin = Mock()
        plugin.initialize.side_effect = OSError("initialization failed")
        with patch.object(launcher, "load_plugin", return_value=plugin):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(launcher.main(["usb"]), 1)
        plugin.execute_tests.assert_not_called()
        plugin.shutdown.assert_called_once_with()

    def test_usb_rejects_arguments_without_starting_child(self):
        with patch("framework.plugin_loader.isolated.subprocess.run") as run:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(launcher.main(["usb", "unexpected"]), 1)
            run.assert_not_called()

    def test_exit_code_is_propagated(self):
        plugin = Mock()
        plugin.execute_tests.return_value = 7
        with patch.object(launcher, "load_plugin", return_value=plugin):
            self.assertEqual(launcher.main(["ethernetip", "assess"]), 7)
        plugin.shutdown.assert_called_once_with()

    def test_offline_cli_works_from_another_working_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, "-B", str(ROOT / "launcher.py"), "ethernetip", "assess"],
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)[0]["identifier"], "EIP-01")

    def test_authorization_failure_is_preserved(self):
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "launcher.py"),
             "ethernetip", "test", "192.0.2.10"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires a target, --authorized", result.stderr)

    def test_unknown_plugin_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                launcher.main(["unknown"])
        self.assertEqual(error.exception.code, 2)

    def test_child_inherits_working_directory(self):
        plugin = load_plugin("usb", [])
        plugin.initialize()
        with patch("framework.plugin_loader.isolated.subprocess.run") as run:
            run.return_value.returncode = 0
            self.assertEqual(plugin.execute_tests(), 0)
        command = run.call_args.args[0]
        self.assertEqual(command[0], sys.executable)
        self.assertEqual(command[1], "-B")
        self.assertEqual(Path(command[2]), ROOT / "plugins" / "usb" / "main.py")
        self.assertNotIn("cwd", run.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
