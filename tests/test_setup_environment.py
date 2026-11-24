import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import setup_environment


class SetupEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "requirements.txt").touch()
        self.environment = self.root / ".venv"
        self.python = (self.environment / "Scripts" / "python.exe" if sys.platform == "win32"
                       else self.environment / "bin" / "python")

    def create_environment(self, path, with_pip):
        self.assertTrue(with_pip)
        self.python.parent.mkdir(parents=True)
        self.python.touch()
        (path / "pyvenv.cfg").touch()

    def test_creates_then_reuses_environment_and_installs(self):
        with patch("setup_environment.venv.create", side_effect=self.create_environment) as create, \
             patch("setup_environment.subprocess.run") as run:
            setup_environment.setup(self.root)
            setup_environment.setup(self.root)
        create.assert_called_once_with(self.environment, with_pip=True)
        install = [str(self.python), "-m", "pip", "install", "-r", str(self.root / "requirements.txt")]
        self.assertEqual([call.args[0] for call in run.call_args_list].count(install), 2)
        self.assertEqual(run.call_args_list[-1].args[0], [str(self.python), "-m", "pip", "check"])

    def test_existing_non_environment_is_not_overwritten(self):
        self.environment.mkdir()
        with patch("setup_environment.venv.create") as create, \
             patch("setup_environment.subprocess.run") as run:
            with self.assertRaisesRegex(RuntimeError, "not a valid virtual environment"):
                setup_environment.setup(self.root)
        create.assert_not_called()
        run.assert_not_called()

    def test_version_failure_prevents_install(self):
        self.create_environment(self.environment, True)
        failure = subprocess.CalledProcessError(1, "version check")
        with patch("setup_environment.subprocess.run", side_effect=failure) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                setup_environment.setup(self.root)
        self.assertEqual(run.call_count, 1)

    def test_install_failure_prevents_success_check(self):
        self.create_environment(self.environment, True)
        failure = subprocess.CalledProcessError(1, "pip")
        with patch("setup_environment.subprocess.run", side_effect=[None, failure]) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                setup_environment.setup(self.root)
        self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
