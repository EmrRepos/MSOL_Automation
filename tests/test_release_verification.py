import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import Mock, patch


@unittest.skipUnless(importlib.util.find_spec("PyInstaller"), "Build dependency not installed")
class ReleaseVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from release_tools import verify_archives
        cls.verifier = verify_archives

    def check(self, modules, files):
        archive = Mock()
        archive.toc = {name: None for name in files}
        archive.open_embedded_archive.return_value.toc = {name: None for name in modules}
        with patch.object(self.verifier, "CArchiveReader", return_value=archive):
            with contextlib.redirect_stdout(io.StringIO()):
                self.verifier.check_bundle(
                    Path("USB.exe"), {"plugins", "plugins.descriptor_test"},
                    {"device_profiles/generic_serial.json"},
                )

    def test_complete_bundle_is_accepted(self):
        self.check(
            {"plugins", "plugins.descriptor_test"},
            {"device_profiles\\generic_serial.json"},
        )

    def test_missing_usb_plugin_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "module plugins.descriptor_test"):
            self.check({"plugins"}, {"device_profiles/generic_serial.json"})

    def test_missing_profile_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "file device_profiles/generic_serial.json"):
            self.check({"plugins", "plugins.descriptor_test"}, set())


if __name__ == "__main__":
    unittest.main()
