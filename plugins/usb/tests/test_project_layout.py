import ast
import importlib
import os
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
import unittest
from unittest.mock import patch

from core import database, device_profile


ROOT = Path(__file__).resolve().parents[1]
CORE_MODULES = {
    "com_port_manager", "database", "device_manager", "device_profile",
    "findings", "firmware_capture", "hardware_helpers", "packet_analysis",
    "plugin_loader", "report_generator", "report_paths", "serial_evidence", "test_runner",
    "test_suite", "theme", "usb_class_mapper",
}


class ProjectLayoutTests(unittest.TestCase):
    def test_entry_points_and_package_initializer_remain_in_root(self):
        self.assertEqual(
            {path.name for path in ROOT.glob("*.py")},
            {"__init__.py", "main.py", "plugin.py"},
        )
        self.assertTrue((ROOT / "core" / "__init__.py").is_file())
        self.assertEqual(
            {path.stem for path in (ROOT / "core").glob("*.py")} - {"__init__"},
            CORE_MODULES,
        )

    def test_every_core_module_imports_from_its_package(self):
        for module in sorted(CORE_MODULES):
            with self.subTest(module=module):
                imported = importlib.import_module(f"core.{module}")
                self.assertEqual(Path(imported.__file__).resolve(), ROOT / "core" / f"{module}.py")

    def test_device_profiles_still_resolve_to_root_assets(self):
        self.assertEqual(Path(device_profile.PROFILE_DIR), ROOT / "device_profiles")
        profiles = device_profile.load_profiles()
        self.assertTrue(profiles)
        self.assertIn("generic_serial.json", {profile["_source"] for profile in profiles})

    def test_source_history_uses_usb_directory_from_any_working_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            usb = root / "plugins" / "usb"
            core = usb / "core"
            core.mkdir(parents=True)
            target = usb / "usb_tests.db"
            old_database = root / "usb_tests.db"
            old_database.write_bytes(b"existing history")
            old_cwd = os.getcwd()
            try:
                os.chdir(root)
                with patch.object(database, "__file__", str(core / "database.py")), \
                     patch.object(database.sys, "frozen", False, create=True):
                    history = database.TestHistoryDB()
                    history.save_result("first", "device", "profile", "PASS")
                    second = database.TestHistoryDB()
                    second.save_result("second", "device", "profile", "FAIL")
                self.assertEqual(history.path, target)
                self.assertEqual(old_database.read_bytes(), b"existing history")
                with closing(sqlite3.connect(target)) as connection:
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM test_history").fetchone()[0], 2)
            finally:
                os.chdir(old_cwd)

    def test_frozen_history_uses_persistent_local_app_data(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(database.sys, "frozen", True, create=True), \
                 patch.dict(os.environ, {"LOCALAPPDATA": folder}):
                history = database.TestHistoryDB()
                history.save_result("now", "device", "profile", "PASS")
            target = Path(folder) / "USB_Pentest_Framework" / "usb_tests.db"
            self.assertEqual(history.path, target)
            with closing(sqlite3.connect(target)) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM test_history").fetchone()[0], 1)

    def test_no_source_imports_removed_root_modules(self):
        sources = [ROOT / "main.py"]
        for folder in ("core", "ui", "plugins", "tests"):
            sources.extend((ROOT / folder).rglob("*.py"))
        for source in sources:
            tree = ast.parse(source.read_bytes(), filename=str(source))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    imports = [node.module.split(".")[0]] if node.module else []
                else:
                    continue
                with self.subTest(source=str(source.relative_to(ROOT)), line=node.lineno):
                    self.assertFalse(CORE_MODULES.intersection(imports))
