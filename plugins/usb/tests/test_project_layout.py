import ast
import importlib
from pathlib import Path
import unittest

from core import device_profile


ROOT = Path(__file__).resolve().parents[1]
CORE_MODULES = {
    "com_port_manager", "database", "device_manager", "device_profile",
    "findings", "firmware_capture", "hardware_helpers", "packet_analysis",
    "plugin_loader", "report_generator", "serial_evidence", "test_runner",
    "test_suite", "theme", "usb_class_mapper",
}


class ProjectLayoutTests(unittest.TestCase):
    def test_only_entry_point_remains_in_root(self):
        self.assertEqual({path.name for path in ROOT.glob("*.py")}, {"main.py"})
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
