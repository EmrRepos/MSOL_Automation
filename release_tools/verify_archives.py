"""Check release bundles for application modules and required runtime assets."""

import sys
from pathlib import Path

from PyInstaller.archive.readers import CArchiveReader


ROOT = Path(__file__).resolve().parents[1]


def check_bundle(path, required_modules, required_files):
    archive = CArchiveReader(str(path))
    modules = archive.open_embedded_archive("PYZ.pyz").toc
    files = {name.replace("\\", "/") for name in archive.toc}
    missing = sorted(
        [f"module {name}" for name in required_modules if name not in modules]
        + [f"file {name}" for name in required_files if name not in files]
    )
    if missing:
        raise ValueError(f"{path.name} is missing: {', '.join(missing)}")
    print(f"Verified bundled modules and resources: {path.name}")


def main(output):
    usb_root = ROOT / "plugins" / "usb"
    plugin_files = tuple((usb_root / "plugins").glob("*.py"))
    profile_files = tuple((usb_root / "device_profiles").glob("*.json"))
    if not plugin_files or not profile_files:
        raise ValueError("USB plugin modules or device profiles were not found.")
    usb_modules = {"plugins"} | {
        f"plugins.{path.stem}" for path in plugin_files if path.stem != "__init__"
    }
    usb_files = {f"device_profiles/{path.name}" for path in profile_files}
    usb_files.update({"libusb_package/libusb-1.0.dll", "PySide6/QtWidgets.pyd"})
    check_bundle(output / "USB.exe", usb_modules, usb_files)
    check_bundle(
        output / "Ethernetip.exe",
        {"ui", "modules.discovery", "modules.live_tests", "modules.fuzz_tests",
         "reports.report", "reports.pdf"},
        {"_tkinter.pyd"},
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python verify_archives.py <release directory>")
    main(Path(sys.argv[1]))
