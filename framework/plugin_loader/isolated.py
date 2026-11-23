"""Run existing framework applications in separate Python processes."""

import subprocess
import sys
from pathlib import Path

from .base import FrameworkPlugin


class IsolatedApplicationPlugin(FrameworkPlugin):
    entry_point: Path
    accepts_arguments = False

    def initialize(self) -> None:
        if not self.entry_point.is_file():
            raise FileNotFoundError(f"Plugin entry point not found: {self.entry_point}")
        if self.arguments and not self.accepts_arguments:
            raise ValueError("This plugin does not accept command-line arguments.")

    def execute_tests(self) -> int:
        return subprocess.run(
            [sys.executable, "-B", str(self.entry_point), *self.arguments],
            check=False,
        ).returncode

    def shutdown(self) -> None:
        pass
