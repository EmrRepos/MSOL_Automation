"""Lifecycle contract for a top-level framework plugin."""

from abc import ABC, abstractmethod
from collections.abc import Sequence


class FrameworkPlugin(ABC):
    def __init__(self, arguments: Sequence[str]) -> None:
        self.arguments = list(arguments)

    @abstractmethod
    def initialize(self) -> None:
        """Prepare the plugin for execution."""

    @abstractmethod
    def execute_tests(self) -> int:
        """Run the selected workflow and return its process exit code."""

    @abstractmethod
    def shutdown(self) -> None:
        """Release resources, including after a failed initialization."""
