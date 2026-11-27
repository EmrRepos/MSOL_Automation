"""Plugin discovery and lifecycle contract."""

from .base import FrameworkPlugin
from .loader import discover_plugins, load_plugin

__all__ = ["FrameworkPlugin", "discover_plugins", "load_plugin"]
