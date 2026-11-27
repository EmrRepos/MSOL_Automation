"""Discover plugin packages without importing unselected applications."""

import importlib
from pathlib import Path
from collections.abc import Sequence

from .base import FrameworkPlugin

PLUGIN_DIRECTORY = Path(__file__).resolve().parents[2] / "plugins"


def discover_plugins() -> list[str]:
    return sorted(
        path.name
        for path in PLUGIN_DIRECTORY.iterdir()
        if path.is_dir()
        and path.name.isidentifier()
        and (path / "__init__.py").is_file()
        and (path / "plugin.py").is_file()
    )


def load_plugin(name: str, arguments: Sequence[str]) -> FrameworkPlugin:
    if name not in discover_plugins():
        raise ValueError(f"Unknown plugin: {name}")
    module = importlib.import_module(f"plugins.{name}.plugin")
    plugin_class = getattr(module, "Plugin", None)
    if not isinstance(plugin_class, type) or not issubclass(plugin_class, FrameworkPlugin):
        raise TypeError(f"Plugin {name!r} must export a FrameworkPlugin subclass named Plugin.")
    return plugin_class(arguments)
