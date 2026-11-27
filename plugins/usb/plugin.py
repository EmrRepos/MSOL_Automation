"""Adapter for the existing USB desktop application."""

from pathlib import Path

from framework.plugin_loader.isolated import IsolatedApplicationPlugin


class Plugin(IsolatedApplicationPlugin):
    entry_point = Path(__file__).with_name("main.py")
