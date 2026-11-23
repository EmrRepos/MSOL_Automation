"""Launch one installed framework plugin."""

import argparse
import sys

from framework.plugin_loader import discover_plugins, load_plugin


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Launch an automation framework.")
    parser.add_argument("--list", action="store_true", help="List available plugins.")
    parser.add_argument("plugin", nargs="?", help="Plugin to launch.")
    parser.add_argument("arguments", nargs=argparse.REMAINDER, help="Arguments passed to the plugin.")
    args = parser.parse_args(argv)

    available = discover_plugins()
    if args.list or not args.plugin:
        print("Available plugins:")
        for name in available:
            print(f"  {name}")
        return 0
    if args.plugin not in available:
        parser.error(f"unknown plugin {args.plugin!r}; available: {', '.join(available)}")

    try:
        plugin = load_plugin(args.plugin, args.arguments)
        try:
            plugin.initialize()
            return plugin.execute_tests()
        finally:
            plugin.shutdown()
    except (ImportError, OSError, TypeError, ValueError) as exc:
        print(f"Plugin {args.plugin!r} failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
