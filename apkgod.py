#!/usr/bin/env python3
"""Compatibility entrypoint for the integrated APK-GOD application."""
from apk_god.cli import main
from apk_god.inspect_apk import inspect_apk as inspect

if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    commands = {"analyze", "batch", "binary", "doctor", "tools", "serve", "diff", "ai", "runtime"}
    if args and args[0] not in commands and not args[0].startswith("-"):
        args.insert(0, "analyze")
    raise SystemExit(main(args))
