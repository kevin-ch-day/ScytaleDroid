#!/usr/bin/env python3
"""Shared safe-help wrapper for profile-tool service entrypoints."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if any(arg in {"-h", "--help"} for arg in args):
        print("usage: _service_wrapper.py [-h]")
        print()
        print("Shared safe-help wrapper for profile-tool service entrypoints.")
        print()
        print("options:")
        print("  -h, --help  show this help message and exit")
    return 0


def _print_help(prog: str, summary: str) -> None:
    print(f"usage: {prog} [-h]")
    print()
    print(summary)
    print()
    print("options:")
    print("  -h, --help  show this help message and exit")


def run_service_wrapper(wrapper_file: str, *, service_module: str, help_summary: str) -> int:
    if any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        _print_help(Path(wrapper_file).name, help_summary)
        return 0

    repo_root = Path(wrapper_file).resolve().parents[2]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    module = importlib.import_module(service_module)
    service_main = module.main
    result = service_main()
    return 0 if result is None else int(result)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
