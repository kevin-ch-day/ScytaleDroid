#!/usr/bin/env python3
"""
Lightweight import smoke test to catch circular imports and missing deps.

Usage:
    python scripts/smoke_imports.py
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
import sys


def main() -> int:
    base = Path(__file__).resolve().parent.parent / "scytaledroid"
    sys.path.insert(0, str(base.parent))
    errors = []
    for module in pkgutil.walk_packages([str(base)]):
        name = f"scytaledroid.{module.name}"
        try:
            importlib.import_module(name)
        except Exception as exc:
            errors.append((name, exc))
    if errors:
        print("Import failures detected:")
        for name, exc in errors:
            print(f" - {name}: {exc}")
        return 1
    print("All scytaledroid modules imported successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
