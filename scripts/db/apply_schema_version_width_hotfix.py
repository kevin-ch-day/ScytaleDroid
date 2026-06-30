#!/usr/bin/env python3
"""Compatibility wrapper for the merged schema-version width hotfix CLI."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    target = Path(__file__).resolve().with_name("schema_version_width_hotfix.py")
    return subprocess.call([sys.executable, str(target), "apply", *args])


if __name__ == "__main__":
    raise SystemExit(main())
