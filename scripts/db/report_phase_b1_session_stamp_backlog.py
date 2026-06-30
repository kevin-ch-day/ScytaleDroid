#!/usr/bin/env python3
"""Compatibility wrapper for the merged Phase B1 session-stamp backlog CLI."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    target = Path(__file__).resolve().with_name("phase_b1_session_stamp_backlog.py")
    return subprocess.call([sys.executable, str(target), "report", *args])


if __name__ == "__main__":
    raise SystemExit(main())
