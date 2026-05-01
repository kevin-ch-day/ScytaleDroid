#!/usr/bin/env python3
"""Thin wrapper for frozen-archive scientific QA generation."""

from __future__ import annotations

import sys
from pathlib import Path


def _print_help() -> None:
    print("usage: publication_scientific_qa.py [-h]")
    print()
    print("Generate frozen-archive scientific QA reports.")
    print()
    print("options:")
    print("  -h, --help  show this help message and exit")


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Reporting.services.publication_scientific_qa_service import main


if __name__ == "__main__":  # pragma: no cover
    if any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        _print_help()
        raise SystemExit(0)
    raise SystemExit(main())
