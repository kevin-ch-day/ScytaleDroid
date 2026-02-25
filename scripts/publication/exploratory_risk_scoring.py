#!/usr/bin/env python3
"""Exploratory risk scoring artifacts (wrapper).

This is intentionally marked exploratory and is not part of the canonical
publication bundle contract.
"""

from __future__ import annotations

import runpy
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    target = repo_root / "scripts" / "paper2" / "paper2_risk_scoring_artifacts.py"
    runpy.run_path(str(target), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

