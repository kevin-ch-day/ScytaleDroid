#!/usr/bin/env python3
"""Compatibility entrypoint for the package-first lineage coverage report."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.db.report_apk_lineage_availability import main


if __name__ == "__main__":
    raise SystemExit(main())
