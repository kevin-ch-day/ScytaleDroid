#!/usr/bin/env python3
"""Wrapper for Profile v3 capture-status reporting."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.DynamicAnalysis.services.profile_v3_capture_status_service import main


if __name__ == "__main__":
    raise SystemExit(main())
