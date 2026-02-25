#!/usr/bin/env python3
"""Legacy wrapper (backwards compatible).

Use `scripts/publication/publication_ml_audit_report.py`.
"""

from __future__ import annotations

import runpy
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    target = repo_root / "scripts" / "publication" / "publication_ml_audit_report.py"
    runpy.run_path(str(target), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
