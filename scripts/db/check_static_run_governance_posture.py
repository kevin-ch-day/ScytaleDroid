#!/usr/bin/env python3
"""Read-only static run governance posture (canonical / handoff invariants).

Runs three high-signal counts against ``static_analysis_runs`` and ``v_static_handoff_v1``:

1. ``failed_canonical_runs`` — non-COMPLETED rows must not have ``is_canonical = 1``.
2. ``failed_missing_run_class`` — non-COMPLETED rows must have ``run_class`` set.
3. ``completed_session_invariant_violations`` — per ``session_stamp``, COMPLETED runs must
   align counts with handoff view rows, ``run_class = 'CANONICAL'``, and ``identity_valid = 1``.

Exit codes: **0** all checks zero, **1** any check non-zero, **2** DB unavailable / query error.

Run from repo root::

  PYTHONPATH=. python scripts/db/check_static_run_governance_posture.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.static_run_governance_checks import (
            GOVERNANCE_POSTURE_CHECKS,
            fetch_static_run_governance_counts,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    eng = str(db_config.DB_CONFIG.get("engine") or "").lower()
    if eng == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    bad = 0
    try:
        counts = fetch_static_run_governance_counts(core_q.run_sql)
        for label, _sql in GOVERNANCE_POSTURE_CHECKS:
            val = getattr(counts, label, 0)
            print(f"{label}={val}")
            if val != 0:
                bad += 1
    except Exception as exc:
        sys.stderr.write(f"Governance posture query failed: {exc}\n")
        return 2

    if bad:
        sys.stderr.write(
            f"Governance posture: {bad} check(s) non-zero. "
            "Repair static_analysis_runs (is_canonical, run_class, identity) or child tables; "
            "recreate views after DDL deploy.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
