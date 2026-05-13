#!/usr/bin/env python3
"""Posture check for **recent** static finding writes (evidence_hash + payload + inline).

Targets findings with ``created_at`` in the last ``--since-hours`` window (default 168).

When the window is empty, prints a short notice and exits **0**.

When ``SCYTALEDROID_FINDINGS_EVIDENCE_INLINE=0`` (or ``false``), flags rows that still
store inline ``evidence`` JSON alongside a non-empty ``evidence_hash`` (new-writer drift).

Also checks: hash without payload row; ``vw_static_finding_surfaces_latest`` rows where
``COALESCE(f.evidence, JSON_EXTRACT(ep.evidence_json, '$'))`` is NULL despite a hash
(MariaDB-safe payload projection, matching ``v_web_app_findings``).

Exit **0** when no violations, **1** when any invariant fails, **2** on DB/schema errors.

Run::

  PYTHONPATH=. python scripts/db/check_evidence_latest_write_posture.py
  PYTHONPATH=. python scripts/db/check_evidence_latest_write_posture.py --since-hours 24
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
    parser.add_argument(
        "--since-hours",
        type=int,
        default=168,
        help="Look-back window for static_analysis_findings.created_at (default 168).",
    )
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_scripts.evidence_latest_write_posture import fetch_recent_posture
        from scytaledroid.StaticAnalysis.cli.persistence.finding_evidence_payload import (
            findings_evidence_inline_enabled,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    eng = str(db_config.DB_CONFIG.get("engine") or "").lower()
    if eng == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    hours = max(1, min(int(args.since_hours), 24 * 366))
    inline_on = findings_evidence_inline_enabled()

    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS c FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = 'static_finding_evidence_payloads'
        """,
        (),
        fetch="one",
        dictionary=True,
        query_name="check_evidence_latest_write_posture.payload_table",
    )
    if not row or int(row.get("c") or 0) == 0:
        sys.stderr.write("static_finding_evidence_payloads missing; apply schema bootstrap.\n")
        return 2

    try:
        counts = fetch_recent_posture(core_q, hours=hours)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"DB error: {exc}\n")
        return 2

    total = counts["recent_findings_total"]
    print(f"since_hours={hours}")
    print(f"SCYTALEDROID_FINDINGS_EVIDENCE_INLINE={1 if inline_on else 0} (effective_inline={inline_on})")
    print(f"recent_findings_total={total}")

    if total == 0:
        print("recent_window_empty=1 (no detailed checks)")
        return 0

    bad = 0
    print(f"recent_hash_missing_payload={counts['recent_hash_missing_payload']}")
    if counts["recent_hash_missing_payload"]:
        bad += 1

    print(f"recent_inline_rows_with_hash={counts['recent_inline_rows_with_hash']}")
    if not inline_on and counts["recent_inline_rows_with_hash"]:
        bad += 1
        print(
            "violation: inline evidence present while SCYTALEDROID_FINDINGS_EVIDENCE_INLINE "
            "is disabled — expect evidence=NULL when evidence_hash is set.",
        )

    print(f"recent_unresolved_on_latest_surface={counts['recent_unresolved_on_latest_surface']}")
    if counts["recent_unresolved_on_latest_surface"]:
        bad += 1

    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
