#!/usr/bin/env python3
"""Posture checks for evidence / JSON externalization (analyst core DB).

1. ``permission_audit_snapshots``: when artifact pointers exist, ``metadata`` should be NULL.
2. ``static_analysis_findings``: rows with ``evidence_hash`` must have a payload row.
3. ``evidence_hash`` column posture: findings and payload hashes should use
   ``CHAR(64) CHARACTER SET ascii COLLATE ascii_bin``.
4. Informational counts: ``findings_with_hash``, ``static_finding_evidence_payloads`` rows, inline-without-hash.

Exit **0** when no violations, **1** when invariant failures, **2** on DB / schema errors.

Run from repo root::

  PYTHONPATH=. python scripts/db/check_evidence_storage_posture.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_HASH_COLUMN_TARGETS = (
    ("static_analysis_findings", "evidence_hash"),
    ("static_finding_evidence_payloads", "evidence_hash"),
)


def _evidence_hash_collation_rows(core_q) -> list[dict[str, object]]:
    rows = core_q.run_sql(
        """
        SELECT table_name, column_name, column_type, character_set_name, collation_name
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND (
            (table_name = 'static_analysis_findings' AND column_name = 'evidence_hash')
            OR (table_name = 'static_finding_evidence_payloads' AND column_name = 'evidence_hash')
          )
        ORDER BY table_name, column_name
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="check_evidence_storage_posture.hash_collations",
    )
    return list(rows or [])


def _hash_collation_ok(rows: list[dict[str, object]]) -> bool:
    by_key = {
        (str(row.get("table_name") or ""), str(row.get("column_name") or "")): row
        for row in rows
    }
    for table, column in _HASH_COLUMN_TARGETS:
        row = by_key.get((table, column))
        if not row:
            return False
        col_type = str(row.get("column_type") or "").lower()
        charset = str(row.get("character_set_name") or "").lower()
        collation = str(row.get("collation_name") or "").lower()
        if col_type != "char(64)" or charset != "ascii" or collation != "ascii_bin":
            return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    eng = str(db_config.DB_CONFIG.get("engine") or "").lower()
    if eng == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    bad = 0
    try:
        row = core_q.run_sql(
            """
            SELECT COUNT(*) AS c FROM information_schema.tables
            WHERE table_schema = DATABASE() AND table_name = 'static_finding_evidence_payloads'
            """,
            (),
            fetch="one",
            dictionary=True,
            query_name="check_evidence_storage_posture.payload_table",
        )
        if not row or int(row.get("c") or 0) == 0:
            sys.stderr.write("static_finding_evidence_payloads table missing; apply schema bootstrap.\n")
            return 2

        hash_rows = _evidence_hash_collation_rows(core_q)
        hash_ok = _hash_collation_ok(hash_rows)
        print(f"evidence_hash_collation_ok={1 if hash_ok else 0}")
        for hrow in hash_rows:
            print(
                "  evidence_hash_column="
                f"{hrow.get('table_name')}.{hrow.get('column_name')} "
                f"{hrow.get('column_type')} "
                f"{hrow.get('character_set_name')}/{hrow.get('collation_name')}"
            )
        if not hash_ok:
            bad += 1

        snap = 0
        col_rel = core_q.run_sql(
            """
            SELECT COUNT(*) AS c FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'permission_audit_snapshots'
              AND column_name = 'evidence_relpath'
            """,
            (),
            fetch="one",
            dictionary=True,
            query_name="check_evidence_storage_posture.col_rel",
        )
        if col_rel and int(col_rel.get("c") or 0) > 0:
            snap_row = core_q.run_sql(
                """
                SELECT COUNT(*) AS c
                FROM permission_audit_snapshots
                WHERE evidence_relpath IS NOT NULL
                  AND TRIM(evidence_relpath) <> ''
                  AND evidence_sha256 IS NOT NULL
                  AND TRIM(evidence_sha256) <> ''
                  AND metadata IS NOT NULL
                """,
                (),
                fetch="one",
                dictionary=True,
                query_name="check_evidence_storage_posture.snapshot_inline",
            )
            snap = int(snap_row.get("c") or 0) if snap_row else 0
        print(f"snapshot_metadata_with_artifact_pointer={snap}")
        if snap:
            bad += 1

        with_hash = core_q.run_sql(
            """
            SELECT COUNT(*) AS c
            FROM static_analysis_findings
            WHERE evidence_hash IS NOT NULL AND TRIM(evidence_hash) <> ''
            """,
            (),
            fetch="one",
            dictionary=True,
            query_name="check_evidence_storage_posture.findings_with_hash",
        )
        print(f"findings_with_hash={int(with_hash.get('c') or 0) if with_hash else 0}")

        pay = core_q.run_sql(
            "SELECT COUNT(*) AS c FROM static_finding_evidence_payloads",
            (),
            fetch="one",
            dictionary=True,
            query_name="check_evidence_storage_posture.payload_count",
        )
        print(f"static_finding_evidence_payload_rows={int(pay.get('c') or 0) if pay else 0}")

        miss = core_q.run_sql(
            """
            SELECT COUNT(*) AS c
            FROM static_analysis_findings f
            LEFT JOIN static_finding_evidence_payloads ep
              ON ep.evidence_hash = f.evidence_hash
            WHERE f.evidence_hash IS NOT NULL
              AND TRIM(f.evidence_hash) <> ''
              AND ep.evidence_hash IS NULL
            """,
            (),
            fetch="one",
            dictionary=True,
            query_name="check_evidence_storage_posture.missing_payload",
        )
        v2 = int(miss.get("c") or 0) if miss else 0
        print(f"findings_hash_missing_payload_row={v2}")
        if v2:
            bad += 1

        stale = core_q.run_sql(
            """
            SELECT COUNT(*) AS c
            FROM static_analysis_findings
            WHERE evidence IS NOT NULL
              AND (evidence_hash IS NULL OR evidence_hash = '')
            """,
            (),
            fetch="one",
            dictionary=True,
            query_name="check_evidence_storage_posture.inline_without_hash",
        )
        print(f"findings_inline_evidence_without_hash={int(stale.get('c') or 0) if stale else 0}")
    except Exception as exc:
        sys.stderr.write(f"Check failed: {exc}\n")
        return 2

    if bad:
        sys.stderr.write(
            "Evidence storage posture: invariant failure(s). "
            "Clear snapshot metadata when artifact pointers exist; "
            "backfill payloads for static_analysis_findings (scripts/db/backfill_static_finding_evidence_payloads.py). "
            "Align evidence_hash columns to CHAR(64) CHARACTER SET ascii COLLATE ascii_bin "
            "using a reviewed safe ALTER path before disabling inline evidence. "
            "Do not strip inline evidence or disable SCYTALEDROID_FINDINGS_EVIDENCE_INLINE until "
            "hash parity is acceptable (scripts/db/probe_finding_evidence_hash_parity.py) and "
            "v_web_app_findings is recreated.\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
