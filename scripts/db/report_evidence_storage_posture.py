#!/usr/bin/env python3
"""Read-only report: evidence / JSON payload bloat signals (MariaDB analyst core).

Summarizes sizes and dedupe headroom for:

- ``static_permission_matrix.flags`` (distinct payloads, total bytes)
- ``static_analysis_findings.evidence`` vs ``static_finding_evidence_payloads``
- ``permission_audit_apps.details``
- ``permission_audit_snapshots.metadata`` vs artifact pointers

Run from repo root::

  PYTHONPATH=. python scripts/db/report_evidence_storage_posture.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _scalar(core_q, sql: str) -> object | None:
    row = core_q.run_sql(sql, (), fetch="one", dictionary=True, query_name="report_evidence_storage_posture.scalar")
    if not row:
        return None
    return next(iter(row.values()))


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

    try:
        print("=== static_permission_matrix.flags ===")
        row = core_q.run_sql(
            """
            SELECT
              COUNT(*) AS rows_total,
              COUNT(DISTINCT flags) AS distinct_flags,
              ROUND(SUM(LENGTH(COALESCE(flags, ''))) / 1024 / 1024, 4) AS flags_mb
            FROM static_permission_matrix
            """,
            (),
            fetch="one",
            dictionary=True,
            query_name="report_evidence_storage_posture.spm_flags",
        )
        if row:
            for k, v in row.items():
                print(f"  {k}: {v}")

        print("\n=== static_analysis_findings + static_finding_evidence_payloads ===")
        row2 = core_q.run_sql(
            """
            SELECT
              COUNT(*) AS findings_rows,
              COUNT(DISTINCT evidence) AS distinct_evidence
            FROM static_analysis_findings
            WHERE evidence IS NOT NULL
            """,
            (),
            fetch="one",
            dictionary=True,
            query_name="report_evidence_storage_posture.findings_counts",
        )
        if row2:
            for k, v in row2.items():
                print(f"  {k}: {v}")
        row2b = core_q.run_sql(
            """
            SELECT
              ROUND(SUM(OCTET_LENGTH(CAST(evidence AS CHAR))) / 1024 / 1024, 4) AS evidence_mb
            FROM static_analysis_findings
            WHERE evidence IS NOT NULL
            """,
            (),
            fetch="one",
            dictionary=True,
            query_name="report_evidence_storage_posture.findings_mb",
        )
        if row2b:
            print(f"  evidence_mb (cast char octets): {row2b.get('evidence_mb')}")

        pl_exists = int(_scalar(core_q, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'static_finding_evidence_payloads'") or 0)
        print(f"  static_finding_evidence_payloads table present: {bool(pl_exists)}")
        if pl_exists:
            row3 = core_q.run_sql(
                """
                SELECT COUNT(*) AS payload_rows,
                       ROUND(SUM(evidence_chars) / 1024 / 1024, 4) AS payload_chars_mb
                FROM static_finding_evidence_payloads
                """,
                (),
                fetch="one",
                dictionary=True,
                query_name="report_evidence_storage_posture.payloads",
            )
            if row3:
                for k, v in row3.items():
                    print(f"  {k}: {v}")
            cov1 = core_q.run_sql(
                """
                SELECT COUNT(*) AS c
                FROM static_analysis_findings
                WHERE evidence IS NOT NULL
                  AND (evidence_hash IS NULL OR evidence_hash = '')
                """,
                (),
                fetch="one",
                dictionary=True,
                query_name="report_evidence_storage_posture.coverage_inline",
            )
            print(f"  findings_inline_without_hash={int(cov1.get('c') or 0) if cov1 else 0}")
            cov2 = core_q.run_sql(
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
                query_name="report_evidence_storage_posture.coverage_missing",
            )
            print(f"  findings_hash_missing_payload={int(cov2.get('c') or 0) if cov2 else 0}")

        print("\n=== permission_audit_apps.details ===")
        row4 = core_q.run_sql(
            """
            SELECT
              COUNT(*) AS rows_total,
              COUNT(DISTINCT details) AS distinct_details,
              ROUND(SUM(LENGTH(COALESCE(details, ''))) / 1024 / 1024, 4) AS details_mb
            FROM permission_audit_apps
            """,
            (),
            fetch="one",
            dictionary=True,
            query_name="report_evidence_storage_posture.audit_apps",
        )
        if row4:
            for k, v in row4.items():
                print(f"  {k}: {v}")

        print("\n=== permission_audit_snapshots (metadata vs artifact pointers) ===")
        has_rel = int(
            _scalar(
                core_q,
                "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() "
                "AND table_name = 'permission_audit_snapshots' AND column_name = 'evidence_relpath'",
            )
            or 0
        )
        if has_rel:
            row5 = core_q.run_sql(
                """
                SELECT
                  COUNT(*) AS rows_total,
                  SUM(CASE WHEN metadata IS NOT NULL THEN 1 ELSE 0 END) AS rows_with_metadata,
                  SUM(
                    CASE
                      WHEN evidence_relpath IS NOT NULL AND TRIM(evidence_relpath) <> ''
                       AND evidence_sha256 IS NOT NULL AND TRIM(evidence_sha256) <> ''
                       AND metadata IS NOT NULL
                      THEN 1 ELSE 0
                    END
                  ) AS inline_metadata_with_artifact_pointer
                FROM permission_audit_snapshots
                """,
                (),
                fetch="one",
                dictionary=True,
                query_name="report_evidence_storage_posture.snapshots",
            )
            if row5:
                for k, v in row5.items():
                    print(f"  {k}: {v}")
        else:
            print("  (evidence_relpath column not present; skip snapshot pointer check)")
    except Exception as exc:
        sys.stderr.write(f"Report failed: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
