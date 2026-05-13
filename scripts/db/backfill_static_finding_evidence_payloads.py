#!/usr/bin/env python3
"""Backfill ``static_finding_evidence_payloads`` and ``static_analysis_findings.evidence_hash``.

Default is dry-run (counts only). With ``--apply``, inserts deduped payload rows and sets
``evidence_hash`` on findings. With ``--strip-inline`` (requires ``--apply``), clears inline
``evidence`` JSON after a hash is stored (operators should deploy ``v_web_app_findings`` first).

**Hash alignment:** persistence uses Python ``canonical_evidence_body`` (sorted JSON keys for
objects). A SQL-only backfill such as ``SHA2(COALESCE(evidence,''),256)`` follows MariaDB’s JSON
text rules and can produce **different** hashes than new writes for the same logical object. If
you already SQL-backfilled prod, either (a) keep using SQL for future hash updates, or (b) verify
hash parity on a sample before relying on Python ``SCYTALEDROID_FINDINGS_EVIDENCE_INLINE=0``.

Run from repo root::

  PYTHONPATH=. python scripts/db/backfill_static_finding_evidence_payloads.py --help
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
    parser.add_argument("--apply", action="store_true", help="Perform writes (default dry-run).")
    parser.add_argument(
        "--strip-inline",
        action="store_true",
        help="After hashing, set evidence=NULL where evidence_hash is set (requires --apply).",
    )
    parser.add_argument("--batch-size", type=int, default=500, help="Rows per SELECT batch.")
    args = parser.parse_args(argv)

    if args.strip_inline and not args.apply:
        sys.stderr.write("--strip-inline requires --apply\n")
        return 2

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.StaticAnalysis.cli.persistence.finding_evidence_payload import (
            canonical_evidence_body,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    eng = str(db_config.DB_CONFIG.get("engine") or "").lower()
    if eng == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    try:
        tbl = core_q.run_sql(
            """
            SELECT COUNT(*) AS c FROM information_schema.tables
            WHERE table_schema = DATABASE() AND table_name = 'static_finding_evidence_payloads'
            """,
            (),
            fetch="one",
            dictionary=True,
            query_name="backfill_evidence_payloads.table_exists",
        )
        if not tbl or int(tbl.get("c") or 0) == 0:
            sys.stderr.write("static_finding_evidence_payloads missing; apply canonical schema first.\n")
            return 2
    except Exception as exc:
        sys.stderr.write(f"Schema probe failed: {exc}\n")
        return 2

    batch = max(1, min(int(args.batch_size or 500), 5000))
    touched = 0
    payloads_upserted = 0

    try:
        pending = core_q.run_sql(
            """
            SELECT COUNT(*) AS c
            FROM static_analysis_findings
            WHERE evidence IS NOT NULL
              AND (evidence_hash IS NULL OR evidence_hash = '')
            """,
            (),
            fetch="one",
            dictionary=True,
            query_name="backfill_evidence_payloads.pending",
        )
        pending_n = int(pending.get("c") or 0) if pending else 0
        print(f"pending_rows_with_evidence_no_hash={pending_n}")
        if not args.apply:
            print("dry-run: no writes performed; re-run with --apply to backfill hashes and payloads.")
            return 0

        while True:
            rows = core_q.run_sql(
                f"""
                SELECT id, evidence
                FROM static_analysis_findings
                WHERE evidence IS NOT NULL
                  AND (evidence_hash IS NULL OR evidence_hash = '')
                LIMIT {batch}
                """,
                (),
                fetch="all",
                dictionary=True,
                query_name="backfill_evidence_payloads.select_batch",
            )
            if not rows:
                break
            for row in rows:
                fid = int(row["id"])
                ev = row.get("evidence")
                digest, body = canonical_evidence_body(ev)
                if not digest or not body:
                    continue
                core_q.run_sql(
                    """
                    INSERT IGNORE INTO static_finding_evidence_payloads (
                      evidence_hash, evidence_json, evidence_chars
                    ) VALUES (%s, %s, %s)
                    """,
                    (digest, body, len(body)),
                    query_name="backfill_evidence_payloads.insert_payload",
                )
                payloads_upserted += 1
                if args.strip_inline:
                    core_q.run_sql(
                        """
                        UPDATE static_analysis_findings
                        SET evidence_hash=%s, evidence=NULL
                        WHERE id=%s
                        """,
                        (digest, fid),
                        query_name="backfill_evidence_payloads.update_strip",
                    )
                else:
                    core_q.run_sql(
                        """
                        UPDATE static_analysis_findings
                        SET evidence_hash=%s
                        WHERE id=%s
                        """,
                        (digest, fid),
                        query_name="backfill_evidence_payloads.update_hash",
                    )
                touched += 1
            if len(rows) < batch:
                break
    except Exception as exc:
        sys.stderr.write(f"Backfill failed: {exc}\n")
        return 2

    print(f"rows_touched={touched}")
    if args.apply:
        print(f"payload_insert_attempts={payloads_upserted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
