#!/usr/bin/env python3
"""Compare MariaDB ``evidence_hash`` (e.g. ``SHA2`` backfill) vs Python ``canonical_evidence_body``.

Samples ``static_analysis_findings`` rows with non-null ``evidence``, compares stored
``evidence_hash`` to the hash produced by ``canonical_evidence_body(evidence)`` in this repo.

**Do not** use ``--strip-inline`` on backfill or set ``SCYTALEDROID_FINDINGS_EVIDENCE_INLINE=0``
until mismatches are acceptable and ``v_web_app_findings`` is recreated/verified.

Run from repo root::

  PYTHONPATH=. python scripts/db/probe_finding_evidence_hash_parity.py --sample 500
  PYTHONPATH=. python scripts/db/probe_finding_evidence_hash_parity.py --sample 200 --order rand
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _preview(evidence: Any, limit: int = 120) -> str:
    try:
        text = json.dumps(evidence, default=str) if not isinstance(evidence, str) else evidence
    except Exception:
        text = repr(evidence)
    text = str(text).replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=int, default=200, help="Max rows to fetch (default 200).")
    parser.add_argument(
        "--order",
        choices=("id_desc", "id_asc", "rand"),
        default="id_desc",
        help="Row order: id_desc (cheap), id_asc, or rand (full scan cost on large tables).",
    )
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.StaticAnalysis.cli.persistence.finding_evidence_payload import (
            canonical_evidence_body,
            evidence_hash_mismatch_hint,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    eng = str(db_config.DB_CONFIG.get("engine") or "").lower()
    if eng == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    n = max(1, min(int(args.sample or 200), 50_000))
    order_sql = {
        "id_desc": "ORDER BY id DESC",
        "id_asc": "ORDER BY id ASC",
        "rand": "ORDER BY RAND()",
    }[args.order]

    sql = f"""
            SELECT id, evidence, evidence_hash
            FROM static_analysis_findings
            WHERE evidence IS NOT NULL
            {order_sql}
            LIMIT {n}
            """

    try:
        rows = core_q.run_sql(
            sql,
            (),
            fetch="all",
            dictionary=True,
            query_name="probe_finding_evidence_hash_parity.sample",
        )
    except Exception as exc:
        sys.stderr.write(f"Query failed: {exc}\n")
        return 2

    if not rows:
        print("sampled_rows=0 (no rows with evidence IS NOT NULL)")
        return 0

    matched = 0
    mismatched = 0
    mismatch_examples: list[dict[str, Any]] = []
    hints: dict[str, int] = {}

    for row in rows:
        rid = int(row["id"])
        ev = row.get("evidence")
        sql_h = row.get("evidence_hash")
        sql_s = str(sql_h).strip().lower() if sql_h is not None else ""
        py_h, _body = canonical_evidence_body(ev)
        py_s = str(py_h).strip().lower() if py_h else ""

        if sql_s == py_s or (not sql_s and not py_s):
            matched += 1
            continue
        mismatched += 1
        hint = evidence_hash_mismatch_hint(ev, sql_hash=sql_s or None, python_hash=py_s or None)
        hints[hint] = hints.get(hint, 0) + 1
        if len(mismatch_examples) < 8:
            mismatch_examples.append(
                {
                    "id": rid,
                    "sql_hash": sql_s[:16] + "…" if len(sql_s) > 16 else sql_s,
                    "python_hash": py_s[:16] + "…" if len(py_s) > 16 else py_s,
                    "hint": hint,
                    "preview": _preview(ev),
                }
            )

    print(f"sampled_rows={len(rows)}")
    print(f"matching_rows={matched}")
    print(f"mismatching_rows={mismatched}")
    print("mismatch_hint_counts:")
    if hints:
        for k in sorted(hints.keys(), key=lambda x: (-hints[x], x)):
            print(f"  {k}: {hints[k]}")
    elif mismatched == 0:
        print("  (all sampled rows: SQL evidence_hash matches Python canonical_evidence_body)")
    else:
        print("  (unexpected: mismatches without hint buckets)")

    if mismatch_examples:
        print("mismatch_examples (up to 8):")
        for ex in mismatch_examples:
            print(f"  id={ex['id']} hint={ex['hint']}")
            print(f"    sql={ex['sql_hash']} python={ex['python_hash']}")
            print(f"    preview={ex['preview']!r}")

    if args.order == "rand":
        print("\ninfo: ORDER BY RAND() can be expensive on large tables; prefer id_desc for routine checks.")

    if mismatched == 0 and len(rows) >= 50:
        print(
            "\nok: hash parity on this sample — optional spot-check: "
            "`--order rand --sample 500` once (costly on large tables)."
        )

    if mismatched and mismatched >= max(5, len(rows) // 10):
        print(
            "\nwarn: mismatches are common; consider re-keying via Python backfill "
            "(scripts/db/backfill_static_finding_evidence_payloads.py --apply) after review."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
