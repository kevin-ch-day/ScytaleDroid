#!/usr/bin/env python3
"""Read-only typed-linkage audit for ``artifact_registry``.

Reports migration posture, fallback-needed rows, typed dangling counts, and a
comparison between legacy integrity logic and typed-preferred integrity logic.

Run from repo root::

  PYTHONPATH=. python scripts/db/report_artifact_registry_typed_linkage_audit.py
  PYTHONPATH=. python scripts/db/report_artifact_registry_typed_linkage_audit.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def _format_counts(rows: list[Mapping[str, Any]]) -> list[str]:
    return [
        f"  {row.get('run_type')}\t{row.get('link_state')}\t{int(row.get('row_count') or 0)}"
        for row in rows
    ]


def format_text_report(data: Mapping[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# artifact_registry typed linkage audit (read-only)")
    lines.append("")
    lines.append(f"total artifact_registry rows: {int(data.get('total_artifact_registry_rows') or 0)}")
    lines.append("")
    lines.append("## rows by run_type")
    for row in data.get("rows_by_run_type") or []:
        lines.append(f"  {row.get('run_type')}\t{int(row.get('row_count') or 0)}")
    lines.append("")
    lines.append(f"migrated static rows: {int(data.get('migrated_static_rows') or 0)}")
    lines.append(f"migrated dynamic rows: {int(data.get('migrated_dynamic_rows') or 0)}")
    lines.append(f"malformed static run_id rows: {int(data.get('malformed_static_run_id_rows') or 0)}")
    lines.append(f"dangling static_run_id rows: {int(data.get('dangling_static_run_id_rows') or 0)}")
    lines.append(f"dangling dynamic_run_id rows: {int(data.get('dangling_dynamic_run_id_rows') or 0)}")
    lines.append(f"fallback-needed rows: {int(data.get('fallback_needed_rows') or 0)}")
    lines.append("")
    lines.append("## legacy integrity counts")
    lines.extend(_format_counts(list(data.get("legacy_integrity_counts") or [])))
    lines.append("")
    lines.append("## typed-preferred integrity counts")
    lines.extend(_format_counts(list(data.get("typed_preferred_integrity_counts") or [])))
    lines.append("")
    lines.append("Maintained SQL companion: scripts/db/sql/audit_artifact_registry_typed_linkage.sql")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils.artifact_registry_typed_linkage import (
            collect_artifact_registry_typed_linkage_audit,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    eng = str(db_config.DB_CONFIG.get("engine") or "").lower()
    if eng == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    try:
        data = collect_artifact_registry_typed_linkage_audit(core_q.run_sql)
    except Exception as exc:
        sys.stderr.write(f"Audit failed: {exc}\n")
        return 2

    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True, default=str))
    else:
        print(format_text_report(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
