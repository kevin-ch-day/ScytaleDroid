"""Schema audit and fixer (temporary script).

Run standalone or from Database Utilities to inspect and optionally fix tables.

Goals:
  - harvest_artifact_paths does not contain stray source_path column
  - legacy permission table audits are skipped (deprecated)
"""

from __future__ import annotations

import argparse
from typing import List, Sequence, Tuple

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils.diagnostics import get_table_columns
from scytaledroid.Utils.DisplayUtils import status_messages as sm


def _index_exists(table: str, index_name: str) -> bool:
    row = core_q.run_sql(
        (
            "SELECT COUNT(*) FROM information_schema.statistics "
            "WHERE table_schema = DATABASE() AND table_name = %s AND index_name = %s"
        ),
        (table, index_name),
        fetch="one",
    )
    return bool(row and int(row[0]) > 0)


def _table_exists(table: str) -> bool:
    row = core_q.run_sql(
        (
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema = DATABASE() AND table_name = %s"
        ),
        (table,),
        fetch="one",
    )
    return bool(row and int(row[0]) > 0)


def audit_detected_permissions(apply_fixes: bool = False) -> Tuple[List[str], List[str]]:
    """Deprecated legacy audit stub (kept for backward imports)."""
    return [], []


def audit_harvest_paths(apply_fixes: bool = False) -> Tuple[List[str], List[str]]:
    issues: List[str] = []
    fixes_applied: List[str] = []

    cols = get_table_columns("harvest_artifact_paths") or []
    if "source_path" in cols:
        issues.append("harvest_artifact_paths has stray source_path column")
        if apply_fixes:
            # Backfill to harvest_source_paths if missing
            core_q.run_sql(
                """
                INSERT INTO harvest_source_paths (apk_id, source_path, created_at, updated_at)
                SELECT hap.apk_id, hap.source_path, NOW(), NOW()
                FROM harvest_artifact_paths hap
                LEFT JOIN harvest_source_paths hsp ON hsp.apk_id = hap.apk_id
                WHERE hap.source_path IS NOT NULL AND hsp.apk_id IS NULL
                """
            )
            core_q.run_sql("ALTER TABLE harvest_artifact_paths DROP COLUMN source_path")
            fixes_applied.append("migrated source_path and dropped stray column")

    return issues, fixes_applied


def _indexes_for_columns(table: str, columns: Sequence[str]) -> List[str]:
    if not columns:
        return []
    placeholders = ", ".join(["%s"] * len(columns))
    rows = core_q.run_sql(
        (
            "SELECT DISTINCT index_name FROM information_schema.statistics "
            "WHERE table_schema = DATABASE() AND table_name = %s AND column_name IN ("
            + placeholders
            + ")"
        ),
        (table, *columns),
        fetch="all",
    )
    names: List[str] = []
    for row in rows or []:
        if not row:
            continue
        name = str(row[0])
        if name and name.upper() != "PRIMARY":
            names.append(name)
    return names



def run_interactive() -> None:
    issues_total = 0
    fixes_total: list[str] = []

    print(sm.status("Auditing schema…", level="info"))
    h_issues, _ = audit_harvest_paths(apply_fixes=False)
    issues_total = len(h_issues)

    if issues_total == 0:
        print(sm.status("Schema health: OK — no issues found.", level="success"))
        return

    print(sm.status(f"Schema health: {issues_total} issue(s) found.", level="warn"))
    for msg in h_issues:
        print(f"  - {msg}")

    try:
        from scytaledroid.Utils.DisplayUtils import prompt_utils

        if not prompt_utils.prompt_yes_no("Apply fixes now?", default=False):
            print(sm.status("No changes applied.", level="info"))
            return
    except Exception:
        pass

    # Apply fixes
    _, fixes = audit_harvest_paths(apply_fixes=True)
    fixes_total.extend(fixes)

    if fixes_total:
        print(sm.status(f"Fixes applied ({len(fixes_total)}):", level="success"))
        for f in fixes_total:
            print(f"  - {f}")
    else:
        print(sm.status("No fixes were required.", level="info"))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Schema audit and fixer (temporary script)")
    parser.add_argument("--fix", action="store_true", help="Apply fixes non-interactively")
    args = parser.parse_args(argv)

    if args.fix:
        _, fixes = audit_harvest_paths(apply_fixes=True)
        total = len(fixes)
        if total:
            print(sm.status(f"Applied {total} fix(es).", level="success"))
        else:
            print(sm.status("No fixes required.", level="info"))
    else:
        run_interactive()


if __name__ == "__main__":  # pragma: no cover
    main()
