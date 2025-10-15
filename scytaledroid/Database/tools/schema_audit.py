"""Schema audit and fixer (temporary script).

Run standalone or from Database Utilities to inspect and optionally fix tables.

Goals:
  - android_detected_permissions uses apk_id + perm_name uniqueness
  - Backfill apk_id from android_apk_repository via sha256
  - Drop legacy columns (version_name, version_code, sha256) when possible
  - harvest_artifact_paths does not contain stray source_path column
"""

from __future__ import annotations

import argparse
from typing import List, Sequence, Tuple

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils.db_utils import get_table_columns
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


def audit_detected_permissions(apply_fixes: bool = False) -> Tuple[List[str], List[str]]:
    issues: List[str] = []
    fixes_applied: List[str] = []

    cols = get_table_columns("android_detected_permissions") or []
    has_apk_id = "apk_id" in cols
    has_sha = "sha256" in cols
    has_ver = ("version_name" in cols) or ("version_code" in cols)
    has_apk_unique = _index_exists("android_detected_permissions", "ux_detected_perm_apk")
    # Foreign key check (best-effort)
    def _fk_exists() -> bool:
        row = core_q.run_sql(
            (
                "SELECT COUNT(*) FROM information_schema.referential_constraints "
                "WHERE constraint_schema = DATABASE() AND table_name = 'android_detected_permissions' "
                "AND constraint_name = 'fk_detected_apk'"
            ),
            fetch="one",
        )
        return bool(row and int(row[0]) > 0)
    has_fk = _fk_exists()
    has_sha_unique = _index_exists("android_detected_permissions", "ux_detected_perm_sha")

    if not has_apk_id:
        issues.append("detected_permissions missing apk_id column")
        if apply_fixes:
            core_q.run_sql(
                "ALTER TABLE android_detected_permissions ADD COLUMN apk_id BIGINT UNSIGNED NULL AFTER detected_id"
            )
            fixes_applied.append("added apk_id column")
            has_apk_id = True

    # Backfill apk_id from sha256 if possible (fix mode only)
    if apply_fixes and has_apk_id and has_sha:
        # Force binary comparison to avoid collation mismatch across tables
        core_q.run_sql(
            """
            UPDATE android_detected_permissions dp
            JOIN android_apk_repository ar ON BINARY dp.sha256 = BINARY ar.sha256
            SET dp.apk_id = ar.apk_id
            WHERE dp.apk_id IS NULL
            """
        )
        fixes_applied.append("backfilled apk_id from repository (binary match)")

    if not has_apk_unique:
        issues.append("detected_permissions missing unique index (apk_id, perm_name)")
        if apply_fixes and has_apk_id:
            core_q.run_sql(
                "ALTER TABLE android_detected_permissions ADD UNIQUE KEY ux_detected_perm_apk (apk_id, perm_name)"
            )
            fixes_applied.append("added unique on (apk_id, perm_name)")

    if has_sha_unique:
        issues.append("legacy unique index ux_detected_perm_sha present")
        if apply_fixes:
            core_q.run_sql(
                "ALTER TABLE android_detected_permissions DROP INDEX ux_detected_perm_sha"
            )
            fixes_applied.append("dropped legacy unique ux_detected_perm_sha")

    # Add FK to repository if not present (optional)
    if apply_fixes and has_apk_id and not has_fk:
        try:
            core_q.run_sql(
                "ALTER TABLE android_detected_permissions ADD CONSTRAINT fk_detected_apk FOREIGN KEY (apk_id) REFERENCES android_apk_repository(apk_id)"
            )
            fixes_applied.append("added foreign key fk_detected_apk")
        except Exception:
            pass

    # Drop legacy columns if requested
    if (has_sha or has_ver) and apply_fixes:
        drops = []
        for c in ("version_name", "version_code", "sha256"):
            if c in cols:
                drops.append(f"DROP COLUMN {c}")
        if drops:
            core_q.run_sql("ALTER TABLE android_detected_permissions " + ", ".join(drops))
            fixes_applied.append("dropped legacy version/sha columns")

    # Enforce NOT NULL on apk_id if requested
    if has_apk_id and apply_fixes:
        try:
            core_q.run_sql(
                "ALTER TABLE android_detected_permissions MODIFY apk_id BIGINT UNSIGNED NOT NULL"
            )
            fixes_applied.append("enforced NOT NULL on apk_id")
        except Exception:
            # If rows still NULL due to missing repository mapping, keep it nullable
            pass

    return issues, fixes_applied


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


def _unknown_unique_exists() -> bool:
    return _index_exists("android_unknown_permissions", "ux_android_unknown_perm")


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


def audit_unknown_permissions(apply_fixes: bool = False) -> Tuple[List[str], List[str]]:
    issues: List[str] = []
    fixes_applied: List[str] = []

    cols = get_table_columns("android_unknown_permissions") or []
    has_observed = ("observed_in_pkg" in cols) or ("observed_in_sha256" in cols)
    has_occ = "occurrences" in cols
    has_unique = _unknown_unique_exists()

    if has_observed or has_occ or not has_unique:
        issues.append("unknown_permissions schema not aligned (drop observed/occurrences, unique perm_name)")
        if apply_fixes:
            # Drop indexes that reference legacy columns before removing them
            legacy_columns = [c for c in ("observed_in_pkg", "observed_in_sha256", "occurrences") if c in cols]
            for index_name in _indexes_for_columns("android_unknown_permissions", legacy_columns):
                try:
                    core_q.run_sql(
                        "ALTER TABLE android_unknown_permissions DROP INDEX `{}`".format(index_name)
                    )
                    fixes_applied.append(f"dropped index {index_name}")
                except Exception:
                    pass

            # Drop legacy columns safely one-by-one (handle already-dropped cases)
            for c in legacy_columns:
                try:
                    core_q.run_sql(f"ALTER TABLE android_unknown_permissions DROP COLUMN `{c}`")
                    fixes_applied.append(f"dropped column {c}")
                except Exception:
                    pass

            # Refresh column cache after mutations
            cols = get_table_columns("android_unknown_permissions") or []
            # Add unique on perm_name if missing
            if not _index_exists("android_unknown_permissions", "ux_android_unknown_perm"):
                core_q.run_sql(
                    "ALTER TABLE android_unknown_permissions ADD UNIQUE KEY ux_android_unknown_perm (perm_name)"
                )
                fixes_applied.append("added unique on perm_name")

    return issues, fixes_applied


def run_interactive() -> None:
    issues_total = 0
    fixes_total: list[str] = []

    print(sm.status("Auditing schema…", level="info"))
    d_issues, _ = audit_detected_permissions(apply_fixes=False)
    h_issues, _ = audit_harvest_paths(apply_fixes=False)
    u_issues, _ = audit_unknown_permissions(apply_fixes=False)
    issues_total = len(d_issues) + len(h_issues) + len(u_issues)

    if issues_total == 0:
        print(sm.status("Schema health: OK — no issues found.", level="success"))
        return

    print(sm.status(f"Schema health: {issues_total} issue(s) found.", level="warn"))
    for msg in d_issues + h_issues + u_issues:
        print(f"  - {msg}")

    try:
        from scytaledroid.Utils.DisplayUtils import prompt_utils

        if not prompt_utils.prompt_yes_no("Apply fixes now?", default=False):
            print(sm.status("No changes applied.", level="info"))
            return
    except Exception:
        pass

    # Apply fixes
    _, fixes = audit_detected_permissions(apply_fixes=True)
    fixes_total.extend(fixes)
    _, fixes = audit_harvest_paths(apply_fixes=True)
    fixes_total.extend(fixes)
    _, fixes = audit_unknown_permissions(apply_fixes=True)
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
        _, fixes1 = audit_detected_permissions(apply_fixes=True)
        _, fixes2 = audit_harvest_paths(apply_fixes=True)
        total = len(fixes1) + len(fixes2)
        if total:
            print(sm.status(f"Applied {total} fix(es).", level="success"))
        else:
            print(sm.status("No fixes required.", level="info"))
    else:
        run_interactive()


if __name__ == "__main__":  # pragma: no cover
    main()
