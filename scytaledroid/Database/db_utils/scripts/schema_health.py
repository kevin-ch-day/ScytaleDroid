"""Schema health checks for the Scripts menu."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages


def run_schema_health_check() -> None:
    from scytaledroid.Database.tools import schema_audit
    from scytaledroid.Database.db_core import db_queries as core_q

    print()
    menu_utils.print_section("Schema audit (read-only)")
    d_issues, _ = schema_audit.audit_detected_permissions(apply_fixes=False)
    h_issues, _ = schema_audit.audit_harvest_paths(apply_fixes=False)
    u_issues, _ = schema_audit.audit_unknown_permissions(apply_fixes=False)
    issues_total = len(d_issues) + len(h_issues) + len(u_issues)
    if issues_total == 0:
        print(status_messages.status("Schema health: OK — no issues found.", level="success"))
    else:
        print(status_messages.status(f"Schema health: {issues_total} issue(s) found.", level="warn"))
        for msg in d_issues + h_issues + u_issues:
            print(f"  - {msg}")

    try:
        row = core_q.run_sql(
            """
            SELECT SUM(idx_name IN ('idx_sha256')) AS has_dup,
                   SUM(idx_name IN ('uk_sha256'))  AS has_unique
            FROM (
              SELECT DISTINCT index_name AS idx_name
              FROM information_schema.statistics
              WHERE table_schema = DATABASE()
                AND table_name = 'android_apk_repository'
                AND column_name = 'sha256'
            ) t
            """,
            fetch="one",
        )
        has_dup = int(row[0]) if row else 0
        has_unique = int(row[1]) if row else 0
        if has_dup and has_unique:
            print(status_messages.status("android_apk_repository: redundant non-unique idx_sha256 present (uk_sha256 already exists)", level="warn"))
        else:
            print(status_messages.status("android_apk_repository: sha256 indexes look OK", level="success"))
    except Exception as exc:
        print(status_messages.status(f"Index check failed: {exc}", level="error"))

__all__ = ["run_schema_health_check"]

