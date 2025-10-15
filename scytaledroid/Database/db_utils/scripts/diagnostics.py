"""Diagnostics and analysis helpers for Scripts menu."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages


def run_diagnostics() -> None:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:
        print(status_messages.status(f"DB import failed: {exc}", level="error"))
        return

    print()
    menu_utils.print_section("Resolution matrix (unknown → framework/vendor)")
    try:
        rows = core_q.run_sql(
            """
            SELECT up.perm_name AS unknown_short,
                   CASE
                     WHEN f.perm_name IS NOT NULL THEN 'framework'
                     WHEN v.vendor_perm_id IS NOT NULL AND v.namespace <> 'android.permission' THEN 'vendor'
                     WHEN v.vendor_perm_id IS NOT NULL AND v.namespace = 'android.permission' THEN 'vendor-misclassified'
                     ELSE 'unmatched'
                   END AS resolution,
                   COALESCE(f.protection,'-') AS framework_protection,
                   COALESCE(v.namespace,'-') AS vendor_ns
            FROM android_unknown_permissions up
            LEFT JOIN android_framework_permissions f
              ON f.short = up.perm_name
              OR f.perm_name = CONCAT('android.permission.', up.perm_name)
            LEFT JOIN android_vendor_permissions v
              ON up.perm_name = SUBSTRING_INDEX(v.perm_name, '.', -1)
            ORDER BY resolution, unknown_short
            """,
            fetch="all",
        )
        menu_utils.print_table(["unknown_short", "resolution", "framework_prot", "vendor_ns"], rows or [])
    except Exception as exc:
        print(status_messages.status(f"Query failed: {exc}", level="error"))

    print()
    menu_utils.print_section("Resolution counts")
    try:
        rows = core_q.run_sql(
            """
            SELECT resolution, COUNT(*) AS n
            FROM (
              SELECT up.perm_name,
                     CASE
                       WHEN f.perm_name IS NOT NULL THEN 'framework'
                       WHEN v.vendor_perm_id IS NOT NULL AND v.namespace <> 'android.permission' THEN 'vendor'
                       WHEN v.vendor_perm_id IS NOT NULL AND v.namespace = 'android.permission' THEN 'vendor-misclassified'
                       ELSE 'unmatched'
                     END AS resolution
              FROM android_unknown_permissions up
              LEFT JOIN android_framework_permissions f
                ON f.short = up.perm_name
                OR f.perm_name = CONCAT('android.permission.', up.perm_name)
              LEFT JOIN android_vendor_permissions v
                ON up.perm_name = SUBSTRING_INDEX(v.perm_name, '.', -1)
            ) x
            GROUP BY resolution
            ORDER BY n DESC
            """,
            fetch="all",
        )
        menu_utils.print_table(["resolution", "count"], rows or [])
        counters = {r[0]: int(r[1]) for r in (rows or []) if len(r) >= 2}
        if counters.get('vendor-misclassified', 0) > 0:
            print(status_messages.status("Vendor rows using android.permission namespace detected (use repair: clean vendor rows).", level="warn"))
        if counters.get('unmatched', 0) > 0:
            print(status_messages.status("Unmatched unknowns remain — likely legacy/system or vendor not in catalog.", level="warn"))
    except Exception as exc:
        print(status_messages.status(f"Count query failed: {exc}", level="error"))

    # Unknown detections with framework namespace
    print()
    menu_utils.print_section("Unknown detections with android.permission namespace")
    try:
        rows = core_q.run_sql(
            """
            SELECT dp.perm_name, COUNT(*) AS n
            FROM android_detected_permissions dp
            WHERE COALESCE(dp.classification,'unknown') = 'unknown'
              AND dp.namespace = 'android.permission'
            GROUP BY dp.perm_name
            ORDER BY n DESC
            """,
            fetch="all",
        )
        menu_utils.print_table(["perm_name", "count"], rows or [])
    except Exception as exc:
        print(status_messages.status(f"Query failed: {exc}", level="error"))

    # Vendor rows misclassified
    print()
    menu_utils.print_section("Vendor rows in android.permission namespace (should be framework)")
    try:
        rows = core_q.run_sql("SELECT perm_name, namespace FROM android_vendor_permissions WHERE namespace='android.permission' ORDER BY perm_name", fetch="all")
        menu_utils.print_table(["perm_name", "namespace"], rows or [])
    except Exception as exc:
        print(status_messages.status(f"Query failed: {exc}", level="error"))

    # Unknown → vendor suffix matches
    print()
    menu_utils.print_section("Unknown → vendor suffix matches (with usage counts)")
    try:
        rows = core_q.run_sql(
            """
            SELECT up.perm_name AS unknown_short,
                   v.perm_name  AS vendor_full,
                   v.namespace  AS vendor_ns,
                   COUNT(dp.detected_id) AS occurrences
            FROM android_unknown_permissions up
            JOIN android_vendor_permissions v
              ON up.perm_name = SUBSTRING_INDEX(v.perm_name, '.', -1)
            LEFT JOIN android_detected_permissions dp
              ON dp.perm_name = up.perm_name
             AND COALESCE(dp.classification,'unknown') = 'unknown'
            GROUP BY up.perm_name, v.perm_name, v.namespace
            ORDER BY occurrences DESC
            """,
            fetch="all",
        )
        menu_utils.print_table(["unknown_short", "vendor_full", "vendor_ns", "occurrences"], rows or [])
    except Exception as exc:
        print(status_messages.status(f"Query failed: {exc}", level="error"))

    print()
    menu_utils.print_section("Unknown detections by source")
    try:
        rows = core_q.run_sql("SELECT COALESCE(source,'-') AS src, COUNT(*) AS n FROM android_detected_permissions WHERE COALESCE(classification,'unknown')='unknown' GROUP BY src ORDER BY n DESC", fetch="all")
        menu_utils.print_table(["source", "count"], rows or [])
    except Exception as exc:
        print(status_messages.status(f"Query failed: {exc}", level="error"))

    print()
    menu_utils.print_section("Unknowns by package (top 25)")
    try:
        rows = core_q.run_sql("SELECT package_name, COUNT(*) AS n FROM android_detected_permissions WHERE COALESCE(classification,'unknown')='unknown' GROUP BY package_name ORDER BY n DESC LIMIT 25", fetch="all")
        menu_utils.print_table(["package", "count"], rows or [])
    except Exception as exc:
        print(status_messages.status(f"Query failed: {exc}", level="error"))

    print()
    menu_utils.print_section("Normalization checks")
    try:
        row1 = core_q.run_sql("SELECT COUNT(*) FROM android_detected_permissions WHERE perm_name REGEXP '(^\\\\s|\\\\s$)'", fetch="one")
        row2 = core_q.run_sql("SELECT COUNT(*) FROM android_detected_permissions WHERE COALESCE(classification,'unknown')='unknown' AND perm_name REGEXP '[a-z]'", fetch="one")
        suspicious = int(row1[0]) if row1 else 0
        lowercase = int(row2[0]) if row2 else 0
        menu_utils.print_table(["check", "count"], [["leading/trailing whitespace", suspicious], ["lowercase in unknown constants", lowercase]])
    except Exception as exc:
        print(status_messages.status(f"Normalization queries failed: {exc}", level="error"))

    print()
    menu_utils.print_section("Framework coverage: AdServices presence")
    try:
        rows = core_q.run_sql("SELECT perm_name, short, protection FROM android_framework_permissions WHERE perm_name LIKE 'android.permission.ACCESS_ADSERVICES_%' OR short LIKE 'ACCESS_ADSERVICES_%' ORDER BY perm_name", fetch="all")
        menu_utils.print_table(["perm_name", "short", "protection"], rows or [])
        if not rows:
            print(status_messages.status("AdServices perms not present in framework catalog (expected for many API levels).", level="info"))
    except Exception as exc:
        print(status_messages.status(f"Coverage query failed: {exc}", level="error"))


def show_sql_bundle() -> None:
    from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages
    queries: list[tuple[str, str]] = []
    # For brevity, provide just the resolution matrix and counts here
    queries.append(("Resolution matrix", "SELECT up.perm_name AS unknown_short, CASE WHEN f.perm_name IS NOT NULL THEN 'framework' WHEN v.vendor_perm_id IS NOT NULL AND v.namespace <> 'android.permission' THEN 'vendor' WHEN v.vendor_perm_id IS NOT NULL AND v.namespace = 'android.permission' THEN 'vendor-misclassified' ELSE 'unmatched' END AS resolution, COALESCE(f.protection,'-') AS framework_protection, COALESCE(v.namespace,'-') AS vendor_ns FROM android_unknown_permissions up LEFT JOIN android_framework_permissions f ON f.short = up.perm_name OR f.perm_name = CONCAT('android.permission.', up.perm_name) LEFT JOIN android_vendor_permissions v ON up.perm_name = SUBSTRING_INDEX(v.perm_name, '.', -1) ORDER BY resolution, unknown_short;"))
    queries.append(("Resolution counts", "SELECT resolution, COUNT(*) AS n FROM (SELECT up.perm_name, CASE WHEN f.perm_name IS NOT NULL THEN 'framework' WHEN v.vendor_perm_id IS NOT NULL AND v.namespace <> 'android.permission' THEN 'vendor' WHEN v.vendor_perm_id IS NOT NULL AND v.namespace = 'android.permission' THEN 'vendor-misclassified' ELSE 'unmatched' END AS resolution FROM android_unknown_permissions up LEFT JOIN android_framework_permissions f ON f.short = up.perm_name OR f.perm_name = CONCAT('android.permission.', up.perm_name) LEFT JOIN android_vendor_permissions v ON up.perm_name = SUBSTRING_INDEX(v.perm_name, '.', -1)) x GROUP BY resolution ORDER BY n DESC;"))

    print()
    menu_utils.print_section("Diagnostic SQL bundle")
    for title, sql in queries:
        print(f"-- {title}\n{sql}\n")
    try:
        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        out_dir = Path("output/sql")
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"diagnostics-{ts}.sql"
        payload = []
        for title, sql in queries:
            payload.append(f"-- {title}\n{sql.strip()}\n")
        path.write_text("\n".join(payload), encoding="utf-8")
        print(status_messages.status(f"Saved SQL bundle to {path}", level="success"))
    except Exception as exc:
        print(status_messages.status(f"Could not write SQL file: {exc}", level="warn"))

__all__ = ["run_diagnostics", "show_sql_bundle"]

