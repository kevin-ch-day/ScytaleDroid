"""Simplified Database Scripts & Tasks menu (numeric keys only).

This menu focuses on curated diagnostics and maintenance tasks with
clear numeric options.
"""

from __future__ import annotations

from datetime import datetime
from typing import Callable, Dict, List, Tuple

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def _task_run_diagnostics() -> None:
    from ..scripts.diagnostics import run_diagnostics

    run_diagnostics()


def _task_schema_health() -> None:
    from ..scripts.schema_health import run_schema_health_check

    run_schema_health_check()


def _task_coverage_checks() -> None:
    """Run canonicalization and mapping coverage checks."""
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:
        print(status_messages.status(f"Import failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_section("Coverage: framework detections mapping to catalog (FQN view)")
    try:
        rows = core_q.run_sql(
            """
            SELECT
              SUM(CASE WHEN f.perm_name IS NOT NULL THEN 1 ELSE 0 END) AS mapped,
              COUNT(*) AS total,
              ROUND(100 * SUM(CASE WHEN f.perm_name IS NOT NULL THEN 1 ELSE 0 END) / NULLIF(COUNT(*),0), 2) AS pct
            FROM v_detected_permissions_fqn d
            LEFT JOIN android_framework_permissions f
              ON f.perm_name = d.detected_fqn
            WHERE d.namespace='android.permission'
            """,
            fetch="all",
        )
        menu_utils.print_table(["mapped", "total", "%"], rows or [])
    except Exception as exc:
        print(status_messages.status(f"Coverage query failed: {exc}", level="error"))

    print()
    menu_utils.print_section("Mapping drift: mappings pointing to missing catalog entries")
    try:
        rows = core_q.run_sql(
            """
            SELECT COUNT(*) AS missing
            FROM permission_signal_mappings sm
            LEFT JOIN android_framework_permissions f ON f.perm_name = sm.perm_name
            WHERE f.perm_name IS NULL
            """,
            fetch="all",
        )
        menu_utils.print_table(["missing"], rows or [])
    except Exception as exc:
        print(status_messages.status(f"Mapping drift query failed: {exc}", level="error"))

    print()
    menu_utils.print_section("Catalog duplicates (should be 0)")
    try:
        rows = core_q.run_sql(
            "SELECT perm_name, COUNT(*) AS c FROM android_framework_permissions GROUP BY perm_name HAVING c>1 ORDER BY c DESC",
            fetch="all",
        )
        menu_utils.print_table(["perm_name", "count"], rows or [])
    except Exception as exc:
        print(status_messages.status(f"Duplicate scan failed: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()


def _task_inventory_sanity_quick() -> None:
    """Quick inventory sanity checks: sha uniqueness, latest view, splits, orphans."""
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:
        print(status_messages.status(f"Import failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_section("APK repository: basic sanity")
    try:
        sha_rows = core_q.run_sql(
            "SELECT COUNT(*) - COUNT(DISTINCT sha256) AS duplicate_sha FROM android_apk_repository",
            fetch="all",
        )
        menu_utils.print_table(["duplicate_sha"], sha_rows or [])
    except Exception as exc:
        print(status_messages.status(f"SHA check failed: {exc}", level="error"))

    print()
    menu_utils.print_section("Latest view correctness (non-base should be 0)")
    try:
        bad_row = core_q.run_sql(
            "SELECT COUNT(*) FROM vw_latest_apk_per_package WHERE COALESCE(is_split_member,0) <> 0",
            fetch="one",
        )
        nbad = int(bad_row[0]) if bad_row else 0
        level = "success" if nbad == 0 else "warn"
        print(status_messages.status(f"non-base rows in view: {nbad}", level=level))
    except Exception as exc:
        print(status_messages.status(f"View check failed: {exc}", level="warn"))

    print()
    menu_utils.print_section("Split/base hygiene (splits without base)")
    try:
        rows = core_q.run_sql(
            """
            SELECT COUNT(*) AS splits_without_base
            FROM android_apk_repository ar
            WHERE ar.is_split_member = 1
              AND NOT EXISTS (
                SELECT 1 FROM android_apk_repository b WHERE b.package_name=ar.package_name AND b.is_split_member=0
              )
            """,
            fetch="all",
        )
        menu_utils.print_table(["splits_without_base"], rows or [])
    except Exception as exc:
        print(status_messages.status(f"Split hygiene query failed: {exc}", level="error"))

    print()
    menu_utils.print_section("Orphan checks (core tables)")
    checks = [
        (
            "Detected permissions -> APK repository",
            "SELECT COUNT(*) FROM android_detected_permissions dp LEFT JOIN android_apk_repository ar ON ar.apk_id = dp.apk_id WHERE ar.apk_id IS NULL",
        ),
        (
            "Artifact paths -> APK repository",
            "SELECT COUNT(*) FROM harvest_artifact_paths hp LEFT JOIN android_apk_repository ar ON ar.apk_id = hp.apk_id WHERE ar.apk_id IS NULL",
        ),
        (
            "Source paths -> APK repository",
            "SELECT COUNT(*) FROM harvest_source_paths hs LEFT JOIN android_apk_repository ar ON ar.apk_id = hs.apk_id WHERE ar.apk_id IS NULL",
        ),
    ]
    for label, sql in checks:
        try:
            row = core_q.run_sql(sql, fetch="one")
            n = int(row[0]) if row else 0
            level = "success" if n == 0 else "warn"
            print(status_messages.status(f"{label}: {n} orphan(s)", level=level))
        except Exception as exc:
            print(status_messages.status(f"{label}: query failed: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()


def _task_scoring_sanity_quick() -> None:
    """Scoring sanity: grade thresholds monotonicity + excluded counts."""
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:
        print(status_messages.status(f"Import failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    print()
    menu_utils.print_section("Grade monotonicity check (permission_audit_apps)")
    try:
        row = core_q.run_sql(
            """
            SELECT COUNT(*) AS inconsistent
            FROM permission_audit_apps paa
            WHERE NOT (
                (paa.grade='A' AND paa.score_capped <= 3.0) OR
                (paa.grade='B' AND paa.score_capped > 3.0 AND paa.score_capped <= 5.0) OR
                (paa.grade='C' AND paa.score_capped > 5.0 AND paa.score_capped <= 7.0) OR
                (paa.grade='D' AND paa.score_capped > 7.0 AND paa.score_capped <= 8.5) OR
                (paa.grade='F' AND paa.score_capped > 8.5)
            )
            """,
            fetch="one",
        )
        n = int(row[0]) if row else 0
        level = "success" if n == 0 else "warn"
        print(status_messages.status(f"inconsistent grades: {n}", level=level))
    except Exception as exc:
        print(status_messages.status(f"Monotonicity query failed: {exc}", level="error"))

    print()
    menu_utils.print_section("Excluded permissions (AdServices) present in detections")
    try:
        row = core_q.run_sql(
            "SELECT COUNT(*) FROM android_detected_permissions WHERE namespace='android.permission' AND perm_name LIKE 'ACCESS_ADSERVICES_%'",
            fetch="one",
        )
        count_ads = int(row[0]) if row else 0
        level = "info"
        print(status_messages.status(f"AdServices detections (excluded from scoring): {count_ads}", level=level))
    except Exception as exc:
        print(status_messages.status(f"AdServices count failed: {exc}", level="error"))

    prompt_utils.press_enter_to_continue()



def scripts_menu() -> None:
    """Render the Database Scripts menu (numeric options only)."""

    while True:
        print()
        menu_utils.print_header("Database Scripts & Tasks")

        # Compute status for dynamic repairs
        from ..scripts.status import compute_script_status
        status = compute_script_status()

        # Build static options
        entries: List[Tuple[str, str, Callable[[], None]]] = [
            ("Database diagnostics (analyze SQL)", "Execute diagnostic SQL and show results.", _task_run_diagnostics),
            ("Schema health check (read-only)", "Run non-destructive checks for schema/index consistency.", _task_schema_health),
            ("Coverage checks (FQN + mappings)", "Canonicalization coverage, mapping drift, cardinality.", _task_coverage_checks),
            ("Inventory sanity (APKs)", "Latest view correctness, orphans, split/base hygiene.", _task_inventory_sanity_quick),
            ("Scoring sanity", "Grades vs thresholds; AdServices excluded counts.", _task_scoring_sanity_quick),
        ]

        # Dynamic repair actions (numbered after static ones)
        repairs: List[Tuple[str, str, Callable[[], None]]] = []
        if status.get("vendor_misclassified", 0) > 0:
            from ..scripts.repairs import clean_vendor_framework_namespace as fn
            repairs.append((f"Clean vendor rows in android.permission namespace ({status['vendor_misclassified']})", "Delete vendor rows that are framework namespace.", fn))
        if status.get("unknown_vendor_match", 0) > 0:
            from ..scripts.repairs import promote_unknown_to_vendor as fn
            repairs.append((f"Reclassify unknown → vendor via suffix match ({status['unknown_vendor_match']})", "Set classification='vendor' when suffix matches vendor (non-android namespace).", fn))
        if status.get("idx_sha256_dup", False):
            from ..scripts.repairs import drop_redundant_sha256_index as fn
            repairs.append(("Drop redundant sha256 index on APK repository", "Remove idx_sha256 when uk_sha256 exists.", fn))
        if status.get("core_mappings_missing", 0) > 0:
            from ..scripts.repairs import seed_signal_mappings_core as fn
            repairs.append(("Seed core signal mappings", "Idempotent insert/update of key signal mappings.", fn))
        if status.get("legacy_seeds_missing", 0) > 0:
            from ..scripts.repairs import seed_legacy_framework as fn
            repairs.append((f"Seed legacy framework permissions ({status['legacy_seeds_missing']} missing)", "Upsert legacy/missing framework constants to reduce 'unmatched' unknowns.", fn))
        if status.get("dp_unknown_count", 0) > 0 and status.get("unknown_catalog_missing", 0) > 0:
            from ..scripts.repairs import backfill_unknowns as fn
            repairs.append((
                "Backfill unknown catalog from detections",
                "Insert distinct unknown perm names into android_unknown_permissions.",
                fn,
            ))

        # Merge and number
        all_entries = entries + repairs
        numbered: List[Tuple[str, str, str]] = []
        handlers: Dict[str, Callable[[], None]] = {}
        for idx, (label, desc, fn) in enumerate(all_entries, start=1):
            key = str(idx)
            numbered.append((key, label, desc))
            handlers[key] = fn

        # Render menu
        menu_utils.print_menu(numbered, padding=True, show_exit=True, show_descriptions=True)
        valid_keys = [k for k in handlers.keys()] + ["0"]
        choice = prompt_utils.get_choice(valid=valid_keys, default="0")
        if choice == "0":
            break
        handler = handlers.get(choice)
        if handler is None:
            continue
        handler()

__all__ = ["scripts_menu"]
