"""Interactive submenu for DB scripts and maintenance tasks.

Each task is designed to be idempotent where possible and will print
succinct results that you can copy back for review and refinement.
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages


def scripts_menu() -> None:
    """Render the Database Scripts menu (flat list; context-aware)."""

    while True:
        print()
        menu_utils.print_header("Database Scripts & Tasks")

        # Compute current DB state to decide which actions to show
        from .scripts.status import compute_script_status
        status = compute_script_status()

        options: list[tuple[str, str, str]] = []
        options.append(("1", "Run diagnostics (SQL) and analyze", "Execute curated SQL and show results."))
        options.append(("2", "Schema health check (read-only)", "Run non-destructive checks for schema/index consistency."))

        # Repair actions (show only when applicable)
        if status.get("vendor_misclassified", 0) > 0:
            options.append(("7", f"Clean vendor rows in android.permission namespace ({status['vendor_misclassified']})", "Delete vendor rows that are framework namespace."))
        if status.get("unknown_fw_ns", 0) > 0:
            options.append(("2f", f"Promote unknown (namespace=android.permission) → framework ({status['unknown_fw_ns']})", "Set classification='framework' for unknown detections declaring framework namespace."))
        if status.get("unknown_vendor_match", 0) > 0:
            options.append(("1r", f"Reclassify unknown → vendor via suffix match ({status['unknown_vendor_match']})", "Set classification='vendor' when suffix matches vendor (non-android namespace)."))
        if status.get("idx_sha256_dup", False):
            options.append(("3", "Drop redundant sha256 index on APK repository", "Remove idx_sha256 when uk_sha256 exists."))
        if status.get("core_mappings_missing", 0) > 0:
            options.append(("4", "Seed core signal mappings", "Idempotent insert/update of key signal mappings."))
        if status.get("legacy_seeds_missing", 0) > 0:
            options.append(("9", f"Seed legacy framework permissions ({status['legacy_seeds_missing']} missing)", "Upsert legacy/missing framework constants to reduce 'unmatched' unknowns."))
        if status.get("dp_unknown_count", 0) > 0 and status.get("unknown_catalog_missing", 0) > 0:
            options.append(("8", "Backfill unknown catalog from detections", "Insert distinct unknown perm names into android_unknown_permissions."))

        # Utility actions
        # Skip permission catalog refresh here; handled in Harvest Android Permissions menu
        options.append(("11", "Create/Refresh DB views", "Define reporting views (latest APK, latest permission risk)."))
        options.append(("10", "User Scripts (SQL/Python)", "Discover, run, create, or delete ad-hoc scripts."))
        options.append(("0", "Back to main menu", None))

        menu_utils.print_menu(options, padding=True, show_exit=False, show_descriptions=True)
        valid = [o[0] for o in options]
        choice = prompt_utils.get_choice(valid=valid, default="0")

        if choice == "0":
            break
        elif choice == "1":
            from .scripts.diagnostics import run_diagnostics
            run_diagnostics()
        elif choice == "2":
            from .scripts.schema_health import run_schema_health_check
            run_schema_health_check()
        elif choice == "7":
            from .scripts.repairs import clean_vendor_framework_namespace
            clean_vendor_framework_namespace()
        elif choice == "2f":
            from .scripts.repairs import promote_unknown_android_perm_to_framework
            promote_unknown_android_perm_to_framework()
        elif choice == "1r":
            from .scripts.repairs import promote_unknown_to_vendor
            promote_unknown_to_vendor()
        elif choice == "3":
            from .scripts.repairs import drop_redundant_sha256_index
            drop_redundant_sha256_index()
        elif choice == "4":
            from .scripts.repairs import seed_signal_mappings_core
            seed_signal_mappings_core()
        elif choice == "9":
            from .scripts.repairs import seed_legacy_framework
            seed_legacy_framework()
        elif choice == "8":
            from .scripts.repairs import backfill_unknowns
            backfill_unknowns()
        elif choice == "10":
            _user_scripts_submenu()
        elif choice == "11":
            from scytaledroid.Database.db_func.views import ensure_views
            ok = ensure_views()
            level = "success" if ok else "error"
            print(status_messages.status("Views created/refreshed." if ok else "Failed to create views.", level=level))
            prompt_utils.press_enter_to_continue()

def _task_refresh_framework_catalog() -> None:
    from scytaledroid.Utils.DisplayUtils import status_messages
    print(status_messages.status("Preparing to write framework catalog to DB…", level="info"))
    try:
        from scytaledroid.Utils.AndroidPermCatalog.constants import DEFAULT_CACHE
        from scytaledroid.Utils.AndroidPermCatalog import api as perm_api
        from scytaledroid.Database.db_func import framework_permissions as fp

        # Ensure table exists
        if not fp.table_exists() and not fp.ensure_table():
            print(status_messages.status("Unable to create android_framework_permissions table.", level="error"))
            prompt_utils.press_enter_to_continue()
            return

        items = []
        if DEFAULT_CACHE.exists():
            items = perm_api.load_catalog_json(DEFAULT_CACHE)
        if not items:
            try:
                items = perm_api.load_catalog("auto")
                perm_api.save_catalog_json(
                    DEFAULT_CACHE,
                    items,
                    source="auto",
                    base_url=perm_api.ONLINE_URL,
                    base_urls=[perm_api.ONLINE_URL, *perm_api.additional_doc_urls()],
                )
            except Exception as exc:
                print(status_messages.status(f"Failed to load framework catalog: {exc}", level="error"))
                prompt_utils.press_enter_to_continue()
                return

        processed = fp.upsert_permissions(items, source="db-cli")
        print(status_messages.status(f"Upserts: {processed} / Items: {len(items)}", level="success"))
    except Exception as exc:
        print(status_messages.status(f"DB write failed: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()


def _task_backfill_unknowns() -> None:
    from scytaledroid.Database.db_core import db_queries as core_q

    try:
        count_row = core_q.run_sql(
            """
            SELECT COUNT(*) AS missing
            FROM (
                SELECT DISTINCT dp.perm_name
                FROM android_detected_permissions dp
                WHERE dp.classification = 'unknown'
            ) names
            LEFT JOIN android_unknown_permissions up
              ON up.perm_name = names.perm_name
            WHERE up.unknown_perm_id IS NULL
            """,
            fetch="one",
        )
        missing = int(count_row[0]) if count_row else 0
    except Exception as exc:
        print(status_messages.status(f"Count query failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    try:
        core_q.run_sql(
            """
            INSERT INTO android_unknown_permissions (perm_name, notes)
            SELECT names.perm_name, 'auto-import from detected'
            FROM (
                SELECT DISTINCT dp.perm_name
                FROM android_detected_permissions dp
                WHERE dp.classification = 'unknown'
            ) names
            LEFT JOIN android_unknown_permissions up
              ON up.perm_name = names.perm_name
            WHERE up.unknown_perm_id IS NULL
            """
        )
        print(status_messages.status(f"Inserted {missing} unknown permission row(s).", level="success"))
    except Exception as exc:
        print(status_messages.status(f"Backfill failed: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()


def _task_seed_signal_mappings_core() -> None:
    """Seed high-confidence mappings for core signals.

    Requires permission_signal_catalog and permission_signal_mappings tables.
    """

    try:
        from scytaledroid.Database.db_func import permission_support as support
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:
        print(status_messages.status(f"Module import failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    # Ensure tables exist and defaults are present
    support.ensure_all()
    support.seed_signal_catalog()  # idempotent

    mappings: list[tuple[str, str, str]] = [
        ("camera", "android.permission.CAMERA", "android.permission"),
        ("microphone", "android.permission.RECORD_AUDIO", "android.permission"),
        ("precise_location", "android.permission.ACCESS_FINE_LOCATION", "android.permission"),
        ("background_location", "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission"),
        ("overlay", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission"),
        ("contacts", "android.permission.READ_CONTACTS", "android.permission"),
        ("contacts", "android.permission.WRITE_CONTACTS", "android.permission"),
        ("calls", "android.permission.READ_CALL_LOG", "android.permission"),
        ("calls", "android.permission.READ_PHONE_STATE", "android.permission"),
        ("sms", "android.permission.READ_SMS", "android.permission"),
        ("sms", "android.permission.SEND_SMS", "android.permission"),
        ("storage_broad", "android.permission.READ_EXTERNAL_STORAGE", "android.permission"),
        ("storage_broad", "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission"),
        ("bt_triad", "android.permission.BLUETOOTH_SCAN", "android.permission"),
        ("bt_triad", "android.permission.BLUETOOTH_CONNECT", "android.permission"),
        ("bt_triad", "android.permission.BLUETOOTH_ADVERTISE", "android.permission"),
        ("notifications", "android.permission.POST_NOTIFICATIONS", "android.permission"),
    ]

    inserted = 0
    updated = 0

    for signal_key, perm_name, namespace in mappings:
        try:
            exists = core_q.run_sql(
                """
                SELECT mapping_id, confidence FROM permission_signal_mappings
                WHERE signal_key=%s AND perm_name=%s AND COALESCE(namespace,'') = %s
                """,
                (signal_key, perm_name, namespace or ""),
                fetch="one",
            )
            if exists:
                # Ensure confidence is 'high'
                core_q.run_sql(
                    """
                    UPDATE permission_signal_mappings
                    SET confidence='high'
                    WHERE signal_key=%s AND perm_name=%s AND COALESCE(namespace,'')=%s
                    """,
                    (signal_key, perm_name, namespace or ""),
                )
                updated += 1
            else:
                core_q.run_sql(
                    """
                    INSERT INTO permission_signal_mappings
                        (signal_key, perm_name, namespace, confidence)
                    VALUES (%s, %s, %s, 'high')
                    """,
                    (signal_key, perm_name, namespace),
                )
                inserted += 1
        except Exception:
            # Continue on individual failures to keep task resilient
            continue

    if inserted or updated:
        print(status_messages.status(f"Mappings: inserted {inserted}, updated {updated}", level="success"))
    else:
        print(status_messages.status("Mappings already up to date", level="info"))
    prompt_utils.press_enter_to_continue()


def _task_create_audit_snapshot() -> None:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:
        print(status_messages.status(f"Import failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    # Count distinct packages in detections
    try:
        pkg_row = core_q.run_sql(
            "SELECT COUNT(DISTINCT package_name) FROM android_detected_permissions",
            fetch="one",
        )
        apps_total = int(pkg_row[0]) if pkg_row else 0
    except Exception as exc:
        print(status_messages.status(f"Failed to count packages: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    snapshot_key = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    try:
        snapshot_id = core_q.run_sql(
            """
            INSERT INTO permission_audit_snapshots (snapshot_key, scope_label, apps_total)
            VALUES (%s, 'All apps', %s)
            """,
            (snapshot_key, apps_total),
            return_lastrowid=True,
        )
    except Exception as exc:
        print(status_messages.status(f"Failed to create snapshot: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    # Populate audit apps with a lightweight scoring model
    try:
        core_q.run_sql(
            """
            INSERT INTO permission_audit_apps (
                snapshot_id, package_name, app_label,
                score_raw, score_capped, grade,
                dangerous_count, signature_count, vendor_count,
                details
            )
            SELECT
                %s AS snapshot_id,
                p.package_name,
                COALESCE(aad.app_name, '') AS app_label,
                -- score_raw: sum of default_weight across distinct signals
                (
                    SELECT COALESCE(SUM(sc.default_weight), 0.0)
                    FROM (
                        SELECT DISTINCT sm.signal_key
                        FROM android_detected_permissions d
                        JOIN permission_signal_mappings sm
                          ON sm.perm_name = d.perm_name
                         AND COALESCE(sm.namespace,'') = COALESCE(d.namespace,'')
                        WHERE d.package_name = p.package_name
                    ) ds
                    JOIN permission_signal_catalog sc ON sc.signal_key = ds.signal_key
                ) AS score_raw,
                -- cap at 10.0
                LEAST(
                    (
                        SELECT COALESCE(SUM(sc.default_weight), 0.0)
                        FROM (
                            SELECT DISTINCT sm.signal_key
                            FROM android_detected_permissions d
                            JOIN permission_signal_mappings sm
                              ON sm.perm_name = d.perm_name
                             AND COALESCE(sm.namespace,'') = COALESCE(d.namespace,'')
                            WHERE d.package_name = p.package_name
                        ) ds
                        JOIN permission_signal_catalog sc ON sc.signal_key = ds.signal_key
                    ), 10.0
                ) AS score_capped,
                -- grade based on capped score
                (
                    CASE
                        WHEN (
                            LEAST((
                                SELECT COALESCE(SUM(sc.default_weight), 0.0)
                                FROM (
                                    SELECT DISTINCT sm.signal_key
                                    FROM android_detected_permissions d
                                    JOIN permission_signal_mappings sm
                                      ON sm.perm_name = d.perm_name
                                     AND COALESCE(sm.namespace,'') = COALESCE(d.namespace,'')
                                    WHERE d.package_name = p.package_name
                                ) ds
                                JOIN permission_signal_catalog sc ON sc.signal_key = ds.signal_key
                            ), 10.0)
                        ) < 2.0 THEN 'A'
                        WHEN (
                            LEAST((
                                SELECT COALESCE(SUM(sc.default_weight), 0.0)
                                FROM (
                                    SELECT DISTINCT sm.signal_key
                                    FROM android_detected_permissions d
                                    JOIN permission_signal_mappings sm
                                      ON sm.perm_name = d.perm_name
                                     AND COALESCE(sm.namespace,'') = COALESCE(d.namespace,'')
                                    WHERE d.package_name = p.package_name
                                ) ds
                                JOIN permission_signal_catalog sc ON sc.signal_key = ds.signal_key
                            ), 10.0)
                        ) < 4.0 THEN 'B'
                        WHEN (
                            LEAST((
                                SELECT COALESCE(SUM(sc.default_weight), 0.0)
                                FROM (
                                    SELECT DISTINCT sm.signal_key
                                    FROM android_detected_permissions d
                                    JOIN permission_signal_mappings sm
                                      ON sm.perm_name = d.perm_name
                                     AND COALESCE(sm.namespace,'') = COALESCE(d.namespace,'')
                                    WHERE d.package_name = p.package_name
                                ) ds
                                JOIN permission_signal_catalog sc ON sc.signal_key = ds.signal_key
                            ), 10.0)
                        ) < 6.0 THEN 'C'
                        WHEN (
                            LEAST((
                                SELECT COALESCE(SUM(sc.default_weight), 0.0)
                                FROM (
                                    SELECT DISTINCT sm.signal_key
                                    FROM android_detected_permissions d
                                    JOIN permission_signal_mappings sm
                                      ON sm.perm_name = d.perm_name
                                     AND COALESCE(sm.namespace,'') = COALESCE(d.namespace,'')
                                    WHERE d.package_name = p.package_name
                                ) ds
                                JOIN permission_signal_catalog sc ON sc.signal_key = ds.signal_key
                            ), 10.0)
                        ) < 8.0 THEN 'D'
                        ELSE 'F'
                    END
                ) AS grade,
                -- counts by class/protection
                (SELECT COUNT(DISTINCT perm_name) FROM android_detected_permissions WHERE package_name=p.package_name AND classification='framework' AND protection='dangerous') AS dangerous_count,
                (SELECT COUNT(DISTINCT perm_name) FROM android_detected_permissions WHERE package_name=p.package_name AND classification='framework' AND protection='signature') AS signature_count,
                (SELECT COUNT(DISTINCT perm_name) FROM android_detected_permissions WHERE package_name=p.package_name AND classification='vendor') AS vendor_count,
                -- details: JSON signals present
                (
                    SELECT JSON_OBJECT('signals', JSON_ARRAYAGG(ds.signal_key))
                    FROM (
                        SELECT DISTINCT sm.signal_key
                        FROM android_detected_permissions d
                        JOIN permission_signal_mappings sm
                          ON sm.perm_name = d.perm_name
                         AND COALESCE(sm.namespace,'') = COALESCE(d.namespace,'')
                        WHERE d.package_name = p.package_name
                    ) ds
                ) AS details
            FROM (
                SELECT DISTINCT package_name FROM android_detected_permissions
            ) p
            LEFT JOIN android_app_definitions aad ON aad.package_name = p.package_name
            """,
            (snapshot_id,),
        )
        print(status_messages.status(f"Snapshot {snapshot_key} created (id={snapshot_id}).", level="success"))
    except Exception as exc:
        print(status_messages.status(f"Failed to populate audit apps: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()


def _task_check_orphans() -> None:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:
        print(status_messages.status(f"Import failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    checks: list[tuple[str, str]] = [
        (
            "Detected permissions -> APK repository",
            """
            SELECT COUNT(*) AS orphans
            FROM android_detected_permissions dp
            LEFT JOIN android_apk_repository ar ON ar.apk_id = dp.apk_id
            WHERE ar.apk_id IS NULL
            """,
        ),
        (
            "Artifact paths -> APK repository",
            """
            SELECT COUNT(*) AS orphans
            FROM harvest_artifact_paths hp
            LEFT JOIN android_apk_repository ar ON ar.apk_id = hp.apk_id
            WHERE ar.apk_id IS NULL
            """,
        ),
        (
            "Source paths -> APK repository",
            """
            SELECT COUNT(*) AS orphans
            FROM harvest_source_paths hs
            LEFT JOIN android_apk_repository ar ON ar.apk_id = hs.apk_id
            WHERE ar.apk_id IS NULL
            """,
        ),
    ]

    print()
    menu_utils.print_section("Orphan checks")

    for label, sql in checks:
        try:
            row = core_q.run_sql(sql, fetch="one")
            n = int(row[0]) if row else 0
            level = "success" if n == 0 else "warn"
            print(status_messages.status(f"{label}: {n} orphan(s)", level=level))
        except Exception as exc:
            print(status_messages.status(f"{label}: query failed: {exc}", level="error"))

    prompt_utils.press_enter_to_continue()


def _task_scan_duplicate_indexes() -> None:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:
        print(status_messages.status(f"Import failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    # Focus on known hot table first; can extend later
    print()
    menu_utils.print_section("Index scan: android_apk_repository")
    try:
        rows = core_q.run_sql(
            "SELECT index_name, non_unique, column_name FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'android_apk_repository' AND column_name='sha256' ORDER BY index_name",
            fetch="all",
        )
        menu_utils.print_table(["Index", "non_unique", "column"], rows or [])
        print(status_messages.status("If both unique and non-unique indexes exist on sha256, consider dropping the non-unique one.", level="info"))
    except Exception as exc:
        print(status_messages.status(f"Index query failed: {exc}", level="error"))

    prompt_utils.press_enter_to_continue()


def _task_top_unknowns(limit: int = 25) -> None:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:
        print(status_messages.status(f"Import failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    try:
        rows = core_q.run_sql(
            """
            SELECT perm_name, COUNT(*) AS n
            FROM android_detected_permissions
            WHERE classification='unknown'
            GROUP BY perm_name
            ORDER BY n DESC
            LIMIT %s
            """,
            (int(limit),),
            fetch="all",
        )
        print()
        menu_utils.print_section("Top unknown permissions")
        menu_utils.print_table(["Permission", "Count"], rows or [])
    except Exception as exc:
        print(status_messages.status(f"Query failed: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()


def _task_show_diagnostic_sql() -> None:
    """Print curated SQL you can copy into your SQL IDE."""

    from datetime import datetime
    from pathlib import Path

    queries: list[tuple[str, str]] = [
        (
            "Resolution matrix (unknown → framework/vendor)",
            """
SELECT up.perm_name AS unknown_short,
       CASE
         WHEN f.perm_name IS NOT NULL THEN 'framework'
         WHEN v.vendor_perm_id IS NOT NULL AND v.namespace <> 'android.permission' THEN 'vendor'
         WHEN v.vendor_perm_id IS NOT NULL AND v.namespace = 'android.permission' THEN 'vendor-misclassified'
         ELSE 'unmatched'
       END AS resolution,
       f.perm_name  AS framework_full,
       f.protection AS framework_protection,
       v.perm_name  AS vendor_full,
       v.namespace  AS vendor_ns
FROM android_unknown_permissions up
LEFT JOIN android_framework_permissions f
  ON f.short = up.perm_name
  OR f.perm_name = CONCAT('android.permission.', up.perm_name)
LEFT JOIN android_vendor_permissions v
  ON up.perm_name = SUBSTRING_INDEX(v.perm_name, '.', -1)
ORDER BY resolution, unknown_short;
""",
        ),
        (
            "Resolution counts",
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
ORDER BY n DESC;
""",
        ),
        (
            "Unknown detections with android.permission namespace",
            """
SELECT dp.perm_name, COUNT(*) AS n
FROM android_detected_permissions dp
WHERE COALESCE(dp.classification,'unknown') = 'unknown'
  AND dp.namespace = 'android.permission'
GROUP BY dp.perm_name
ORDER BY n DESC;
""",
        ),
        (
            "Vendor rows in android.permission namespace (should be framework)",
            """
SELECT v.perm_name, v.namespace
FROM android_vendor_permissions v
WHERE v.namespace = 'android.permission'
ORDER BY v.perm_name;
""",
        ),
        (
            "Unknown → vendor suffix matches (with usage counts)",
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
ORDER BY occurrences DESC;
""",
        ),
        (
            "Unknown detections by source",
            """
SELECT COALESCE(source,'-') AS src, COUNT(*) AS n
FROM android_detected_permissions
WHERE COALESCE(classification,'unknown') = 'unknown'
GROUP BY src
ORDER BY n DESC;
""",
        ),
        (
            "Unknowns by package (top 25)",
            """
SELECT package_name, COUNT(*) AS n
FROM android_detected_permissions
WHERE COALESCE(classification,'unknown') = 'unknown'
GROUP BY package_name
ORDER BY n DESC
LIMIT 25;
""",
        ),
        (
            "Normalization checks: leading/trailing whitespace",
            """
SELECT COUNT(*) AS suspicious
FROM android_detected_permissions
WHERE perm_name REGEXP '(^\\s|\\s$)';
""",
        ),
        (
            "Normalization checks: lowercase in short constants",
            """
SELECT perm_name, COUNT(*) AS n
FROM android_detected_permissions
WHERE COALESCE(classification,'unknown') = 'unknown'
  AND perm_name REGEXP '[a-z]'
GROUP BY perm_name
ORDER BY n DESC;
""",
        ),
        (
            "Framework coverage: AdServices presence",
            """
SELECT perm_name, short, protection
FROM android_framework_permissions
WHERE perm_name LIKE 'android.permission.ACCESS_ADSERVICES_%'
   OR short LIKE 'ACCESS_ADSERVICES_%'
ORDER BY perm_name;
""",
        ),
        (
            "Group contributions by package (replace :pkg)",
            """
-- Replace :pkg with a package name, e.g., 'com.facebook.katana'
SELECT ':pkg' AS package,
  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('ACCESS_FINE_LOCATION','ACCESS_COARSE_LOCATION','ACCESS_MEDIA_LOCATION') THEN 1 ELSE 0 END) AS loc_fg,
  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name='ACCESS_BACKGROUND_LOCATION' THEN 1 ELSE 0 END) AS loc_bg,
  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name='CAMERA' THEN 1 ELSE 0 END) AS cam,
  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('RECORD_AUDIO','CAPTURE_AUDIO_OUTPUT') THEN 1 ELSE 0 END) AS mic,
  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('READ_CONTACTS','WRITE_CONTACTS','GET_ACCOUNTS','MANAGE_ACCOUNTS') THEN 1 ELSE 0 END) AS cnt,
  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('READ_CALL_LOG','CALL_PHONE','READ_PHONE_STATE','READ_PHONE_NUMBERS','ANSWER_PHONE_CALLS') THEN 1 ELSE 0 END) AS phn,
  SUM(CASE WHEN dp.classification='framework' AND (dp.perm_name REGEXP '^READ_MEDIA_' OR dp.perm_name IN ('READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE','MANAGE_EXTERNAL_STORAGE')) THEN 1 ELSE 0 END) AS str,
  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('SEND_SMS','RECEIVE_SMS','READ_SMS','RECEIVE_MMS','RECEIVE_WAP_PUSH') THEN 1 ELSE 0 END) AS sms,
  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('BLUETOOTH_SCAN','BLUETOOTH_ADVERTISE','BLUETOOTH_CONNECT','NEARBY_WIFI_DEVICES') THEN 1 ELSE 0 END) AS bt,
  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('SYSTEM_ALERT_WINDOW','SYSTEM_OVERLAY_WINDOW') THEN 1 ELSE 0 END) AS ovr,
  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('POST_NOTIFICATIONS','BIND_NOTIFICATION_LISTENER_SERVICE','ACCESS_NOTIFICATION_POLICY') THEN 1 ELSE 0 END) AS noti,
  SUM(CASE WHEN dp.classification='vendor' AND (dp.perm_name LIKE '%AD_ID%' OR dp.perm_name LIKE '%ADVERTIS%' OR dp.perm_name LIKE '%INSTALL_REFERRER%') THEN 1 ELSE 0 END) AS ads
FROM android_detected_permissions dp
WHERE dp.package_name=':pkg';
""",
        ),
        (
            "Group permission list by package (replace :pkg)",
            """
-- Replace :pkg with a package name
SELECT 'LOC' AS grp, dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=':pkg' AND dp.classification='framework' AND (dp.perm_name IN ('ACCESS_FINE_LOCATION','ACCESS_COARSE_LOCATION','ACCESS_MEDIA_LOCATION','ACCESS_BACKGROUND_LOCATION'))
UNION ALL
SELECT 'CAM', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=':pkg' AND dp.classification='framework' AND (dp.perm_name IN ('CAMERA'))
UNION ALL
SELECT 'MIC', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=':pkg' AND dp.classification='framework' AND (dp.perm_name IN ('RECORD_AUDIO','CAPTURE_AUDIO_OUTPUT'))
UNION ALL
SELECT 'CNT', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=':pkg' AND dp.classification='framework' AND (dp.perm_name IN ('READ_CONTACTS','WRITE_CONTACTS','GET_ACCOUNTS','MANAGE_ACCOUNTS'))
UNION ALL
SELECT 'PHN', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=':pkg' AND dp.classification='framework' AND (dp.perm_name IN ('READ_CALL_LOG','CALL_PHONE','READ_PHONE_STATE','READ_PHONE_NUMBERS','ANSWER_PHONE_CALLS'))
UNION ALL
SELECT 'SMS', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=':pkg' AND dp.classification='framework' AND (dp.perm_name IN ('SEND_SMS','RECEIVE_SMS','READ_SMS','RECEIVE_MMS','RECEIVE_WAP_PUSH'))
UNION ALL
SELECT 'STR', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=':pkg' AND dp.classification='framework' AND ((dp.perm_name REGEXP '^READ_MEDIA_' OR dp.perm_name IN ('READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE','MANAGE_EXTERNAL_STORAGE')))
UNION ALL
SELECT 'BT', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=':pkg' AND dp.classification='framework' AND (dp.perm_name IN ('BLUETOOTH_SCAN','BLUETOOTH_ADVERTISE','BLUETOOTH_CONNECT','NEARBY_WIFI_DEVICES'))
UNION ALL
SELECT 'OVR', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=':pkg' AND dp.classification='framework' AND (dp.perm_name IN ('SYSTEM_ALERT_WINDOW','SYSTEM_OVERLAY_WINDOW'))
UNION ALL
SELECT 'NOT', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=':pkg' AND dp.classification='framework' AND (dp.perm_name IN ('POST_NOTIFICATIONS','BIND_NOTIFICATION_LISTENER_SERVICE','ACCESS_NOTIFICATION_POLICY'))
UNION ALL
SELECT 'ADS', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=':pkg' AND dp.classification='vendor' AND (dp.perm_name LIKE '%AD_ID%' OR dp.perm_name LIKE '%ADVERTIS%' OR dp.perm_name LIKE '%INSTALL_REFERRER%')
ORDER BY grp, perm_name;
""",
        ),
    ]

    # Render to screen
    print()
    for title, sql in queries:
        menu_utils.print_section(title)
        print(sql.strip())
        print()

    # Also write to a file for convenience
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

    prompt_utils.press_enter_to_continue("Press Enter when done copying the SQL…")


def _task_schema_health_check() -> None:
    """Run non-destructive schema checks and print findings."""
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

    # Redundant sha256 index on APK repository
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

    prompt_utils.press_enter_to_continue()


def _task_update_repair_menu() -> None:
    """Submenu for update/repair operations."""
    while True:
        print()
        menu_utils.print_section("Update/Repair operations")
        options = [
            ("1", "Reclassify unknown → vendor via suffix match", "Set classification='vendor' when suffix matches vendor (non-android namespace)."),
            ("2", "Promote unknown (namespace=android.permission) → framework", "Set classification='framework' for unknown detections declaring framework namespace."),
            ("3", "Drop redundant sha256 index on APK repository", "Remove idx_sha256 when uk_sha256 exists."),
            ("4", "Seed core signal mappings", "Idempotent insert/update of key signal mappings."),
            ("5", "Refresh framework permission catalog", "Download & upsert doc-derived metadata."),
            ("6", "Create audit snapshot and score apps", "Populate permission_audit_* with capped scores."),
            ("7", "Clean vendor rows in android.permission namespace", "Delete vendor rows that are framework namespace."),
            ("8", "Backfill unknown catalog from detections", "Insert distinct unknown perm names into android_unknown_permissions."),
            ("9", "Seed legacy framework permissions", "Upsert missing/legacy framework constants to reduce 'unmatched' unknowns."),
            ("0", "Back", None),
        ]
        menu_utils.print_menu(options, padding=True, show_exit=False, show_descriptions=True)
        choice = prompt_utils.get_choice(valid=[o[0] for o in options], default="0")

        if choice == "0":
            break
        elif choice == "1":
            _task_promote_unknown_to_vendor()
        elif choice == "2":
            _task_promote_unknown_android_perm_to_framework()
        elif choice == "3":
            _task_drop_redundant_sha256_index()
        elif choice == "4":
            _task_seed_signal_mappings_core()
        elif choice == "5":
            _task_refresh_framework_catalog()
        elif choice == "6":
            _task_create_audit_snapshot()
        elif choice == "7":
            _task_clean_vendor_framework_namespace()
        elif choice == "8":
            _task_backfill_unknowns()
        elif choice == "9":
            _task_seed_legacy_framework()


def _compute_script_status() -> dict:
    """Return counts/flags for conditional menu items."""
    status: dict = {
        "vendor_misclassified": 0,
        "unknown_fw_ns": 0,
        "unknown_vendor_match": 0,
        "idx_sha256_dup": False,
        "core_mappings_missing": 0,
        "legacy_seeds_missing": 0,
        "dp_unknown_count": 0,
        "unknown_catalog_missing": 0,
    }
    try:
        from scytaledroid.Database.db_core import db_queries as q
        # Vendor misclassified
        row = q.run_sql("SELECT COUNT(*) FROM android_vendor_permissions WHERE namespace='android.permission'", fetch="one")
        status["vendor_misclassified"] = int(row[0]) if row else 0
        # Unknown detections in framework namespace
        row = q.run_sql("SELECT COUNT(*) FROM android_detected_permissions WHERE COALESCE(classification,'unknown')='unknown' AND namespace='android.permission'", fetch="one")
        status["unknown_fw_ns"] = int(row[0]) if row else 0
        # Unknown → vendor suffix matches
        row = q.run_sql(
            """
            SELECT COUNT(*)
            FROM android_detected_permissions dp
            JOIN android_vendor_permissions v
              ON dp.perm_name = SUBSTRING_INDEX(v.perm_name, '.', -1)
            WHERE COALESCE(dp.classification,'unknown')='unknown'
              AND v.namespace <> 'android.permission'
            """,
            fetch="one",
        )
        status["unknown_vendor_match"] = int(row[0]) if row else 0
        # Redundant sha256 index
        row = q.run_sql(
            """
            SELECT SUM(index_name='idx_sha256') AS has_dup,
                   SUM(index_name='uk_sha256')  AS has_unique
            FROM information_schema.statistics
            WHERE table_schema = DATABASE()
              AND table_name = 'android_apk_repository'
              AND column_name = 'sha256'
            """,
            fetch="one",
        )
        if row:
            status["idx_sha256_dup"] = bool(int(row[0]) and int(row[1]))
        # Core mappings present
        row = q.run_sql("SELECT COUNT(*) FROM permission_signal_mappings", fetch="one")
        status["core_mappings_missing"] = 0 if (row and int(row[0]) > 0) else 1
        # Legacy seeds missing (check a subset)
        row = q.run_sql(
            """
            SELECT COUNT(*) AS missing
            FROM (
              SELECT 'AUTHENTICATE_ACCOUNTS' AS short UNION ALL
              SELECT 'MANAGE_ACCOUNTS' UNION ALL
              SELECT 'FLASHLIGHT' UNION ALL
              SELECT 'CAPTURE_VIDEO_OUTPUT' UNION ALL
              SELECT 'DOWNLOAD_WITHOUT_NOTIFICATION'
            ) s
            LEFT JOIN android_framework_permissions f ON f.short = s.short
            WHERE f.perm_name IS NULL
            """,
            fetch="one",
        )
        status["legacy_seeds_missing"] = int(row[0]) if row else 0
        # Unknown catalog backfill need
        row = q.run_sql("SELECT COUNT(*) FROM android_detected_permissions WHERE COALESCE(classification,'unknown')='unknown'", fetch="one")
        status["dp_unknown_count"] = int(row[0]) if row else 0
        row = q.run_sql("SELECT COUNT(*) FROM android_unknown_permissions", fetch="one")
        status["unknown_catalog_missing"] = 0 if (row and int(row[0]) > 0) else 1
    except Exception:
        pass
    return status


def _user_scripts_submenu() -> None:
    from .user_script_runner import (
        discover_scripts,
        run_sql_script,
        run_python_script,
        delete_script,
        create_sql_script,
        ensure_dir,
    )
    ensure_dir()
    while True:
        print()
        menu_utils.print_section("User Scripts (SQL/Python)")
        scripts = discover_scripts()
        if scripts:
            rows = [[s.kind, s.name, s.desc or "-", s.path] for s in scripts]
            menu_utils.print_table(["type", "name", "desc", "path"], rows)
        else:
            print(status_messages.status("No scripts found in scripts/db (create one).", level="info"))

        options = [
            ("1", "Run a script", "Execute a selected .sql or .py script."),
            ("2", "View a script", "Show the contents of a script."),
            ("3", "Create new SQL script", "Paste SQL and save to scripts/db/"),
            ("4", "Delete a script", "Remove a script file from scripts/db/"),
            ("0", "Back", None),
        ]
        menu_utils.print_menu(options, padding=True, show_exit=False, show_descriptions=True)
        choice = prompt_utils.get_choice(valid=[o[0] for o in options], default="0")

        if choice == "0":
            break
        elif choice == "1":
            if not scripts:
                print(status_messages.status("No scripts available to run.", level="warn"))
                continue
            idx = prompt_utils.prompt_text("Enter script number (1..N)", required=True, hint="Use the table order above")
            try:
                sel = scripts[int(idx) - 1]
            except Exception:
                print(status_messages.status("Invalid selection.", level="warn"))
                continue
            print(status_messages.status(f"Running {sel.name}…", level="info"))
            if sel.kind == "sql":
                run_sql_script(sel.path, print_fn=lambda m: print(m), table_fn=menu_utils.print_table)
            else:
                run_python_script(sel.path, print_fn=lambda m: print(status_messages.status(m, level="error")))
            prompt_utils.press_enter_to_continue()
        elif choice == "2":
            if not scripts:
                print(status_messages.status("No scripts available to view.", level="warn"))
                continue
            idx = prompt_utils.prompt_text("Enter script number (1..N)", required=True)
            try:
                sel = scripts[int(idx) - 1]
            except Exception:
                print(status_messages.status("Invalid selection.", level="warn"))
                continue
            print()
            print(f"--- {sel.path} ---")
            try:
                with sel.path.open("r", encoding="utf-8", errors="ignore") as fh:
                    for i, line in enumerate(fh, start=1):
                        print(f"{i:4d}: {line.rstrip()}" )
            except Exception as exc:
                print(status_messages.status(f"Failed to read script: {exc}", level="error"))
            prompt_utils.press_enter_to_continue()
        elif choice == "3":
            name = prompt_utils.prompt_text("New SQL script name (e.g., seed_legacy_perms.sql)", required=True)
            print("Paste SQL below. Finish with a single line containing only EOF.")
            lines: list[str] = []
            while True:
                try:
                    line = input("")
                except EOFError:
                    break
                if line.strip() == "EOF":
                    break
                lines.append(line)
            content = "\n".join(lines).strip() + "\n"
            created = create_sql_script(name, content)
            if created is None:
                print(status_messages.status("File exists or invalid name.", level="warn"))
            else:
                print(status_messages.status(f"Wrote {created}", level="success"))
            prompt_utils.press_enter_to_continue()
        elif choice == "4":
            if not scripts:
                print(status_messages.status("No scripts available to delete.", level="warn"))
                continue
            idx = prompt_utils.prompt_text("Enter script number (1..N)", required=True)
            try:
                sel = scripts[int(idx) - 1]
            except Exception:
                print(status_messages.status("Invalid selection.", level="warn"))
                continue
            if prompt_utils.prompt_yes_no(f"Delete {sel.name}?", default=False):
                ok = delete_script(sel.path)
                level = "success" if ok else "error"
                print(status_messages.status("Deleted." if ok else "Delete failed.", level=level))
            prompt_utils.press_enter_to_continue()


def _task_promote_unknown_to_vendor() -> None:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        # Preview count
        row = core_q.run_sql(
            """
            SELECT COUNT(*)
            FROM android_detected_permissions dp
            JOIN android_vendor_permissions v
              ON dp.perm_name = SUBSTRING_INDEX(v.perm_name, '.', -1)
            WHERE COALESCE(dp.classification,'unknown') = 'unknown'
              AND v.namespace <> 'android.permission'
            """,
            fetch="one",
        )
        n = int(row[0]) if row else 0
        print(status_messages.status(f"Will reclassify {n} row(s) to vendor.", level=("success" if n else "info")))
        core_q.run_sql(
            """
            UPDATE android_detected_permissions dp
            JOIN android_vendor_permissions v
              ON dp.perm_name = SUBSTRING_INDEX(v.perm_name, '.', -1)
            SET dp.classification = 'vendor',
                dp.namespace = v.namespace,
                dp.updated_at = CURRENT_TIMESTAMP
            WHERE COALESCE(dp.classification,'unknown') = 'unknown'
              AND v.namespace <> 'android.permission'
            """
        )
        print(status_messages.status("Reclassification to vendor complete.", level="success"))
    except Exception as exc:
        print(status_messages.status(f"Vendor reclassification failed: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()


def _task_run_diagnostics() -> None:
    """Run the curated diagnostics SQL and print analysis."""
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:
        print(status_messages.status(f"DB import failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
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

    # Resolution counts
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
        # Quick analysis hints
        counters = {r[0]: int(r[1]) for r in (rows or []) if len(r) >= 2}
        notes: list[str] = []
        if counters.get('vendor-misclassified', 0) > 0:
            notes.append("Vendor rows using android.permission namespace detected (use repair 7).")
        if counters.get('framework', 0) > 0:
            notes.append("Unknown catalog contains framework constants — consider seeding/cleanup.")
        if counters.get('unmatched', 0) > 0:
            notes.append("Unmatched unknowns remain — likely legacy/system or vendor not in catalog.")
        for n in notes:
            print(status_messages.status(n, level="warn"))
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
        if rows:
            print(status_messages.status("Promote these via repair option 2.", level="warn"))
    except Exception as exc:
        print(status_messages.status(f"Query failed: {exc}", level="error"))

    # Vendor rows misclassified under android.permission
    print()
    menu_utils.print_section("Vendor rows in android.permission namespace (should be framework)")
    try:
        rows = core_q.run_sql(
            "SELECT perm_name, namespace FROM android_vendor_permissions WHERE namespace='android.permission' ORDER BY perm_name",
            fetch="all",
        )
        menu_utils.print_table(["perm_name", "namespace"], rows or [])
        if rows:
            print(status_messages.status("Clean with repair option 7.", level="warn"))
    except Exception as exc:
        print(status_messages.status(f"Query failed: {exc}", level="error"))

    # Unknown → vendor suffix matches with usage counts
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

    # Unknown detections by source
    print()
    menu_utils.print_section("Unknown detections by source")
    try:
        rows = core_q.run_sql(
            "SELECT COALESCE(source,'-') AS src, COUNT(*) AS n FROM android_detected_permissions WHERE COALESCE(classification,'unknown')='unknown' GROUP BY src ORDER BY n DESC",
            fetch="all",
        )
        menu_utils.print_table(["source", "count"], rows or [])
    except Exception as exc:
        print(status_messages.status(f"Query failed: {exc}", level="error"))

    # Unknowns by package
    print()
    menu_utils.print_section("Unknowns by package (top 25)")
    try:
        rows = core_q.run_sql(
            "SELECT package_name, COUNT(*) AS n FROM android_detected_permissions WHERE COALESCE(classification,'unknown')='unknown' GROUP BY package_name ORDER BY n DESC LIMIT 25",
            fetch="all",
        )
        menu_utils.print_table(["package", "count"], rows or [])
    except Exception as exc:
        print(status_messages.status(f"Query failed: {exc}", level="error"))

    # Normalization checks
    print()
    menu_utils.print_section("Normalization checks")
    try:
        row1 = core_q.run_sql("SELECT COUNT(*) FROM android_detected_permissions WHERE perm_name REGEXP '(^\\\\s|\\\\s$)'", fetch="one")
        row2 = core_q.run_sql("SELECT COUNT(*) FROM android_detected_permissions WHERE COALESCE(classification,'unknown')='unknown' AND perm_name REGEXP '[a-z]'", fetch="one")
        suspicious = int(row1[0]) if row1 else 0
        lowercase = int(row2[0]) if row2 else 0
        menu_utils.print_table(["check", "count"], [["leading/trailing whitespace", suspicious], ["lowercase in unknown constants", lowercase]])
        if suspicious or lowercase:
            print(status_messages.status("Normalization issues detected in extractor output.", level="warn"))
    except Exception as exc:
        print(status_messages.status(f"Normalization queries failed: {exc}", level="error"))

    # Framework coverage: AdServices
    print()
    menu_utils.print_section("Framework coverage: AdServices presence")
    try:
        rows = core_q.run_sql(
            "SELECT perm_name, short, protection FROM android_framework_permissions WHERE perm_name LIKE 'android.permission.ACCESS_ADSERVICES_%' OR short LIKE 'ACCESS_ADSERVICES_%' ORDER BY perm_name",
            fetch="all",
        )
        menu_utils.print_table(["perm_name", "short", "protection"], rows or [])
        if not rows:
            print(status_messages.status("AdServices perms not present in framework catalog (expected for many API levels).", level="info"))
    except Exception as exc:
        print(status_messages.status(f"Coverage query failed: {exc}", level="error"))

    # Optional per-package footprint cross-check
    print()
    menu_utils.print_section("Per-package footprint cross-check (optional)")
    pkg = prompt_utils.prompt_text("Package to inspect (blank to skip)", default="", required=False)
    if pkg:
        try:
            row = core_q.run_sql(
                """
                SELECT ? AS package
                """,
                (pkg,),
                fetch="one",
            )
        except Exception:
            pass
        try:
            rows = core_q.run_sql(
                """
                SELECT ? AS package,
                  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('ACCESS_FINE_LOCATION','ACCESS_COARSE_LOCATION','ACCESS_MEDIA_LOCATION') THEN 1 ELSE 0 END) AS loc_fg,
                  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name='ACCESS_BACKGROUND_LOCATION' THEN 1 ELSE 0 END) AS loc_bg,
                  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name='CAMERA' THEN 1 ELSE 0 END) AS cam,
                  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('RECORD_AUDIO','CAPTURE_AUDIO_OUTPUT') THEN 1 ELSE 0 END) AS mic,
                  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('READ_CONTACTS','WRITE_CONTACTS','GET_ACCOUNTS','MANAGE_ACCOUNTS') THEN 1 ELSE 0 END) AS cnt,
                  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('READ_CALL_LOG','CALL_PHONE','READ_PHONE_STATE','READ_PHONE_NUMBERS','ANSWER_PHONE_CALLS') THEN 1 ELSE 0 END) AS phn,
                  SUM(CASE WHEN dp.classification='framework' AND (dp.perm_name REGEXP '^READ_MEDIA_' OR dp.perm_name IN ('READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE','MANAGE_EXTERNAL_STORAGE')) THEN 1 ELSE 0 END) AS str,
                  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('SEND_SMS','RECEIVE_SMS','READ_SMS','RECEIVE_MMS','RECEIVE_WAP_PUSH') THEN 1 ELSE 0 END) AS sms,
                  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('BLUETOOTH_SCAN','BLUETOOTH_ADVERTISE','BLUETOOTH_CONNECT','NEARBY_WIFI_DEVICES') THEN 1 ELSE 0 END) AS bt,
                  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('SYSTEM_ALERT_WINDOW','SYSTEM_OVERLAY_WINDOW') THEN 1 ELSE 0 END) AS ovr,
                  SUM(CASE WHEN dp.classification='framework' AND dp.perm_name IN ('POST_NOTIFICATIONS','BIND_NOTIFICATION_LISTENER_SERVICE','ACCESS_NOTIFICATION_POLICY') THEN 1 ELSE 0 END) AS noti,
                  SUM(CASE WHEN dp.classification='vendor' AND (dp.perm_name LIKE '%AD_ID%' OR dp.perm_name LIKE '%ADVERTIS%' OR dp.perm_name LIKE '%INSTALL_REFERRER%') THEN 1 ELSE 0 END) AS ads
                FROM android_detected_permissions dp
                WHERE dp.package_name = ?
                """,
                (pkg,),
                fetch="all",
            )
            menu_utils.print_table(["package","loc_fg","loc_bg","cam","mic","cnt","phn","str","sms","bt","ovr","noti","ads"], rows or [])
        except Exception as exc:
            print(status_messages.status(f"Package summary failed: {exc}", level="error"))
        try:
            rows = core_q.run_sql(
                """
                SELECT 'LOC' AS grp, dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=? AND dp.classification='framework' AND (dp.perm_name IN ('ACCESS_FINE_LOCATION','ACCESS_COARSE_LOCATION','ACCESS_MEDIA_LOCATION','ACCESS_BACKGROUND_LOCATION'))
                UNION ALL
                SELECT 'CAM', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=? AND dp.classification='framework' AND (dp.perm_name IN ('CAMERA'))
                UNION ALL
                SELECT 'MIC', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=? AND dp.classification='framework' AND (dp.perm_name IN ('RECORD_AUDIO','CAPTURE_AUDIO_OUTPUT'))
                UNION ALL
                SELECT 'CNT', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=? AND dp.classification='framework' AND (dp.perm_name IN ('READ_CONTACTS','WRITE_CONTACTS','GET_ACCOUNTS','MANAGE_ACCOUNTS'))
                UNION ALL
                SELECT 'PHN', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=? AND dp.classification='framework' AND (dp.perm_name IN ('READ_CALL_LOG','CALL_PHONE','READ_PHONE_STATE','READ_PHONE_NUMBERS','ANSWER_PHONE_CALLS'))
                UNION ALL
                SELECT 'SMS', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=? AND dp.classification='framework' AND (dp.perm_name IN ('SEND_SMS','RECEIVE_SMS','READ_SMS','RECEIVE_MMS','RECEIVE_WAP_PUSH'))
                UNION ALL
                SELECT 'STR', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=? AND dp.classification='framework' AND ((dp.perm_name REGEXP '^READ_MEDIA_' OR dp.perm_name IN ('READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE','MANAGE_EXTERNAL_STORAGE')))
                UNION ALL
                SELECT 'BT', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=? AND dp.classification='framework' AND (dp.perm_name IN ('BLUETOOTH_SCAN','BLUETOOTH_ADVERTISE','BLUETOOTH_CONNECT','NEARBY_WIFI_DEVICES'))
                UNION ALL
                SELECT 'OVR', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=? AND dp.classification='framework' AND (dp.perm_name IN ('SYSTEM_ALERT_WINDOW','SYSTEM_OVERLAY_WINDOW'))
                UNION ALL
                SELECT 'NOT', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=? AND dp.classification='framework' AND (dp.perm_name IN ('POST_NOTIFICATIONS','BIND_NOTIFICATION_LISTENER_SERVICE','ACCESS_NOTIFICATION_POLICY'))
                UNION ALL
                SELECT 'ADS', dp.perm_name FROM android_detected_permissions dp WHERE dp.package_name=? AND dp.classification='vendor' AND (dp.perm_name LIKE '%AD_ID%' OR dp.perm_name LIKE '%ADVERTIS%' OR dp.perm_name LIKE '%INSTALL_REFERRER%')
                ORDER BY grp, perm_name
                """,
                (pkg, pkg, pkg, pkg, pkg, pkg, pkg, pkg, pkg, pkg, pkg, pkg),
                fetch="all",
            )
            menu_utils.print_table(["group","perm_name"], rows or [])
        except Exception as exc:
            print(status_messages.status(f"Package detail failed: {exc}", level="error"))

    prompt_utils.press_enter_to_continue()


def _task_promote_unknown_android_perm_to_framework() -> None:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        row = core_q.run_sql(
            "SELECT COUNT(*) FROM android_detected_permissions WHERE COALESCE(classification,'unknown')='unknown' AND namespace='android.permission'",
            fetch="one",
        )
        n = int(row[0]) if row else 0
        print(status_messages.status(f"Will promote {n} row(s) to framework.", level=("success" if n else "info")))
        core_q.run_sql(
            """
            UPDATE android_detected_permissions
            SET classification='framework',
                updated_at=CURRENT_TIMESTAMP
            WHERE COALESCE(classification,'unknown')='unknown'
              AND namespace='android.permission'
            """
        )
        print(status_messages.status("Promotion to framework complete.", level="success"))
    except Exception as exc:
        print(status_messages.status(f"Framework promotion failed: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()


def _task_drop_redundant_sha256_index() -> None:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        row = core_q.run_sql(
            """
            SELECT SUM(index_name='idx_sha256') AS has_dup,
                   SUM(index_name='uk_sha256')  AS has_unique
            FROM information_schema.statistics
            WHERE table_schema = DATABASE()
              AND table_name = 'android_apk_repository'
              AND column_name = 'sha256'
            """,
            fetch="one",
        )
        has_dup = int(row[0]) if row else 0
        has_unique = int(row[1]) if row else 0
        if has_dup and has_unique:
            core_q.run_sql("ALTER TABLE android_apk_repository DROP INDEX idx_sha256")
            print(status_messages.status("Dropped redundant index idx_sha256.", level="success"))
        else:
            print(status_messages.status("No redundant idx_sha256 found (or unique index missing).", level="info"))
    except Exception as exc:
        print(status_messages.status(f"Index drop failed: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()


def _task_clean_vendor_framework_namespace() -> None:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        row = core_q.run_sql(
            "SELECT COUNT(*) FROM android_vendor_permissions WHERE namespace='android.permission'",
            fetch="one",
        )
        n = int(row[0]) if row else 0
        if n:
            core_q.run_sql("DELETE FROM android_vendor_permissions WHERE namespace='android.permission'")
            print(status_messages.status(f"Deleted {n} vendor row(s) in framework namespace.", level="success"))
        else:
            print(status_messages.status("No vendor rows in framework namespace.", level="info"))
    except Exception as exc:
        print(status_messages.status(f"Cleanup failed: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()


def _task_seed_legacy_framework() -> None:
    """Upsert a curated set of legacy/missing framework permissions.

    This helps diagnostics resolve 'unmatched' unknowns by matching on f.short.
    Protections are best-effort; system_only is set for clearly system-only perms.
    """
    try:
        from scytaledroid.Database.db_func import framework_permissions as _fp
    except Exception as exc:
        print(status_messages.status(f"Import failed: {exc}", level="error"))
        prompt_utils.press_enter_to_continue()
        return

    seeds = [
        # idempotent seeds; short is derived from perm_name if omitted
        {"perm_name": "android.permission.AUTHENTICATE_ACCOUNTS", "short": "AUTHENTICATE_ACCOUNTS", "protection": "signature", "system_only": 1},
        {"perm_name": "android.permission.MANAGE_ACCOUNTS", "short": "MANAGE_ACCOUNTS", "protection": "signature", "system_only": 1},
        {"perm_name": "android.permission.FLASHLIGHT", "short": "FLASHLIGHT", "protection": "normal", "system_only": 0, "deprecated_note": "Legacy flashlight permission"},
        {"perm_name": "android.permission.CAPTURE_VIDEO_OUTPUT", "short": "CAPTURE_VIDEO_OUTPUT", "protection": "signature", "system_only": 1},
        {"perm_name": "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION", "short": "DOWNLOAD_WITHOUT_NOTIFICATION", "protection": "signature", "system_only": 1},
        {"perm_name": "android.permission.READ_PROFILE", "short": "READ_PROFILE", "protection": None, "system_only": 0, "deprecated_note": "Legacy contacts profile API"},
        {"perm_name": "android.permission.USE_CREDENTIALS", "short": "USE_CREDENTIALS", "protection": "dangerous", "system_only": 0, "deprecated_note": "Legacy account credentials"},
        {"perm_name": "android.permission.WRITE_SMS", "short": "WRITE_SMS", "protection": "dangerous", "system_only": 0},
        {"perm_name": "android.permission.ACCESS_MESSAGES_ON_ICC", "short": "ACCESS_MESSAGES_ON_ICC", "protection": "signature", "system_only": 1},
        {"perm_name": "android.permission.PERFORM_IMS_SINGLE_REGISTRATION", "short": "PERFORM_IMS_SINGLE_REGISTRATION", "protection": "signature", "system_only": 1},
        {"perm_name": "android.permission.QUERY_USERS", "short": "QUERY_USERS", "protection": "signature", "system_only": 1},
        {"perm_name": "android.permission.READ_CLIPBOARD", "short": "READ_CLIPBOARD", "protection": None, "system_only": 0, "deprecated_note": "Legacy clipboard API"},
        {"perm_name": "android.permission.READ_PRIVILEGED_PHONE_STATE", "short": "READ_PRIVILEGED_PHONE_STATE", "protection": "signature", "system_only": 1},
        {"perm_name": "android.permission.READ_SYSTEM_GRAMMATICAL_GENDER", "short": "READ_SYSTEM_GRAMMATICAL_GENDER", "protection": "signature", "system_only": 1},
        {"perm_name": "android.permission.SATELLITE_COMMUNICATION", "short": "SATELLITE_COMMUNICATION", "protection": "signature", "system_only": 1},
        {"perm_name": "android.permission.SHOW_ON_LOCK_SCREEN", "short": "SHOW_ON_LOCK_SCREEN", "protection": None, "system_only": 0},
        {"perm_name": "android.permission.SUBSCRIBED_FEEDS_READ", "short": "SUBSCRIBED_FEEDS_READ", "protection": None, "system_only": 0},
        {"perm_name": "android.permission.SUBSCRIBED_FEEDS_WRITE", "short": "SUBSCRIBED_FEEDS_WRITE", "protection": None, "system_only": 0},
        {"perm_name": "android.permission.UPDATE_APP_BADGE", "short": "UPDATE_APP_BADGE", "protection": None, "system_only": 0},
        {"perm_name": "android.permission.CONNECTIVITY_USE_RESTRICTED_NETWORKS", "short": "CONNECTIVITY_USE_RESTRICTED_NETWORKS", "protection": "signature", "system_only": 1},
    ]
    # annotate source and defaults
    for item in seeds:
        item.setdefault("source", "legacy-seed")
        item.setdefault("summary", "Seeded legacy/missing permission")
        item.setdefault("protection_raw", item.get("protection"))

    try:
        if not _fp.table_exists():
            if not _fp.ensure_table():
                print(status_messages.status("Failed to ensure framework permissions table.", level="error"))
                prompt_utils.press_enter_to_continue()
                return
        n = _fp.upsert_permissions(seeds, source="legacy-seed")
        print(status_messages.status(f"Legacy seeds upserted: {n}", level="success"))
    except Exception as exc:
        print(status_messages.status(f"Seeding failed: {exc}", level="error"))
    prompt_utils.press_enter_to_continue()

__all__: Iterable[str] = [
    "scripts_menu",
]
