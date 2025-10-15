"""Repair actions for Database Scripts menu."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import status_messages


def promote_unknown_to_vendor() -> None:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
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


def promote_unknown_android_perm_to_framework() -> None:
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


def drop_redundant_sha256_index() -> None:
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


def seed_signal_mappings_core() -> None:
    try:
        from scytaledroid.Database.db_func import permission_support as support
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:
        print(status_messages.status(f"Module import failed: {exc}", level="error"))
        return
    support.ensure_all()
    support.seed_signal_catalog()
    mappings = [
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
                    INSERT INTO permission_signal_mappings (signal_key, perm_name, namespace, confidence)
                    VALUES (%s, %s, %s, 'high')
                    """,
                    (signal_key, perm_name, namespace),
                )
                inserted += 1
        except Exception:
            continue
    level = "success" if inserted or updated else "info"
    print(status_messages.status(f"Mappings: inserted {inserted}, updated {updated}", level=level))


def clean_vendor_framework_namespace() -> None:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        row = core_q.run_sql("SELECT COUNT(*) FROM android_vendor_permissions WHERE namespace='android.permission'", fetch="one")
        n = int(row[0]) if row else 0
        if n:
            core_q.run_sql("DELETE FROM android_vendor_permissions WHERE namespace='android.permission'")
            print(status_messages.status(f"Deleted {n} vendor row(s) in framework namespace.", level="success"))
        else:
            print(status_messages.status("No vendor rows in framework namespace.", level="info"))
    except Exception as exc:
        print(status_messages.status(f"Cleanup failed: {exc}", level="error"))


def backfill_unknowns() -> None:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
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


def seed_legacy_framework() -> None:
    try:
        from scytaledroid.Database.db_func import framework_permissions as _fp
    except Exception as exc:
        print(status_messages.status(f"Import failed: {exc}", level="error"))
        return
    seeds = [
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
    for item in seeds:
        item.setdefault("source", "legacy-seed")
        item.setdefault("summary", "Seeded legacy/missing permission")
        item.setdefault("protection_raw", item.get("protection"))
    try:
        if not _fp.table_exists() and not _fp.ensure_table():
            print(status_messages.status("Failed to ensure framework permissions table.", level="error"))
            return
        n = _fp.upsert_permissions(seeds, source="legacy-seed")
        print(status_messages.status(f"Legacy seeds upserted: {n}", level="success"))
    except Exception as exc:
        print(status_messages.status(f"Seeding failed: {exc}", level="error"))

__all__ = [
    "promote_unknown_to_vendor",
    "promote_unknown_android_perm_to_framework",
    "drop_redundant_sha256_index",
    "seed_signal_mappings_core",
    "clean_vendor_framework_namespace",
    "backfill_unknowns",
    "seed_legacy_framework",
]

