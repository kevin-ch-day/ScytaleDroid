"""Helpers to compute context flags for the Scripts menu."""

from __future__ import annotations

def compute_script_status() -> dict:
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

__all__ = ["compute_script_status"]

