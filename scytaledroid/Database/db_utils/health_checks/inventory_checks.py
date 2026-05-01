from __future__ import annotations

from collections.abc import Callable


def run_inventory_snapshot_checks(
    *,
    scalar: Callable[..., int | None],
    latest_snapshot_id: int | None,
    snapshot_headers_total: int,
    orphan_headers: int,
    latest_is_orphan: bool,
    latest_rows: int,
    latest_expected: int,
    print_status_line: Callable[[str, str], None],
) -> None:
    bad_pkg_count = scalar(
        """
        SELECT COUNT(*)
        FROM device_inventory
        WHERE package_name LIKE '%/%'
           OR package_name LIKE '%=%'
           OR package_name LIKE '%base.apk%'
           OR package_name LIKE '% %'
        """
    ) or 0

    invalid_catalog_tokens = scalar(
        """
        SELECT COUNT(*)
        FROM apps
        WHERE package_name REGEXP '^[0-9]+$'
        """
    ) or 0

    apk_suffix_catalog = scalar(
        """
        SELECT COUNT(*)
        FROM apps
        WHERE package_name LIKE '%.apk'
        """
    ) or 0

    case_variants = scalar(
        """
        SELECT COUNT(*)
        FROM (
            SELECT LOWER(CONVERT(a.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci AS pkg_lower,
                   COUNT(DISTINCT a.package_name) AS variants_in_apps,
                   COUNT(DISTINCT i.package_name) AS variants_in_inventory
            FROM apps a
            LEFT JOIN device_inventory i
              ON LOWER(CONVERT(i.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
                 = LOWER(CONVERT(a.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
            GROUP BY LOWER(CONVERT(a.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
            HAVING COUNT(DISTINCT a.package_name) > 1
                OR COUNT(DISTINCT i.package_name) > 1
        ) v
        """
    ) or 0

    vendor_misc_remaining = scalar(
        "SELECT COUNT(*) FROM apps WHERE publisher_key = 'VENDOR_MISC'"
    ) or 0

    label_is_package = (
        scalar(
            """
            SELECT COUNT(*)
            FROM device_inventory
            WHERE snapshot_id = %s
              AND LOWER(CONVERT(app_label USING utf8mb4)) COLLATE utf8mb4_unicode_ci
                  = LOWER(CONVERT(package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
            """,
            (latest_snapshot_id,),
        )
        if latest_snapshot_id
        else 0
    )

    label_mismatch = (
        scalar(
            """
            SELECT COUNT(*)
            FROM device_inventory i
            JOIN apps a
              ON LOWER(CONVERT(i.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
                 = LOWER(CONVERT(a.package_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
            WHERE i.snapshot_id = %s
              AND i.app_label IS NOT NULL
              AND i.app_label <> ''
              AND LOWER(CONVERT(i.app_label USING utf8mb4)) COLLATE utf8mb4_unicode_ci
                  <> LOWER(CONVERT(a.display_name USING utf8mb4)) COLLATE utf8mb4_unicode_ci
            """,
            (latest_snapshot_id,),
        )
        if latest_snapshot_id
        else 0
    )

    if snapshot_headers_total:
        non_latest_orphans = orphan_headers - (1 if latest_is_orphan else 0)
        if latest_snapshot_id and latest_rows == latest_expected and latest_expected:
            level = "ok" if orphan_headers == 0 else "warn"
        else:
            level = "fail" if orphan_headers else "warn"
        print_status_line(
            level,
            "inventory snapshots",
            detail=(
                f"headers={snapshot_headers_total} orphaned={orphan_headers} "
                f"non_latest_orphans={max(non_latest_orphans, 0)}"
            ),
        )
    else:
        print_status_line("warn", "inventory snapshots", detail="no snapshots recorded")

    if latest_snapshot_id:
        level = "ok" if latest_rows == latest_expected and latest_expected else "fail"
        print_status_line(
            level,
            "latest snapshot row count",
            detail=f"id={latest_snapshot_id} rows={latest_rows} expected={latest_expected}",
        )
    else:
        print_status_line("warn", "latest snapshot", detail="no snapshot headers recorded")

    print_status_line(
        "ok" if bad_pkg_count == 0 else "warn",
        "suspicious package_name",
        detail=str(bad_pkg_count),
    )

    print_status_line(
        "ok" if invalid_catalog_tokens == 0 else "warn",
        "invalid catalog package tokens",
        detail=str(invalid_catalog_tokens),
    )

    print_status_line(
        "ok" if apk_suffix_catalog == 0 else "warn",
        "catalog package_name with .apk suffix",
        detail=str(apk_suffix_catalog),
    )

    print_status_line(
        "ok" if case_variants == 0 else "warn",
        "case drift (apps ↔ inventory)",
        detail=str(case_variants),
    )

    print_status_line(
        "ok" if vendor_misc_remaining == 0 else "warn",
        "vendor_misc publishers",
        detail=str(vendor_misc_remaining),
    )

    if latest_snapshot_id:
        print_status_line(
            "ok" if label_is_package == 0 else "warn",
            "inventory labels equal package",
            detail=str(label_is_package),
        )
        print_status_line(
            "ok" if label_mismatch == 0 else "warn",
            "inventory label mismatch vs apps",
            detail=str(label_mismatch),
        )
