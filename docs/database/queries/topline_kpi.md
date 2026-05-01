# Topline KPI Summary

## Purpose
Provide high-level counts for inventory, harvest, and identity coverage using
the current core tables.

## Query
```sql
SELECT
    (SELECT COUNT(*) FROM apps) AS total_apps,
    (SELECT COUNT(*) FROM app_versions) AS total_app_versions,
    (SELECT COUNT(*) FROM android_apk_repository) AS total_artifacts,
    (SELECT COUNT(DISTINCT package_name) FROM android_apk_repository) AS harvested_packages,
    (SELECT COUNT(DISTINCT device_serial) FROM android_apk_repository) AS total_devices,
    (SELECT MAX(snapshot_id) FROM device_inventory_snapshots) AS latest_snapshot_id,
    (SELECT MAX(captured_at) FROM device_inventory_snapshots) AS latest_snapshot_captured_at,
    (SELECT MAX(harvested_at) FROM android_apk_repository) AS last_harvest
;
```

## Notes
* `apps` is the current app identity table.
* `app_versions` is currently analysis-owned and may not represent every
  harvested `(app_id, version_code)` pair.
* For operator-facing dashboards, prefer showing both `total_artifacts` and
  `harvested_packages`; they answer different questions.
