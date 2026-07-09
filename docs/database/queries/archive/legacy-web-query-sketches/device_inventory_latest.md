# Device Inventory (Latest)

## Purpose
Return the latest known package inventory for a device, annotated with whether a
harvested artifact exists in the APK repository.

## Inputs
* `DEVICE_SERIAL` – device serial string.

## Current schema contract
The current schema uses:

* `device_inventory(snapshot_id, device_serial, package_name, version_name, version_code, source_label, ...)`
* `device_inventory_snapshots(snapshot_id, captured_at, device_serial, package_count, ...)`
* `android_apk_repository(package_name, harvested_at, app_id, sha256, ...)`

Do **not** use older examples that reference:
- `device_inventory.snapshot_timestamp`
- `android_app_definitions`

Those names describe an older model and are retained here only as a warning for
people copying historical SQL snippets.

## Query
```sql
WITH latest_snapshot AS (
    SELECT s.snapshot_id, s.captured_at
    FROM device_inventory_snapshots AS s
    WHERE s.device_serial = :DEVICE_SERIAL
    ORDER BY s.snapshot_id DESC
    LIMIT 1
)
SELECT
    di.package_name,
    di.version_name,
    di.version_code,
    di.source_label,
    di.partition_label,
    di.split_count,
    ls.snapshot_id,
    ls.captured_at,
    CASE WHEN MAX(ar.apk_id) IS NOT NULL THEN 1 ELSE 0 END AS has_artifact,
    MAX(ar.harvested_at) AS latest_artifact_timestamp
FROM latest_snapshot AS ls
JOIN device_inventory AS di
  ON di.snapshot_id = ls.snapshot_id
LEFT JOIN android_apk_repository AS ar
  ON ar.package_name COLLATE utf8mb4_unicode_ci =
     di.package_name COLLATE utf8mb4_unicode_ci
GROUP BY
    di.package_name,
    di.version_name,
    di.version_code,
    di.source_label,
    di.partition_label,
    di.split_count,
    ls.snapshot_id,
    ls.captured_at
ORDER BY di.package_name;
```

## Result Columns
| Column | Type | Notes |
| --- | --- | --- |
| `package_name` | string | Package ID from the latest snapshot |
| `version_name` | string | Human-readable version |
| `version_code` | string | Build/play-store code |
| `source_label` | string | e.g. `Play Store`, `System`, `OEM/Carrier` |
| `partition_label` | string | e.g. `Data (/data)`, `System (/system, /system_ext)` |
| `split_count` | integer | Number of APK members detected in inventory |
| `snapshot_id` | integer | Latest retained snapshot identifier |
| `captured_at` | datetime | Snapshot capture time |
| `has_artifact` | boolean/int | 1 if the repository holds at least one harvested artifact |
| `latest_artifact_timestamp` | datetime | Most recent harvest time for the package |

## Notes
* Package-name joins currently cross mixed collations in the live schema. Use
  explicit `COLLATE` in ad hoc SQL until the collation migration is completed.
* For “latest inventory for all devices,” remove the `WHERE s.device_serial = ...`
  clause and partition the `latest_snapshot` selection per device.
* Future enhancement: join to `apps` for display labels and to
  `static_analysis_runs` for latest static coverage state.
