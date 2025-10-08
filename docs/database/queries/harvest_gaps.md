# Harvest Gaps (Installed but not Pulled)

## Purpose
List packages found in the latest inventory for a device that do **not** yet have a harvested artifact. Helps analysts queue another pull.

## Inputs
* `DEVICE_SERIAL` – device serial string.

## Discover the tables
1. `SHOW TABLES LIKE '%inventory%';`
2. `DESCRIBE device_inventory;` (or equivalent table used for snapshot rows).
3. `DESCRIBE android_apk_repository;`

## Pseudo-SQL
```sql
WITH latest_snapshot AS (
    SELECT MAX(snapshot_timestamp) AS latest_ts
    FROM device_inventory
    WHERE device_serial = :DEVICE_SERIAL
),
latest_packages AS (
    SELECT di.*
    FROM device_inventory AS di
    CROSS JOIN latest_snapshot AS ls
    WHERE di.device_serial = :DEVICE_SERIAL
      AND di.snapshot_timestamp = ls.latest_ts
)
SELECT
    lp.package_name,
    lp.version_name,
    lp.version_code,
    lp.source_tag,
    lp.snapshot_timestamp
FROM latest_packages AS lp
LEFT JOIN android_apk_repository AS ar
    ON ar.package_name = lp.package_name
WHERE ar.package_name IS NULL
ORDER BY lp.package_name;
```

## Result Columns
| Column | Type | Notes |
| --- | --- | --- |
| `package_name` | string | Package lacking repository coverage |
| `version_name` | string | From the latest inventory |
| `version_code` | string | Inventory build code |
| `source_tag` | string | Play/System/User, depending on ingestion |
| `snapshot_timestamp` | datetime | Inventory timestamp |

## Example Payload
```json
[
  {
    "package_name": "com.motorola.demotool",
    "version_name": "1.0",
    "version_code": "1",
    "source_tag": "System",
    "snapshot_timestamp": "2025-10-06T13:55:13Z"
  }
]
```

## Notes
* If inventory snapshots are not yet in SQL, import them from `data/state/<serial>/inventory/latest.json` and `latest.meta.json` before using this query.
* Combine with heuristics (e.g., `source_tag = 'Play'`) to prioritise high-value apps.
* When static-analysis tables arrive, left join by `package_name`/`apk_id` to flag missing security posture coverage for these gaps.
