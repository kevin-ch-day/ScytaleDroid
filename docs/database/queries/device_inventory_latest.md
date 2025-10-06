# Device Inventory (Latest)

## Purpose
Return the latest known app inventory for a device, annotating each package with whether a harvested artifact exists.

## Inputs
* `DEVICE_SERIAL` – device serial string.

## Discover the tables
1. `SHOW TABLES LIKE '%inventory%';` – identify where inventory snapshots are stored after ingestion.
2. Example structures to look for:
   * `device_inventory` (one row per package per device snapshot)
   * `device_inventory_snapshots` (snapshot headers)
3. Verify column names with `DESCRIBE <table>;`.
4. You already know `android_apk_repository` stores artifact metadata.

## Pseudo-SQL
> Replace table/column names with the ones discovered in your schema. The example assumes:
> * `device_inventory` has columns `(device_serial, package_name, version_name, version_code, source_tag, snapshot_timestamp)`.

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
    lp.snapshot_timestamp,
    CASE WHEN ar.package_name IS NOT NULL THEN 1 ELSE 0 END AS has_artifact,
    MAX(ar.harvested_at) AS latest_artifact_timestamp
FROM latest_packages AS lp
LEFT JOIN android_apk_repository AS ar
    ON ar.package_name = lp.package_name
GROUP BY
    lp.package_name,
    lp.version_name,
    lp.version_code,
    lp.source_tag,
    lp.snapshot_timestamp,
    has_artifact
ORDER BY lp.package_name;
```

## Result Columns
| Column | Type | Notes |
| --- | --- | --- |
| `package_name` | string | Package ID from the latest snapshot |
| `version_name` | string | Human-readable version |
| `version_code` | string/int | Play Store code or OEM build number |
| `source_tag` | string | e.g., `Play`, `System`, `User` – depends on ingestion |
| `snapshot_timestamp` | datetime | Timestamp of the inventory snapshot |
| `has_artifact` | boolean/int | 1 if the repository holds at least one artifact |
| `latest_artifact_timestamp` | datetime | Most recent harvest time for the package |

## Example Payload
```json
[
  {
    "package_name": "com.google.android.gm",
    "version_name": "2025.01.05.715468168.Release",
    "version_code": "64943052",
    "source_tag": "Play",
    "snapshot_timestamp": "2025-10-06T13:55:13Z",
    "has_artifact": 1,
    "latest_artifact_timestamp": "2025-10-06T14:21:36Z"
  },
  {
    "package_name": "com.motorola.demoapp",
    "version_name": "1.0",
    "version_code": "1",
    "source_tag": "System",
    "snapshot_timestamp": "2025-10-06T13:55:13Z",
    "has_artifact": 0,
    "latest_artifact_timestamp": null
  }
]
```

## Notes
* Inventory snapshots are currently JSON on disk (`data/state/<serial>/inventory/…`). Ensure they are imported into SQL before running this query.
* Adjust the grouping and ordering if you maintain per-scope snapshots.
