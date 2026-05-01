# Latest Harvest by Device

## Purpose
Show the most recent harvest summary for a specific device. Intended for a device dashboard card.

## Inputs
* `DEVICE_SERIAL` – device serial string.

## Discover the tables
1. `SHOW TABLES LIKE 'android_apk_repository';`
2. `DESCRIBE android_apk_repository;`
3. If you track inventory snapshots in another table, inspect it and update this doc accordingly.

## Pseudo-SQL
```sql
WITH device_artifacts AS (
    SELECT
        ar.package_name,
        ar.harvested_at,
        ar.sha256,
        ar.is_split_member,
        ROW_NUMBER() OVER (
            PARTITION BY ar.package_name
            ORDER BY ar.harvested_at DESC, ar.apk_id DESC
        ) AS rn
    FROM android_apk_repository AS ar
    WHERE ar.device_serial = :DEVICE_SERIAL
)
SELECT
    :DEVICE_SERIAL AS device_serial,
    MAX(da.harvested_at) AS latest_harvest,
    COUNT(DISTINCT CASE WHEN da.rn = 1 THEN da.package_name END) AS packages_pulled,
    COUNT(*) AS artifact_count,
    SUM(CASE WHEN da.is_split_member = 0 THEN 1 ELSE 0 END) AS base_apk_count,
    SUM(CASE WHEN da.is_split_member = 1 THEN 1 ELSE 0 END) AS split_apk_count
FROM device_artifacts AS da;
```

## Result Columns
| Column | Type | Notes |
| --- | --- | --- |
| `device_serial` | string | Echoed input |
| `latest_harvest` | datetime | Most recent `harvested_at` for the device |
| `packages_pulled` | integer | Unique packages captured in that latest run (best-effort) |
| `artifact_count` | integer | Total artifacts recorded for the device |
| `base_apk_count` | integer | Count of base APKs |
| `split_apk_count` | integer | Count of split APKs |

## Example Payload
```json
{
  "device_serial": "ZY22JK89DR",
  "latest_harvest": "2025-10-06T14:21:36Z",
  "packages_pulled": 58,
  "artifact_count": 198,
  "base_apk_count": 58,
  "split_apk_count": 140
}
```

## Notes
* This query treats the **most recent** row per package as part of the latest harvest. If you store explicit run IDs later, replace the window logic with that column.
* Consider enriching the payload with guard decisions (stored in sidecars today) once they are persisted in MySQL.
* Future iteration: surface whether each package has a fresh static-analysis run by joining planned `static_analysis_runs` on
  `apk_id`.
