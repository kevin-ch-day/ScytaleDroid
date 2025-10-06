# Duplicate Artifacts (SHA-256 collisions)

## Purpose
Identify re-used APK binaries across packages/versions/devices. Useful for dedupe audits and storage planning.

## Inputs
* `LIMIT_ROWS` – maximum rows to return (default 100).

## Discover the tables
1. Confirm `android_apk_repository` has `sha256`, `package_name`, `version_name`, `device_serial` columns.
2. Optional: `DESCRIBE apk_split_groups;` if you want to aggregate splits separately.

## Pseudo-SQL
```sql
WITH duplicates AS (
    SELECT
        sha256,
        COUNT(*) AS artifact_count
    FROM android_apk_repository
    WHERE sha256 IS NOT NULL AND sha256 <> ''
    GROUP BY sha256
    HAVING COUNT(*) > 1
)
SELECT
    d.sha256,
    ar.package_name,
    COALESCE(def.app_name, ar.package_name) AS app_name,
    ar.version_name,
    ar.version_code,
    ar.device_serial,
    ar.harvested_at,
    d.artifact_count
FROM duplicates AS d
JOIN android_apk_repository AS ar
    ON ar.sha256 = d.sha256
LEFT JOIN android_app_definitions AS def
    ON def.package_name = ar.package_name
ORDER BY d.artifact_count DESC, d.sha256
LIMIT :LIMIT_ROWS;
```

## Result Columns
| Column | Type | Notes |
| --- | --- | --- |
| `sha256` | string | Hash shared by multiple artifacts |
| `package_name` | string | Package using the binary |
| `app_name` | string | Friendly label |
| `version_name` | string | Version string |
| `version_code` | string | Version code |
| `device_serial` | string | Device from which the artifact was captured |
| `harvested_at` | datetime | Capture timestamp |
| `artifact_count` | integer | Total rows sharing the hash |

## Example Payload
```json
[
  {
    "sha256": "4a3b...",
    "package_name": "com.whatsapp",
    "app_name": "WhatsApp",
    "version_name": "2.25.26.74",
    "version_code": "252674000",
    "device_serial": "ZY22JK89DR",
    "harvested_at": "2025-10-06T14:21:40Z",
    "artifact_count": 3
  },
  {
    "sha256": "4a3b...",
    "package_name": "com.whatsapp",
    "app_name": "WhatsApp",
    "version_name": "2.25.26.74",
    "version_code": "252674000",
    "device_serial": "ZY11AB12CD",
    "harvested_at": "2025-10-01T09:18:12Z",
    "artifact_count": 3
  }
]
```

## Notes
* Use this output to highlight binaries shared across carrier variants or devices.
* Can be extended with storage size sums to show total space saved.
