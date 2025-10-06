# Topline KPI Summary

## Purpose
Provide high-level counts for the landing page KPI tiles.

## Inputs
* (Optional) `SINCE_DATE` – filter artifacts harvested after a timestamp when computing recency metrics.

## Discover the tables
1. `SHOW TABLES LIKE 'android_app_definitions';`
2. `SHOW TABLES LIKE 'android_app_categories';`
3. `SHOW TABLES LIKE 'android_apk_repository';`
4. `SHOW TABLES LIKE '%devices%';` – if you track devices in a separate table (otherwise derive from repository/device inventory).

## Pseudo-SQL
```sql
SELECT
    (SELECT COUNT(*) FROM android_app_definitions) AS total_apps,
    (SELECT COUNT(*) FROM android_app_definitions WHERE category_id IS NOT NULL) AS categorized_apps,
    (SELECT COUNT(*) FROM android_app_definitions WHERE category_id IS NULL) AS uncategorized_apps,
    (SELECT COUNT(*) FROM android_apk_repository) AS total_artifacts,
    (SELECT COUNT(DISTINCT device_serial) FROM android_apk_repository) AS total_devices,
    (SELECT MAX(harvested_at) FROM android_apk_repository WHERE (:SINCE_DATE IS NULL OR harvested_at >= :SINCE_DATE)) AS last_harvest
;
```

## Result Columns
| Column | Type | Notes |
| --- | --- | --- |
| `total_apps` | integer | All rows in `android_app_definitions` |
| `categorized_apps` | integer | Non-null `category_id` |
| `uncategorized_apps` | integer | Derived difference |
| `total_artifacts` | integer | Rows in `android_apk_repository` |
| `total_devices` | integer | Distinct serials appearing in the repository |
| `last_harvest` | datetime | Most recent harvest timestamp |

## Example Payload
```json
{
  "total_apps": 612,
  "categorized_apps": 470,
  "uncategorized_apps": 142,
  "total_artifacts": 2418,
  "total_devices": 12,
  "last_harvest": "2025-10-06T14:21:40Z"
}
```

## Notes
* If you maintain a dedicated devices table, join it instead of relying on `android_apk_repository`.
* Extend with trend metrics (e.g., artifacts added in the last 7 days) as needed.
