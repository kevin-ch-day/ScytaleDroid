# Manual Database Verification Checklist

Use this checklist to confirm the MySQL repository contains the data required by the upcoming PHP UI. All commands are read-only.

> Replace `scytaledroid_droid_intel_db_dev` with your schema name if it differs.

## 1. List tables
```sql
SHOW TABLES;
```
Verify that tables such as `android_app_definitions`, `android_app_categories`, `android_apk_repository`, and any inventory tables appear.

## 2. Describe key tables
```sql
DESCRIBE android_app_definitions;
DESCRIBE android_app_categories;
DESCRIBE android_apk_repository;
DESCRIBE harvest_storage_roots;
DESCRIBE harvest_artifact_paths;
-- If inventory data has been imported:
DESCRIBE device_inventory;
DESCRIBE device_inventory_snapshots;
```
Confirm column names align with the pseudo-SQL in the query docs.

## 3. Row presence checks
```sql
SELECT COUNT(*) AS total_apps FROM android_app_definitions;
SELECT COUNT(*) AS total_categories FROM android_app_categories;
SELECT COUNT(*) AS total_artifacts FROM android_apk_repository;
SELECT COUNT(*) AS total_artifact_paths FROM harvest_artifact_paths;
```
Run a harvest from the CLI and re-run the artifact count to ensure it increases as expected.

## 4. Join smoke test (categories)
```sql
SELECT
    cat.category_name,
    COUNT(def.app_id) AS app_count
FROM android_app_definitions AS def
LEFT JOIN android_app_categories AS cat
    ON def.category_id = cat.category_id
GROUP BY cat.category_name
ORDER BY app_count DESC;
```
Look for familiar apps (e.g., WhatsApp, Telegram) in the Messaging bucket to confirm category data is populated.

## 5. Package deep-dive
```sql
SELECT
    ar.apk_id,
    ar.package_name,
    ar.file_name,
    ar.sha256,
    ar.device_serial,
    ar.harvested_at,
    hap.source_path,
    hap.local_rel_path,
    hsr.data_root
FROM android_apk_repository AS ar
LEFT JOIN harvest_artifact_paths AS hap ON hap.apk_id = ar.apk_id
LEFT JOIN harvest_storage_roots AS hsr ON hsr.root_id = hap.storage_root_id
WHERE ar.package_name = 'com.instagram.android'
ORDER BY ar.harvested_at DESC
LIMIT 5;
```
Confirm that `local_rel_path` aligns with the directory structure `device_apks/<serial>/<timestamp>/<package>/…` and, when combined with `data_root`, points to an existing file on disk.

## 6. Quick-harvest no-op (if enabled)
* Ensure `HARVEST_WRITE_DB` is set to `False` in the configuration.
* Perform a quick harvest from the CLI.
* Re-run the artifact count from step 3 and confirm the value did **not** change.
* Re-enable `HARVEST_WRITE_DB` afterward.

Document any discrepancies before wiring the PHP UI to these tables.
