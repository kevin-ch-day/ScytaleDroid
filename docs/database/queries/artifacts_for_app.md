# Artifacts for a Single App

## Purpose
Show every artifact harvested for a given package, including base and split APKs, across devices. Uses the new `harvest_artifact_paths` table to expose path metadata.

## Inputs
* `PACKAGE_NAME` – package identifier (lowercase).
* (Optional) `SINCE_DATE` – restrict to artifacts harvested after a timestamp.

## Discover the tables
1. `SHOW TABLES LIKE 'android_apk_repository';`
2. `SHOW TABLES LIKE 'harvest_artifact_paths';`
3. `SHOW TABLES LIKE 'harvest_storage_roots';`
4. `DESCRIBE` each table to confirm column names.
5. Joinable reference: `android_app_definitions` for app labels.

## Pseudo-SQL
```sql
SELECT
    ar.apk_id,
    ar.package_name,
    def.app_name,
    ar.version_name,
    ar.version_code,
    ar.file_name,
    ar.file_size,
    ar.sha256,
    ar.is_split_member,
    ar.split_group_id,
    ar.device_serial,
    ar.harvested_at,
    hap.source_path,
    hap.local_rel_path,
    hsr.data_root
FROM android_apk_repository AS ar
LEFT JOIN android_app_definitions AS def
    ON def.package_name = ar.package_name
LEFT JOIN harvest_artifact_paths AS hap
    ON hap.apk_id = ar.apk_id
LEFT JOIN harvest_storage_roots AS hsr
    ON hsr.root_id = hap.storage_root_id
WHERE ar.package_name = :PACKAGE_NAME
  AND (:SINCE_DATE IS NULL OR ar.harvested_at >= :SINCE_DATE)
ORDER BY ar.harvested_at DESC, ar.apk_id DESC;
```

## Result Columns
| Column | Type | Notes |
| --- | --- | --- |
| `apk_id` | integer | Primary key for the artifact |
| `package_name` | string | Requested package |
| `app_name` | string | Friendly label if recorded |
| `version_name` | string | Version string pulled from inventory |
| `version_code` | string | Version code |
| `file_name` | string | Filename under the repository |
| `file_size` | integer | Bytes |
| `sha256` | string | Dedup key |
| `is_split_member` | boolean/int | 1 for splits, 0 for base APK |
| `split_group_id` | integer/null | Logical grouping of split members |
| `device_serial` | string | Source device |
| `harvested_at` | datetime | Capture timestamp |
| `source_path` | string/null | Original on-device path |
| `local_rel_path` | string/null | Relative path under the ingest host’s `data/apks/` |
| `data_root` | string/null | Host-specific data root; combine with `local_rel_path` if you need an absolute path |

## Example Payload
```json
[
  {
    "apk_id": 126,
    "package_name": "com.google.android.gm",
    "app_name": "Gmail",
    "version_name": "2025.01.05.715468168.Release",
    "version_code": "64943052",
    "file_name": "com_google_android_gm_64943052__base.apk",
    "file_size": 75987127,
    "sha256": "f3a…",
    "is_split_member": 0,
    "split_group_id": null,
    "device_serial": "ZY22JK89DR",
    "harvested_at": "2025-10-06T14:21:36Z",
    "source_path": "/data/app/…/base.apk",
    "local_rel_path": "device_apks/ZY22JK89DR/com.google.android.gm/20251006-142134/com_google_android_gm_64943052__base.apk",
    "data_root": "/srv/scytaledroid/data/apks"
  }
]
```

## Notes
* Reconstruct an absolute filesystem path on demand: `CONCAT(hsr.data_root, '/', hap.local_rel_path)`.
* Display `split_group_id` as a collapsible group in the UI to show related splits.
* Combine with file hashes to offer “download latest” from the PHP interface.
* Pair this query with static-analysis metadata (`data/static_analysis/reports/<sha256>.json`) so analysts can open detector
  findings or diff reproducibility bundles per artifact.
