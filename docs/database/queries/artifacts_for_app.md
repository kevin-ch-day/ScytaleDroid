# Artifacts for a Single App

## Purpose
Show every harvested artifact for a package, including base and split APKs, with
both source-device path lineage and local artifact path lineage.

## Inputs
* `PACKAGE_NAME` – package identifier (lowercase).
* (Optional) `SINCE_DATE` – restrict to artifacts harvested after a timestamp.

## Query
```sql
SELECT
    r.apk_id,
    r.package_name,
    a.display_name,
    r.version_name,
    r.version_code,
    r.file_name,
    r.file_size,
    r.sha256,
    r.is_split_member,
    r.split_group_id,
    r.device_serial,
    r.harvested_at,
    hsp.source_path,
    hap.local_rel_path,
    hsr.data_root
FROM android_apk_repository AS r
LEFT JOIN apps AS a
  ON a.id = r.app_id
LEFT JOIN harvest_source_paths AS hsp
  ON hsp.apk_id = r.apk_id
LEFT JOIN harvest_artifact_paths AS hap
  ON hap.apk_id = r.apk_id
LEFT JOIN harvest_storage_roots AS hsr
  ON hsr.root_id = hap.storage_root_id
WHERE r.package_name = :PACKAGE_NAME
  AND (:SINCE_DATE IS NULL OR r.harvested_at >= :SINCE_DATE)
ORDER BY r.harvested_at DESC, r.apk_id DESC;
```

## Notes
* `apps` is the current canonical app/package identity table for display labels.
* `android_apk_repository` is the cumulative harvested artifact catalog.
* `harvest_source_paths` stores original on-device lineage; `harvest_artifact_paths`
  stores local host-side lineage.
