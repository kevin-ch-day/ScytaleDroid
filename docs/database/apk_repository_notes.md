# Android APK Repository – Operational Notes

This document captures the intended behaviour and common workflows for
`android_apk_repository` and `android_app_categories`. It mirrors the latest
schema adjustments captured in `migrations/2025-09-30-apk-schema-update.sql`.

## Table purpose recap

### android_apk_repository

* **Row cardinality:** one physical APK file per row.
* **Key fields:**
  * `apk_id` – surrogate primary key (auto increment).
  * `package_name` – Android package identifier (`com.example.foo`).
  * `file_name`, `file_size` – host side metadata.
  * `is_system`, `installer` – provenance markers.
  * `version_name`, `version_code`, `signer_fingerprint` – manifest/certificate data.
  * `md5`, `sha1`, `sha256` – fingerprints; `sha256` has a UNIQUE constraint for
deduplication.
  * `is_split_member`, `split_group_id` – link split APK members.
  * `created_at`, `updated_at` – audit timestamps.

### android_app_categories

* Normalised lookup of category labels (Social, Messaging, Finance, …).
* `category_id` is auto increment, `category_name` is unique.

## Recommended ingestion flow

1. Pull APK(s) from device / upload source.
2. Compute `file_size`, `md5`, `sha1`, `sha256`.
3. Extract manifest data (`package_name`, `version_*`, `installer`, signer info).
4. Detect split membership. If the APK came from `/data/app/<token>/`, gather all
files in that token directory.
5. Assign or create a `split_group_id` (e.g. base APK’s `apk_id` or an entry in
`apk_split_groups`).
6. Insert/Upsert using:
   ```sql
   INSERT INTO android_apk_repository (...)
   VALUES (...)
   ON DUPLICATE KEY UPDATE ...
   ```
   (template included in the migration script).

## Split APK grouping options

* **Reuse base APK id:** insert the base APK first, capture its `apk_id`, and set
  `split_group_id` for remaining splits to that value.
* **Dedicated group table:** use the optional `apk_split_groups` table to keep
  logical group metadata separate.

Example helper to backfill `split_group_id` with base APK id:
```sql
UPDATE android_apk_repository t
JOIN (
    SELECT package_name, MIN(apk_id) AS base_apk
    FROM android_apk_repository
    WHERE is_split_member = 1
    GROUP BY package_name
) g ON t.package_name = g.package_name
SET t.split_group_id = g.base_apk
WHERE t.is_split_member = 1 AND t.split_group_id IS NULL;
```

## Common analyst queries

* **Duplicates by hash:**
  ```sql
  SELECT sha256, COUNT(*)
  FROM android_apk_repository
  WHERE sha256 IS NOT NULL
  GROUP BY sha256 HAVING COUNT(*) > 1;
  ```

* **Missing fingerprints:**
  ```sql
  SELECT apk_id, package_name, file_name
  FROM android_apk_repository
  WHERE sha256 IS NULL;
  ```

* **Split APK inventory:**
  ```sql
  SELECT package_name, COUNT(*) AS parts
  FROM android_apk_repository
  WHERE is_split_member = 1
  GROUP BY package_name
  ORDER BY parts DESC;
  ```

* **Un-signed / missing signer info:**
  ```sql
  SELECT apk_id, package_name, sha256
  FROM android_apk_repository
  WHERE signer_fingerprint IS NULL AND sha256 IS NOT NULL;
  ```

## Static-analysis linkages

Static-analysis reports now embed the `apk_id` (when available) so that
downstream tooling can join detector output back to repository rows:

* JSON reports live under `data/static_analysis/reports/<sha256>.json` and
  include `metadata.apk_id`, `metadata.pipeline_trace`, and
  `metadata.repro_bundle`.
* Use the `sha256` (unique) or `apk_id` (preferred) to join repository entries
  with static-analysis findings when you design dashboards or warehouse models.
* For drift analysis, pair the `repro_bundle.manifest_digest` between runs to
  detect changes even when the APK filename remains the same.

## Next steps / TODOs

* Map `package_name` to `android_app_categories` (e.g. via
  `android_app_definitions`) once ingestion is wired in.
* Persist split group metadata during ingestion rather than via backfill.
* Capture additional provenance fields where required (device serial, source feed
  etc.).

