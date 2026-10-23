# Legacy Web query sketches (archive)

These are early PHP/MySQL read-side query sketches. They are retained for
historical context, but they are not current DB/view contracts.

Use current sources first:

- `docs/maintenance/database_governance_runbook.md`
- `docs/maintenance/database_target_schema_v2.md`
- `docs/database/view_contract_v_web_static_dynamic_app_summary.md`
- runtime view definitions under `scytaledroid/Database/db_queries/`
- operator scripts under `scripts/db/`

Merged 2026-10 from nine separate files in `legacy-web-query-sketches/`. Table and
column names reflect the schema when they were written; verify before running.

## Contents
- Topline KPI Summary (`topline_kpi`)
- Apps by Profile / Category (`apps_by_category`)
- Uncategorized Apps (`uncategorized_apps`)
- Artifacts for a Single App (`artifacts_for_app`)
- Duplicate Artifacts (SHA-256 collisions) (`duplicate_artifacts`)
- Device Inventory (Latest) (`device_inventory_latest`)
- Latest Harvest by Device (`latest_harvest_by_device`)
- Harvest Gaps (Installed but not Pulled) (`harvest_gaps`)
- Recent Package Changes (`recent_changes`)

## Topline KPI Summary

### Purpose
Provide high-level counts for inventory, harvest, and identity coverage using
the current core tables.

### Query
```sql
SELECT
    (SELECT COUNT(*) FROM apps) AS total_apps,
    (SELECT COUNT(*) FROM app_versions) AS total_app_versions,
    (SELECT COUNT(*) FROM android_apk_repository) AS total_artifacts,
    (SELECT COUNT(DISTINCT package_name) FROM android_apk_repository) AS harvested_packages,
    (SELECT COUNT(DISTINCT device_serial) FROM android_apk_repository) AS total_devices,
    (SELECT MAX(snapshot_id) FROM device_inventory_snapshots) AS latest_snapshot_id,
    (SELECT MAX(captured_at) FROM device_inventory_snapshots) AS latest_snapshot_captured_at,
    (SELECT MAX(harvested_at) FROM android_apk_repository) AS last_harvest
;
```

### Notes
* `apps` is the current app identity table.
* `app_versions` is currently analysis-owned and may not represent every
  harvested `(app_id, version_code)` pair.
* For operator-facing dashboards, prefer showing both `total_artifacts` and
  `harvested_packages`; they answer different questions.

---

## Apps by Profile / Category

### Purpose
List the current app inventory grouped by `apps.profile_key`, with coverage for
whether at least one harvested artifact exists for each package.

### Current contract
The current identity table is `apps`, not `android_app_definitions`.

### Query
```sql
WITH artifact_coverage AS (
    SELECT package_name, COUNT(*) AS artifact_rows
    FROM android_apk_repository
    GROUP BY package_name
)
SELECT
    COALESCE(a.profile_key, 'UNCLASSIFIED') AS profile_key,
    COUNT(*) AS app_count,
    SUM(CASE WHEN ac.package_name IS NOT NULL THEN 1 ELSE 0 END) AS apps_with_artifacts,
    ROUND(
        CASE WHEN COUNT(*) = 0 THEN 0
             ELSE SUM(CASE WHEN ac.package_name IS NOT NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(*)
        END,
        2
    ) AS coverage_percent
FROM apps AS a
LEFT JOIN artifact_coverage AS ac
  ON ac.package_name = a.package_name
GROUP BY COALESCE(a.profile_key, 'UNCLASSIFIED')
ORDER BY app_count DESC, profile_key;
```

### Notes
* `profile_key` is the most stable current grouping field for operator-facing
  app cohorts.
* If you want human-friendly labels, join to `android_app_profiles` when that
  lookup table is populated and trusted.

---

## Uncategorized Apps

### Purpose
Identify packages in `apps` that still lack a meaningful `profile_key`
assignment, so operators can improve grouping quality over time.

### Query
```sql
SELECT
    a.id AS app_id,
    a.package_name,
    COALESCE(a.display_name, a.package_name) AS display_name,
    a.profile_key,
    a.publisher_key
FROM apps AS a
WHERE a.profile_key IS NULL
   OR a.profile_key IN ('', 'UNCLASSIFIED')
ORDER BY COALESCE(a.display_name, a.package_name), a.package_name
LIMIT :LIMIT_ROWS;
```

### Notes
* This query is intentionally based on `apps`, not older `android_app_definitions`
  examples.
* If you need to prioritize uncategorized apps with harvested artifacts, join to
  `android_apk_repository` on `package_name` and count artifact rows.

---

## Artifacts for a Single App

### Purpose
Show every harvested artifact for a package, including base and split APKs, with
both source-device path lineage and local artifact path lineage.

### Inputs
* `PACKAGE_NAME` – package identifier (lowercase).
* (Optional) `SINCE_DATE` – restrict to artifacts harvested after a timestamp.

### Query
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

### Notes
* `apps` is the current canonical app/package identity table for display labels.
* `android_apk_repository` is the cumulative harvested artifact catalog.
* `harvest_source_paths` stores original on-device lineage; `harvest_artifact_paths`
  stores local host-side lineage.

---

## Duplicate Artifacts (SHA-256 collisions)

### Purpose
Identify re-used APK binaries across packages/versions/devices. Useful for dedupe audits and storage planning.

### Inputs
* `LIMIT_ROWS` – maximum rows to return (default 100).

### Current contract
Use `apps` for friendly labels and package identity. Do **not** join through the
older `android_app_definitions` examples.

### Query
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
    COALESCE(a.display_name, ar.package_name) AS app_name,
    ar.version_name,
    ar.version_code,
    ar.device_serial,
    ar.harvested_at,
    d.artifact_count
FROM duplicates AS d
JOIN android_apk_repository AS ar
    ON ar.sha256 = d.sha256
LEFT JOIN apps AS a
    ON a.id = ar.app_id
ORDER BY d.artifact_count DESC, d.sha256
LIMIT :LIMIT_ROWS;
```

### Result Columns
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

### Example Payload
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

### Notes
* Use this output to highlight binaries shared across carrier variants or devices.
* Can be extended with storage size sums to show total space saved.
* Once static-analysis runs are persisted, surface whether the shared binary has
  a recent scan to avoid duplicate processing.
* If you need package-name joins outside `app_id`, use explicit `COLLATE`
  until package-name collation normalization is complete.

---

## Device Inventory (Latest)

### Purpose
Return the latest known package inventory for a device, annotated with whether a
harvested artifact exists in the APK repository.

### Inputs
* `DEVICE_SERIAL` – device serial string.

### Current schema contract
The current schema uses:

* `device_inventory(snapshot_id, device_serial, package_name, version_name, version_code, source_label, ...)`
* `device_inventory_snapshots(snapshot_id, captured_at, device_serial, package_count, ...)`
* `android_apk_repository(package_name, harvested_at, app_id, sha256, ...)`

Do **not** use older examples that reference:
- `device_inventory.snapshot_timestamp`
- `android_app_definitions`

Those names describe an older model and are retained here only as a warning for
people copying historical SQL snippets.

### Query
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

### Result Columns
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

### Notes
* Package-name joins currently cross mixed collations in the live schema. Use
  explicit `COLLATE` in ad hoc SQL until the collation migration is completed.
* For “latest inventory for all devices,” remove the `WHERE s.device_serial = ...`
  clause and partition the `latest_snapshot` selection per device.
* Future enhancement: join to `apps` for display labels and to
  `static_analysis_runs` for latest static coverage state.

---

## Latest Harvest by Device

### Purpose
Show the most recent harvest summary for a specific device. Intended for a device dashboard card.

### Inputs
* `DEVICE_SERIAL` – device serial string.

### Discover the tables
1. `SHOW TABLES LIKE 'android_apk_repository';`
2. `DESCRIBE android_apk_repository;`
3. If you track inventory snapshots in another table, inspect it and update this doc accordingly.

### Pseudo-SQL
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

### Result Columns
| Column | Type | Notes |
| --- | --- | --- |
| `device_serial` | string | Echoed input |
| `latest_harvest` | datetime | Most recent `harvested_at` for the device |
| `packages_pulled` | integer | Unique packages captured in that latest run (best-effort) |
| `artifact_count` | integer | Total artifacts recorded for the device |
| `base_apk_count` | integer | Count of base APKs |
| `split_apk_count` | integer | Count of split APKs |

### Example Payload
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

### Notes
* This query treats the **most recent** row per package as part of the latest harvest. If you store explicit run IDs later, replace the window logic with that column.
* Consider enriching the payload with guard decisions (stored in sidecars today) once they are persisted in MySQL.
* Future iteration: surface whether each package has a fresh static-analysis run by joining planned `static_analysis_runs` on
  `apk_id`.

---

## Harvest Gaps (Installed but not Pulled)

### Purpose
List packages present in the latest inventory snapshot for a device that do
**not** yet have a harvested artifact in `android_apk_repository`.

### Inputs
* `DEVICE_SERIAL` – device serial string.

### Query
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
    ls.snapshot_id,
    ls.captured_at
FROM latest_snapshot AS ls
JOIN device_inventory AS di
  ON di.snapshot_id = ls.snapshot_id
LEFT JOIN android_apk_repository AS ar
  ON ar.package_name COLLATE utf8mb4_unicode_ci =
     di.package_name COLLATE utf8mb4_unicode_ci
WHERE ar.package_name IS NULL
ORDER BY di.package_name;
```

### Result Columns
| Column | Type | Notes |
| --- | --- | --- |
| `package_name` | string | Package lacking repository coverage |
| `version_name` | string | From the latest inventory |
| `version_code` | string | Inventory build code |
| `source_label` | string | Play/System/OEM-style source label |
| `partition_label` | string | Device partition classification |
| `snapshot_id` | integer | Latest retained snapshot identifier |
| `captured_at` | datetime | Inventory capture time |

### Notes
* On non-root devices, many `System` / `OEM/Carrier` rows are expected to remain
  harvest gaps because policy blocks pulling protected partitions.
* Package-name joins currently require explicit `COLLATE` in ad hoc SQL because
  the live schema still has mixed package-name collations.
* Pair this with `source_label`, `partition_label`, and `review_needed` if you
  want a higher-value “harvestable gaps only” queue.

---

## Recent Package Changes

### Purpose
Show packages whose version changed between the two most recent retained
inventory snapshots for a device, and whether a new artifact was harvested
after the latest snapshot.

### Inputs
* `DEVICE_SERIAL` – device serial string.

### Query
```sql
WITH last_two AS (
    SELECT s.snapshot_id, s.captured_at
    FROM device_inventory_snapshots AS s
    WHERE s.device_serial = :DEVICE_SERIAL
    ORDER BY s.snapshot_id DESC
    LIMIT 2
),
latest_id AS (
    SELECT MAX(snapshot_id) AS snapshot_id FROM last_two
),
previous_id AS (
    SELECT MIN(snapshot_id) AS snapshot_id FROM last_two
),
curr AS (
    SELECT di.*, s.captured_at
    FROM device_inventory AS di
    JOIN device_inventory_snapshots AS s ON s.snapshot_id = di.snapshot_id
    WHERE di.snapshot_id = (SELECT snapshot_id FROM latest_id)
),
prev AS (
    SELECT di.*, s.captured_at
    FROM device_inventory AS di
    JOIN device_inventory_snapshots AS s ON s.snapshot_id = di.snapshot_id
    WHERE di.snapshot_id = (SELECT snapshot_id FROM previous_id)
)
SELECT
    curr.package_name,
    prev.version_name AS old_version_name,
    prev.version_code AS old_version_code,
    curr.version_name AS new_version_name,
    curr.version_code AS new_version_code,
    prev.captured_at AS old_snapshot_captured_at,
    curr.captured_at AS new_snapshot_captured_at,
    CASE WHEN MAX(ar.apk_id) IS NOT NULL THEN 1 ELSE 0 END AS has_new_artifact
FROM curr
LEFT JOIN prev
  ON prev.package_name COLLATE utf8mb4_unicode_ci =
     curr.package_name COLLATE utf8mb4_unicode_ci
LEFT JOIN android_apk_repository AS ar
  ON ar.package_name COLLATE utf8mb4_unicode_ci =
     curr.package_name COLLATE utf8mb4_unicode_ci
 AND ar.harvested_at >= curr.captured_at
WHERE prev.package_name IS NOT NULL
  AND (
        COALESCE(prev.version_name, '') <> COALESCE(curr.version_name, '')
     OR COALESCE(prev.version_code, '') <> COALESCE(curr.version_code, '')
  )
GROUP BY
    curr.package_name,
    prev.version_name,
    prev.version_code,
    curr.version_name,
    curr.version_code,
    prev.captured_at,
    curr.captured_at
ORDER BY curr.captured_at DESC, curr.package_name;
```

### Notes
* This query assumes at least two retained snapshots exist for the device.
* Package-name joins currently need explicit `COLLATE` because the live schema
  still has mixed package-name collations.
* “New artifact” means any artifact harvested at or after the latest snapshot
  time; it does not guarantee the artifact is the exact matching version unless
  you also compare `version_code`.
