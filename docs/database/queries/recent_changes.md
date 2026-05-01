# Recent Package Changes

## Purpose
Show packages whose version changed between the two most recent retained
inventory snapshots for a device, and whether a new artifact was harvested
after the latest snapshot.

## Inputs
* `DEVICE_SERIAL` – device serial string.

## Query
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

## Notes
* This query assumes at least two retained snapshots exist for the device.
* Package-name joins currently need explicit `COLLATE` because the live schema
  still has mixed package-name collations.
* “New artifact” means any artifact harvested at or after the latest snapshot
  time; it does not guarantee the artifact is the exact matching version unless
  you also compare `version_code`.
