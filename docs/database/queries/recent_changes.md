# Recent Package Changes

## Purpose
Show packages whose version changed between the two most recent inventory snapshots for a device, and whether new artifacts were harvested.

## Inputs
* `DEVICE_SERIAL` – device serial string.

## Discover the tables
1. Locate the inventory history table(s): `SHOW TABLES LIKE '%inventory%';`
2. Expected structure:
   * `device_inventory` (one row per package per snapshot)
   * Columns: `device_serial`, `package_name`, `version_name`, `version_code`, `snapshot_timestamp`
3. Confirm repository table: `DESCRIBE android_apk_repository;`

## Pseudo-SQL
```sql
WITH ordered_snapshots AS (
    SELECT DISTINCT snapshot_timestamp
    FROM device_inventory
    WHERE device_serial = :DEVICE_SERIAL
    ORDER BY snapshot_timestamp DESC
    LIMIT 2
),
latest AS (
    SELECT di.*
    FROM device_inventory AS di
    JOIN ordered_snapshots AS os ON di.snapshot_timestamp = os.snapshot_timestamp
    WHERE di.device_serial = :DEVICE_SERIAL
),
paired AS (
    SELECT
        curr.package_name,
        curr.version_name AS new_version_name,
        curr.version_code AS new_version_code,
        curr.snapshot_timestamp AS new_snapshot,
        prev.version_name AS old_version_name,
        prev.version_code AS old_version_code,
        prev.snapshot_timestamp AS old_snapshot
    FROM latest AS curr
    LEFT JOIN latest AS prev
        ON prev.package_name = curr.package_name
       AND prev.snapshot_timestamp = (
            SELECT snapshot_timestamp
            FROM ordered_snapshots
            ORDER BY snapshot_timestamp DESC
            LIMIT 1 OFFSET 1
       )
    WHERE curr.snapshot_timestamp = (
        SELECT MAX(snapshot_timestamp) FROM ordered_snapshots
    )
)
SELECT
    p.package_name,
    p.old_version_name,
    p.old_version_code,
    p.new_version_name,
    p.new_version_code,
    p.old_snapshot,
    p.new_snapshot,
    CASE WHEN ar.package_name IS NOT NULL THEN 1 ELSE 0 END AS has_new_artifact
FROM paired AS p
LEFT JOIN android_apk_repository AS ar
    ON ar.package_name = p.package_name
   AND ar.harvested_at >= p.new_snapshot
WHERE (p.old_version_name IS DISTINCT FROM p.new_version_name)
   OR (p.old_version_code IS DISTINCT FROM p.new_version_code)
ORDER BY p.new_snapshot DESC, p.package_name;
```

## Result Columns
| Column | Type | Notes |
| --- | --- | --- |
| `package_name` | string | Package with version delta |
| `old_version_name` / `old_version_code` | string | Previous snapshot values |
| `new_version_name` / `new_version_code` | string | Latest snapshot values |
| `old_snapshot` / `new_snapshot` | datetime | Snapshot timestamps |
| `has_new_artifact` | boolean/int | 1 if an artifact exists with `harvested_at >= new_snapshot` |

## Example Payload
```json
[
  {
    "package_name": "com.android.chrome",
    "old_version_name": "117.0.5938.117",
    "old_version_code": "677826031",
    "new_version_name": "118.0.5990.90",
    "new_version_code": "739004333",
    "old_snapshot": "2025-10-01T09:10:05Z",
    "new_snapshot": "2025-10-06T13:55:13Z",
    "has_new_artifact": 1
  }
]
```

## Notes
* The SQL above assumes only two snapshots are compared. Adapt if you store more history (e.g., use window functions).
* Inventory ingestion must capture snapshot timestamps reliably (e.g., from `latest.meta.json`).
