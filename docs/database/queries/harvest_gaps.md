# Harvest Gaps (Installed but not Pulled)

## Purpose
List packages present in the latest inventory snapshot for a device that do
**not** yet have a harvested artifact in `android_apk_repository`.

## Inputs
* `DEVICE_SERIAL` – device serial string.

## Query
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

## Result Columns
| Column | Type | Notes |
| --- | --- | --- |
| `package_name` | string | Package lacking repository coverage |
| `version_name` | string | From the latest inventory |
| `version_code` | string | Inventory build code |
| `source_label` | string | Play/System/OEM-style source label |
| `partition_label` | string | Device partition classification |
| `snapshot_id` | integer | Latest retained snapshot identifier |
| `captured_at` | datetime | Inventory capture time |

## Notes
* On non-root devices, many `System` / `OEM/Carrier` rows are expected to remain
  harvest gaps because policy blocks pulling protected partitions.
* Package-name joins currently require explicit `COLLATE` in ad hoc SQL because
  the live schema still has mixed package-name collations.
* Pair this with `source_label`, `partition_label`, and `review_needed` if you
  want a higher-value “harvestable gaps only” queue.
