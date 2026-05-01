# Uncategorized Apps

## Purpose
Identify packages in `apps` that still lack a meaningful `profile_key`
assignment, so operators can improve grouping quality over time.

## Query
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

## Notes
* This query is intentionally based on `apps`, not older `android_app_definitions`
  examples.
* If you need to prioritize uncategorized apps with harvested artifacts, join to
  `android_apk_repository` on `package_name` and count artifact rows.
