# Apps by Profile / Category

## Purpose
List the current app inventory grouped by `apps.profile_key`, with coverage for
whether at least one harvested artifact exists for each package.

## Current contract
The current identity table is `apps`, not `android_app_definitions`.

## Query
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

## Notes
* `profile_key` is the most stable current grouping field for operator-facing
  app cohorts.
* If you want human-friendly labels, join to `android_app_profiles` when that
  lookup table is populated and trusted.
