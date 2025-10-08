# Apps by Category

## Purpose
List each app category with total apps, how many have at least one harvested artifact, and the coverage percentage. Intended for a “Catalog Overview” dashboard card.

## Inputs
* (Optional) `MIN_ARTIFACT_DATE` – limit to artifacts harvested after a timestamp.

## Discover the tables
1. `SHOW TABLES LIKE 'android_app_%';`
2. `DESCRIBE android_app_definitions;`
3. `DESCRIBE android_app_categories;`
4. `DESCRIBE android_apk_repository;`

## Pseudo-SQL
```sql
WITH latest_artifacts AS (
    SELECT
        ar.package_name,
        MAX(ar.harvested_at) AS latest_harvested_at
    FROM android_apk_repository AS ar
    WHERE (:MIN_ARTIFACT_DATE IS NULL OR ar.harvested_at >= :MIN_ARTIFACT_DATE)
    GROUP BY ar.package_name
)
SELECT
    cat.category_name,
    COUNT(def.app_id) AS app_count,
    SUM(CASE WHEN la.package_name IS NOT NULL THEN 1 ELSE 0 END) AS apps_with_artifacts,
    ROUND(
        CASE WHEN COUNT(def.app_id) = 0 THEN 0
             ELSE SUM(CASE WHEN la.package_name IS NOT NULL THEN 1 ELSE 0 END) * 100.0 / COUNT(def.app_id)
        END,
        2
    ) AS coverage_percent
FROM android_app_definitions AS def
LEFT JOIN android_app_categories AS cat
    ON def.category_id = cat.category_id
LEFT JOIN latest_artifacts AS la
    ON la.package_name = def.package_name
GROUP BY cat.category_name
ORDER BY coverage_percent DESC, cat.category_name;
```

## Result Columns
| Column | Type | Notes |
| --- | --- | --- |
| `category_name` | string | Falls back to `NULL` for unassigned categories |
| `app_count` | integer | Total packages in category |
| `apps_with_artifacts` | integer | Packages with at least one artifact meeting the filter |
| `coverage_percent` | decimal | Coverage %, rounded to 2 decimal places |

## Example Payload
```json
[
  {
    "category_name": "Messaging",
    "app_count": 18,
    "apps_with_artifacts": 16,
    "coverage_percent": 88.89
  },
  {
    "category_name": "Social",
    "app_count": 22,
    "apps_with_artifacts": 21,
    "coverage_percent": 95.45
  },
  {
    "category_name": null,
    "app_count": 54,
    "apps_with_artifacts": 12,
    "coverage_percent": 22.22
  }
]
```

## Notes
* Treat `NULL` / “Other” categories specially in the UI (e.g., display “Uncategorized”).
* If you need to distinguish OEM/system apps, join on `android_apk_repository.is_system` for additional breakdowns.
* Future enhancement: join with forthcoming `static_analysis_runs` to show
  coverage % for apps that have received a static scan in addition to being
  harvested.
