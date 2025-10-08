# Uncategorized Apps

## Purpose
Identify packages without a meaningful category assignment so analysts can flag or curate them.

## Inputs
* (Optional) `LIMIT_ROWS` – safety cap for the UI (default 500).

## Discover the tables
1. `SHOW TABLES LIKE 'android_app_%';`
2. `DESCRIBE android_app_definitions;`
3. `DESCRIBE android_app_categories;`

## Pseudo-SQL
```sql
SELECT
    def.app_id,
    def.package_name,
    COALESCE(def.app_name, def.package_name) AS display_name,
    def.updated_at
FROM android_app_definitions AS def
LEFT JOIN android_app_categories AS cat
    ON def.category_id = cat.category_id
WHERE def.category_id IS NULL
   OR cat.category_name IS NULL
   OR cat.category_name IN ('Other', '')
ORDER BY def.updated_at DESC
LIMIT :LIMIT_ROWS;
```

## Result Columns
| Column | Type | Notes |
| --- | --- | --- |
| `app_id` | integer | Primary key from `android_app_definitions` |
| `package_name` | string | Lowercased package identifier |
| `display_name` | string | Preferred label for UI |
| `updated_at` | datetime | Last metadata update timestamp |

## Example Payload
```json
[
  {
    "app_id": 431,
    "package_name": "com.example.partnerhelper",
    "display_name": "Partner Helper",
    "updated_at": "2025-10-05T07:46:22Z"
  }
]
```

## Notes
* Use this list to drive a “Needs categorization” view or export.
* Consider adding filters (search by package) for large datasets.
* Future enhancement: surface whether static-analysis coverage exists by joining
  on `android_apk_repository` (and later `static_analysis_runs`) so triage can
  prioritise uncategorized yet high-risk apps.
