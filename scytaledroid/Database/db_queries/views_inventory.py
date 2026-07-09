"""SQL for database convenience views (reporting/consumption)."""

from __future__ import annotations

CREATE_VW_LATEST_APK_PER_PACKAGE = """
CREATE OR REPLACE VIEW vw_latest_apk_per_package AS
SELECT ar.*
FROM android_apk_repository ar
JOIN (
  SELECT ranked.apk_id
  FROM (
    SELECT
      ar2.apk_id,
      ROW_NUMBER() OVER (
        PARTITION BY CONVERT(ar2.package_name USING utf8mb4) COLLATE utf8mb4_unicode_ci
        ORDER BY
          CASE
            WHEN EXISTS (
              SELECT 1
              FROM apk_sets aset
              WHERE aset.base_apk_id = ar2.apk_id
            ) THEN 1 ELSE 0
          END DESC,
          COALESCE(ar2.updated_at, ar2.harvested_at, ar2.created_at) DESC,
          CAST(COALESCE(NULLIF(ar2.version_code, ''), '0') AS UNSIGNED) DESC,
          ar2.apk_id DESC
      ) AS rn
    FROM android_apk_repository ar2
    WHERE COALESCE(ar2.is_split_member, 0) = 0
  ) ranked
  WHERE ranked.rn = 1
) t
  ON t.apk_id = ar.apk_id;
"""

__all__ = [
    "CREATE_VW_LATEST_APK_PER_PACKAGE",
]
