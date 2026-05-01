"""SQL for database convenience views (reporting/consumption)."""

from __future__ import annotations

CREATE_VW_LATEST_APK_PER_PACKAGE = """
CREATE OR REPLACE VIEW vw_latest_apk_per_package AS
SELECT ar.*
FROM android_apk_repository ar
JOIN (
  SELECT package_name, MAX(updated_at) AS max_updated
  FROM android_apk_repository
  WHERE is_split_member = 0
  GROUP BY package_name
) t
  ON t.package_name = ar.package_name AND t.max_updated = ar.updated_at
WHERE ar.is_split_member = 0;
"""

__all__ = [
    "CREATE_VW_LATEST_APK_PER_PACKAGE",
]
