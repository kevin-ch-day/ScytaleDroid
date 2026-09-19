"""SQL for permission taxonomy scaffolding (groups only)."""

from __future__ import annotations

CREATE_GROUPS = """
CREATE TABLE IF NOT EXISTS perm_groups (
  group_key VARCHAR(64) NOT NULL,
  display_name VARCHAR(191) NOT NULL,
  description TEXT NULL,
  default_band VARCHAR(16) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (group_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

SELECT_GROUPS = """
SELECT group_key, display_name, description, default_band
FROM perm_groups
ORDER BY group_key
"""

__all__ = [
    "CREATE_GROUPS",
    "SELECT_GROUPS",
]
