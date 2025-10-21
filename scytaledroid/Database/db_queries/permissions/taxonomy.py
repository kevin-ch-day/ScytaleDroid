"""SQL for permission taxonomy scaffolding (groups, map, overrides)."""

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

CREATE_ANDROID_PERM_MAP = """
CREATE TABLE IF NOT EXISTS android_perm_map (
  perm_name VARCHAR(191) NOT NULL,
  group_key VARCHAR(64) NOT NULL,
  band VARCHAR(16) NULL,
  notes TEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (perm_name),
  KEY ix_perm_map_group (group_key),
  CONSTRAINT fk_perm_map_group FOREIGN KEY (group_key)
    REFERENCES perm_groups (group_key)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_ANDROID_PERM_OVERRIDE = """
CREATE TABLE IF NOT EXISTS android_perm_override (
  package_name VARCHAR(191) NOT NULL,
  perm_name VARCHAR(191) NOT NULL,
  band VARCHAR(16) NULL,
  notes TEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (package_name, perm_name),
  KEY ix_perm_override_perm (perm_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

SELECT_GROUPS = """
SELECT group_key, display_name, description, default_band
FROM perm_groups
ORDER BY group_key
"""

SELECT_PERMISSION_MAP = """
SELECT perm_name, group_key, band, notes, updated_at
FROM android_perm_map
ORDER BY perm_name
"""

SELECT_PACKAGE_OVERRIDES = """
SELECT perm_name, band, notes, updated_at
FROM android_perm_override
WHERE package_name = %s
ORDER BY perm_name
"""

__all__ = [
    "CREATE_GROUPS",
    "CREATE_ANDROID_PERM_MAP",
    "CREATE_ANDROID_PERM_OVERRIDE",
    "SELECT_GROUPS",
    "SELECT_PERMISSION_MAP",
    "SELECT_PACKAGE_OVERRIDES",
]

