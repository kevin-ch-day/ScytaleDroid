"""SQL for permission taxonomy scaffolding (groups only; map/overrides deprecated)."""

from __future__ import annotations

import warnings

warnings.warn(
    "android_perm_map/android_perm_override are deprecated; only perm_groups is supported.",
    DeprecationWarning,
    stacklevel=2,
)

_NOOP = ""
_ZERO = "SELECT 0"

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

CREATE_ANDROID_PERM_MAP = _NOOP
CREATE_ANDROID_PERM_OVERRIDE = _NOOP

SELECT_GROUPS = """
SELECT group_key, display_name, description, default_band
FROM perm_groups
ORDER BY group_key
"""

SELECT_PERMISSION_MAP = _ZERO
SELECT_PACKAGE_OVERRIDES = _ZERO

__all__ = [
    "CREATE_GROUPS",
    "CREATE_ANDROID_PERM_MAP",
    "CREATE_ANDROID_PERM_OVERRIDE",
    "SELECT_GROUPS",
    "SELECT_PERMISSION_MAP",
    "SELECT_PACKAGE_OVERRIDES",
]
