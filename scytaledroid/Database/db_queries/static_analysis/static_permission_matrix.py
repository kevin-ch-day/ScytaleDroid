"""SQL utilities for persisting per-run Android permission matrices."""

from __future__ import annotations

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS static_permission_matrix (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  run_id BIGINT UNSIGNED NOT NULL,
  apk_id BIGINT UNSIGNED NULL,
  package_name VARCHAR(255) NOT NULL,
  permission_name VARCHAR(255) NOT NULL,
  source VARCHAR(32) DEFAULT NULL,
  protection VARCHAR(191) DEFAULT NULL,
  guard_strength VARCHAR(32) DEFAULT NULL,
  declared_in VARCHAR(191) DEFAULT NULL,
  tokens LONGTEXT DEFAULT NULL,
  severity TINYINT UNSIGNED NOT NULL DEFAULT 0,
  is_flagged_normal TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
  flags LONGTEXT DEFAULT NULL,
  is_runtime_dangerous TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
  is_signature TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
  is_privileged TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
  is_special_access TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
  is_custom TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY ux_spm_run_perm (run_id, permission_name),
  KEY ix_spm_package (package_name),
  KEY ix_spm_source (source),
  CONSTRAINT fk_spm_run
    FOREIGN KEY (run_id)
    REFERENCES static_analysis_runs (id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DELETE_FOR_RUN = """
DELETE FROM static_permission_matrix
WHERE run_id = %s
"""

INSERT_ROWS = """
INSERT INTO static_permission_matrix (
  run_id,
  apk_id,
  package_name,
  permission_name,
  source,
  protection,
  guard_strength,
  declared_in,
  tokens,
  severity,
  is_flagged_normal,
  flags,
  is_runtime_dangerous,
  is_signature,
  is_privileged,
  is_special_access,
  is_custom
) VALUES (
  %(run_id)s,
  %(apk_id)s,
  %(package_name)s,
  %(permission_name)s,
  %(source)s,
  %(protection)s,
  %(guard_strength)s,
  %(declared_in)s,
  %(tokens)s,
  %(severity)s,
  %(is_flagged_normal)s,
  %(flags)s,
  %(is_runtime_dangerous)s,
  %(is_signature)s,
  %(is_privileged)s,
  %(is_special_access)s,
  %(is_custom)s
)
"""

TABLE_EXISTS = """
SELECT COUNT(*)
FROM information_schema.tables
WHERE table_schema = DATABASE()
  AND table_name = 'static_permission_matrix'
"""

__all__ = [
    "CREATE_TABLE",
    "DELETE_FOR_RUN",
    "INSERT_ROWS",
    "TABLE_EXISTS",
]
