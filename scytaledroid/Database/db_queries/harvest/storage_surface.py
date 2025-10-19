"""SQL for storage surface module persistence."""

from __future__ import annotations

CREATE_TABLE_FILEPROVIDERS = """
CREATE TABLE IF NOT EXISTS static_fileproviders (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  run_key VARCHAR(128) NULL,
  package_name VARCHAR(191) NOT NULL,
  session_stamp VARCHAR(32) NULL,
  scope_label VARCHAR(191) NULL,
  app_id VARCHAR(64) NULL,
  apk_id VARCHAR(64) NULL,
  sha256 CHAR(64) NULL,
  authority VARCHAR(191) NOT NULL,
  provider_name VARCHAR(191) NULL,
  base_perm VARCHAR(191) NULL,
  read_perm VARCHAR(191) NULL,
  write_perm VARCHAR(191) NULL,
  exported TINYINT(1) NOT NULL DEFAULT 0,
  grant_uri_permissions TINYINT(1) NOT NULL DEFAULT 0,
  path_globs TEXT NULL,
  risk VARCHAR(32) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY ix_fileproviders_package (package_name),
  KEY ix_fileproviders_apk (apk_id),
  UNIQUE KEY uq_fileproviders_run (run_key, authority)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_TABLE_PROVIDER_ACL = """
CREATE TABLE IF NOT EXISTS static_provider_acl (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  run_key VARCHAR(128) NULL,
  package_name VARCHAR(191) NOT NULL,
  session_stamp VARCHAR(32) NULL,
  scope_label VARCHAR(191) NULL,
  app_id VARCHAR(64) NULL,
  apk_id VARCHAR(64) NULL,
  sha256 CHAR(64) NULL,
  authority VARCHAR(191) NOT NULL,
  provider_name VARCHAR(191) NULL,
  path TEXT NULL,
  path_type VARCHAR(16) NULL,
  read_perm VARCHAR(191) NULL,
  write_perm VARCHAR(191) NULL,
  base_perm VARCHAR(191) NULL,
  exported TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY ix_provider_acl_package (package_name),
  KEY ix_provider_acl_apk (apk_id),
  UNIQUE KEY uq_provider_acl_run (run_key, authority, path(191), path_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DELETE_FILEPROVIDERS_FOR_SESSION = """
DELETE FROM static_fileproviders
WHERE package_name=%s AND session_stamp=%s
"""

DELETE_PROVIDER_ACL_FOR_SESSION = """
DELETE FROM static_provider_acl
WHERE package_name=%s AND session_stamp=%s
"""

INSERT_FILEPROVIDER = """
INSERT INTO static_fileproviders (
  package_name, session_stamp, scope_label, app_id, apk_id, sha256,
  run_key, authority, provider_name, base_perm, read_perm, write_perm,
  exported, grant_uri_permissions, path_globs, risk
) VALUES (
  %(package_name)s, %(session_stamp)s, %(scope_label)s, %(app_id)s, %(apk_id)s, %(sha256)s,
  %(run_key)s, %(authority)s, %(provider_name)s, %(base_perm)s, %(read_perm)s, %(write_perm)s,
  %(exported)s, %(grant_uri_permissions)s, %(path_globs)s, %(risk)s
)
"""

INSERT_PROVIDER_ACL = """
INSERT INTO static_provider_acl (
  package_name, session_stamp, scope_label, app_id, apk_id, sha256,
  run_key, authority, provider_name, path, path_type, read_perm, write_perm, base_perm, exported
) VALUES (
  %(package_name)s, %(session_stamp)s, %(scope_label)s, %(app_id)s, %(apk_id)s, %(sha256)s,
  %(run_key)s, %(authority)s, %(provider_name)s, %(path)s, %(path_type)s, %(read_perm)s, %(write_perm)s, %(base_perm)s, %(exported)s
)
"""

__all__ = [
    "CREATE_TABLE_FILEPROVIDERS",
    "CREATE_TABLE_PROVIDER_ACL",
    "DELETE_FILEPROVIDERS_FOR_SESSION",
    "DELETE_PROVIDER_ACL_FOR_SESSION",
    "INSERT_FILEPROVIDER",
    "INSERT_PROVIDER_ACL",
]
