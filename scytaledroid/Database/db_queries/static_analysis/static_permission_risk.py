"""SQL for per-APK permission risk persistence (single row per apk_id)."""

from __future__ import annotations

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS static_permission_risk (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  apk_id BIGINT UNSIGNED NOT NULL,
  app_id BIGINT UNSIGNED NULL,
  package_name VARCHAR(255) NOT NULL,
  sha256 CHAR(64) NOT NULL,
  session_stamp VARCHAR(128) NOT NULL,
  scope_label VARCHAR(191) NOT NULL,
  risk_score DECIMAL(7,3) NOT NULL,
  risk_grade CHAR(1) NOT NULL,
  dangerous INT UNSIGNED NOT NULL DEFAULT 0,
  signature INT UNSIGNED NOT NULL DEFAULT 0,
  vendor INT UNSIGNED NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY ux_spr_apk (apk_id),
  KEY ix_spr_pkg (package_name),
  KEY ix_spr_session (session_stamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_TABLE_VNEXT = """
CREATE TABLE IF NOT EXISTS static_permission_risk_vnext (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  run_id BIGINT UNSIGNED NOT NULL,
  permission_name VARCHAR(255) NOT NULL,
  risk_score DECIMAL(7,3) NOT NULL,
  risk_class VARCHAR(32) NULL,
  rationale_code VARCHAR(64) NULL,
  created_at_utc TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY ux_spr_vnext_run_perm (run_id, permission_name),
  KEY ix_spr_vnext_run (run_id),
  CONSTRAINT fk_spr_vnext_run
    FOREIGN KEY (run_id) REFERENCES static_analysis_runs(id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

UPSERT_RISK = """
INSERT INTO static_permission_risk (
  apk_id, app_id, package_name, sha256,
  session_stamp, scope_label,
  risk_score, risk_grade,
  dangerous, signature, vendor
) VALUES (
  %(apk_id)s, %(app_id)s, %(package_name)s, %(sha256)s,
  %(session_stamp)s, %(scope_label)s,
  %(risk_score)s, %(risk_grade)s,
  %(dangerous)s, %(signature)s, %(vendor)s
)
ON DUPLICATE KEY UPDATE
  app_id = VALUES(app_id),
  package_name = VALUES(package_name),
  sha256 = VALUES(sha256),
  session_stamp = VALUES(session_stamp),
  scope_label = VALUES(scope_label),
  risk_score = VALUES(risk_score),
  risk_grade = VALUES(risk_grade),
  dangerous = VALUES(dangerous),
  signature = VALUES(signature),
  vendor = VALUES(vendor),
  created_at = CURRENT_TIMESTAMP
"""

TABLE_EXISTS = """
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'static_permission_risk'
"""

__all__ = [
    "CREATE_TABLE",
    "CREATE_TABLE_VNEXT",
    "UPSERT_RISK",
    "TABLE_EXISTS",
]
