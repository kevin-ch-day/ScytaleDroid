"""SQL for dynamic loading module persistence."""

from __future__ import annotations

CREATE_TABLE_DYNLOAD_EVENTS = """
CREATE TABLE IF NOT EXISTS static_dynload_events (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  package_name VARCHAR(191) NOT NULL,
  session_stamp VARCHAR(32) NULL,
  scope_label VARCHAR(191) NULL,
  app_id VARCHAR(64) NULL,
  apk_id VARCHAR(64) NULL,
  sha256 CHAR(64) NULL,
  event_type VARCHAR(32) NOT NULL,
  class_ref VARCHAR(191) NOT NULL,
  source VARCHAR(191) NULL,
  origin_type VARCHAR(64) NULL,
  sample_hash CHAR(64) NULL,
  severity VARCHAR(16) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY ix_dynload_package (package_name),
  KEY ix_dynload_apk (apk_id),
  KEY ix_dynload_session (session_stamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_TABLE_REFLECTION = """
CREATE TABLE IF NOT EXISTS static_reflection_calls (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  package_name VARCHAR(191) NOT NULL,
  session_stamp VARCHAR(32) NULL,
  scope_label VARCHAR(191) NULL,
  app_id VARCHAR(64) NULL,
  apk_id VARCHAR(64) NULL,
  sha256 CHAR(64) NULL,
  target_class VARCHAR(191) NOT NULL,
  target_method VARCHAR(191) NULL,
  evidence_hash CHAR(64) NOT NULL,
  evidence TEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY ux_reflection (apk_id, evidence_hash),
  KEY ix_reflection_package (package_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DELETE_EVENTS_FOR_SESSION = """
DELETE FROM static_dynload_events
WHERE package_name=%s AND session_stamp=%s
"""

DELETE_REFLECTION_FOR_SESSION = """
DELETE FROM static_reflection_calls
WHERE package_name=%s AND session_stamp=%s
"""

INSERT_EVENT = """
INSERT INTO static_dynload_events (
  package_name, session_stamp, scope_label, app_id, apk_id, sha256,
  event_type, class_ref, source, origin_type, sample_hash, severity
) VALUES (
  %(package_name)s, %(session_stamp)s, %(scope_label)s, %(app_id)s, %(apk_id)s, %(sha256)s,
  %(event_type)s, %(class_ref)s, %(source)s, %(origin_type)s, %(sample_hash)s, %(severity)s
)
"""

INSERT_REFLECTION = """
INSERT INTO static_reflection_calls (
  package_name, session_stamp, scope_label, app_id, apk_id, sha256,
  target_class, target_method, evidence_hash, evidence
) VALUES (
  %(package_name)s, %(session_stamp)s, %(scope_label)s, %(app_id)s, %(apk_id)s, %(sha256)s,
  %(target_class)s, %(target_method)s, %(evidence_hash)s, %(evidence)s
)
ON DUPLICATE KEY UPDATE
  evidence=VALUES(evidence)
"""

__all__ = [
    "CREATE_TABLE_DYNLOAD_EVENTS",
    "CREATE_TABLE_REFLECTION",
    "DELETE_EVENTS_FOR_SESSION",
    "DELETE_REFLECTION_FOR_SESSION",
    "INSERT_EVENT",
    "INSERT_REFLECTION",
]

