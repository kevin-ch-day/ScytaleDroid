"""SQL for static analysis findings persistence."""

from __future__ import annotations

CREATE_FINDINGS_SUMMARY = """
CREATE TABLE IF NOT EXISTS static_findings_summary (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  package_name VARCHAR(191) NOT NULL,
  session_stamp VARCHAR(32) NOT NULL,
  scope_label VARCHAR(191) NOT NULL,
  high INT UNSIGNED NOT NULL DEFAULT 0,
  med INT UNSIGNED NOT NULL DEFAULT 0,
  low INT UNSIGNED NOT NULL DEFAULT 0,
  info INT UNSIGNED NOT NULL DEFAULT 0,
  details JSON NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY ux_findings_summary (package_name, session_stamp, scope_label),
  KEY ix_findings_session (session_stamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS static_findings (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  summary_id BIGINT UNSIGNED NOT NULL,
  finding_id VARCHAR(128) NULL,
  severity VARCHAR(16) NOT NULL,
  title VARCHAR(512) NULL,
  evidence JSON NULL,
  fix TEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY ix_findings_summary (summary_id),
  CONSTRAINT fk_findings_summary FOREIGN KEY (summary_id)
    REFERENCES static_findings_summary (id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

UPSERT_FINDINGS_SUMMARY = """
INSERT INTO static_findings_summary (
  package_name, session_stamp, scope_label,
  high, med, low, info, details
) VALUES (
  %(package_name)s, %(session_stamp)s, %(scope_label)s,
  %(high)s, %(med)s, %(low)s, %(info)s, %(details)s
)
ON DUPLICATE KEY UPDATE
  high=VALUES(high),
  med=VALUES(med),
  low=VALUES(low),
  info=VALUES(info),
  details=VALUES(details)
"""

SELECT_FINDINGS_SUMMARY_ID = """
SELECT id FROM static_findings_summary
WHERE package_name=%s AND session_stamp=%s AND scope_label=%s
"""

DELETE_FINDINGS_FOR_SUMMARY = """
DELETE FROM static_findings WHERE summary_id=%s
"""

INSERT_FINDING = """
INSERT INTO static_findings (
  summary_id, finding_id, severity, title, evidence, fix
) VALUES (
  %s, %s, %s, %s, %s, %s
)
"""

TABLE_EXISTS_SUMMARY = """
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name='static_findings_summary'
"""

TABLE_EXISTS_FINDINGS = """
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name='static_findings'
"""

__all__ = [
    "CREATE_FINDINGS_SUMMARY",
    "CREATE_FINDINGS",
    "UPSERT_FINDINGS_SUMMARY",
    "SELECT_FINDINGS_SUMMARY_ID",
    "DELETE_FINDINGS_FOR_SUMMARY",
    "INSERT_FINDING",
    "TABLE_EXISTS_SUMMARY",
    "TABLE_EXISTS_FINDINGS",
]

