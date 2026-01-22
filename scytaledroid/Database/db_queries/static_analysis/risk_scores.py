"""SQL for risk scoring snapshots persisted from permission analysis."""

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS `risk_scores` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `package_name`  VARCHAR(191)    NOT NULL,
  `app_label`     VARCHAR(191)    DEFAULT NULL,
  `session_stamp` VARCHAR(128)    NOT NULL,
  `scope_label`   VARCHAR(191)    NOT NULL,
  `risk_score`    DECIMAL(7,3)    NOT NULL,
  `risk_grade`    CHAR(1)         NOT NULL,
  `dangerous`     INT             NOT NULL DEFAULT 0,
  `signature`     INT             NOT NULL DEFAULT 0,
  `vendor`        INT             NOT NULL DEFAULT 0,
  `created_at`    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ix_risk_scores_session` (`session_stamp`),
  KEY `ix_risk_scores_scope` (`scope_label`),
  UNIQUE KEY `ux_risk_scores_pkg_session_scope` (`package_name`, `session_stamp`, `scope_label`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

UPSERT_RISK = """
INSERT INTO risk_scores (
  package_name, app_label, session_stamp, scope_label,
  risk_score, risk_grade, dangerous, signature, vendor
) VALUES (
  %(package_name)s, %(app_label)s, %(session_stamp)s, %(scope_label)s,
  %(risk_score)s, %(risk_grade)s, %(dangerous)s, %(signature)s, %(vendor)s
)
ON DUPLICATE KEY UPDATE
  app_label = VALUES(app_label),
  risk_score = VALUES(risk_score),
  risk_grade = VALUES(risk_grade),
  dangerous = VALUES(dangerous),
  signature = VALUES(signature),
  vendor = VALUES(vendor),
  created_at = CURRENT_TIMESTAMP
"""

TABLE_EXISTS = """
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'risk_scores'
"""

__all__ = ["CREATE_TABLE", "UPSERT_RISK", "TABLE_EXISTS"]
