"""SQL statements for the android_framework_permissions catalog table."""

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS `android_framework_permissions` (
  `perm_id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `perm_name`        VARCHAR(191)    NOT NULL,
  `short`            VARCHAR(64)     DEFAULT NULL,
  `protection`       VARCHAR(32)     DEFAULT NULL,
  `protection_raw`   VARCHAR(255)    DEFAULT NULL,
  `added_api`        INT             DEFAULT NULL,
  `deprecated_api`   INT             DEFAULT NULL,
  `deprecated_note`  TEXT            DEFAULT NULL,
  `hard_restricted`  TINYINT(1)      NOT NULL DEFAULT 0,
  `soft_restricted`  TINYINT(1)      NOT NULL DEFAULT 0,
  `system_only`      TINYINT(1)      NOT NULL DEFAULT 0,
  `constant_value`   VARCHAR(128)    DEFAULT NULL,
  `summary`          TEXT            DEFAULT NULL,
  `doc_url`          VARCHAR(512)    DEFAULT NULL,
  `source`           VARCHAR(32)     DEFAULT NULL,
  `retrieved_at`     TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`       TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`perm_id`),
  UNIQUE KEY `ux_android_framework_permissions_perm_name` (`perm_name`),
  KEY `ix_android_framework_permissions_protection` (`protection`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

UPSERT_PERMISSION = """
INSERT INTO android_framework_permissions (
  perm_name, short, protection, protection_raw, added_api, deprecated_api, deprecated_note,
  hard_restricted, soft_restricted, system_only, constant_value, summary, doc_url, source
) VALUES (
  %(perm_name)s, %(short)s, %(protection)s, %(protection_raw)s, %(added_api)s, %(deprecated_api)s, %(deprecated_note)s,
  %(hard_restricted)s, %(soft_restricted)s, %(system_only)s, %(constant_value)s, %(summary)s, %(doc_url)s, %(source)s
)
ON DUPLICATE KEY UPDATE
  short = VALUES(short),
  protection = VALUES(protection),
  protection_raw = VALUES(protection_raw),
  added_api = VALUES(added_api),
  deprecated_api = VALUES(deprecated_api),
  deprecated_note = VALUES(deprecated_note),
  hard_restricted = VALUES(hard_restricted),
  soft_restricted = VALUES(soft_restricted),
  system_only = VALUES(system_only),
  constant_value = VALUES(constant_value),
  summary = VALUES(summary),
  doc_url = VALUES(doc_url),
  source = VALUES(source),
  updated_at = CURRENT_TIMESTAMP
"""

COUNT_ROWS = """
SELECT COUNT(*) FROM android_framework_permissions
"""

TABLE_EXISTS = """
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'android_framework_permissions'
"""

PROTECTION_COUNTS = """
SELECT COALESCE(protection, '-') AS protection, COUNT(*) AS cnt
FROM android_framework_permissions
GROUP BY protection
ORDER BY cnt DESC
"""

__all__ = [
    "CREATE_TABLE",
    "UPSERT_PERMISSION",
    "COUNT_ROWS",
    "TABLE_EXISTS",
    "PROTECTION_COUNTS",
]
