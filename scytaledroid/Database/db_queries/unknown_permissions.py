"""SQL statements for the android_unknown_permissions table."""

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS `android_unknown_permissions` (
  `unknown_perm_id`  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `perm_name`        VARCHAR(191)    NOT NULL,
  `notes`            TEXT            DEFAULT NULL,
  `first_seen_at`    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_seen_at`     TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`unknown_perm_id`),
  UNIQUE KEY `ux_android_unknown_perm` (`perm_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

UPSERT_UNKNOWN = """
INSERT INTO android_unknown_permissions
  (perm_name, notes)
VALUES
  (%(perm_name)s, %(notes)s)
ON DUPLICATE KEY UPDATE
  notes = COALESCE(VALUES(notes), android_unknown_permissions.notes),
  last_seen_at = CURRENT_TIMESTAMP
"""

COUNT_ROWS = """
SELECT COUNT(*) FROM android_unknown_permissions
"""

TABLE_EXISTS = """
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'android_unknown_permissions'
"""

__all__ = [
    "CREATE_TABLE",
    "UPSERT_UNKNOWN",
    "COUNT_ROWS",
    "TABLE_EXISTS",
]
