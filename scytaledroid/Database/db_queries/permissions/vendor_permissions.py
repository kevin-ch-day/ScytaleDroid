"""SQL statements for the android_vendor_permissions table."""

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS `android_vendor_permissions` (
  `vendor_perm_id`   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `perm_name`        VARCHAR(191)    NOT NULL,
  `namespace`        VARCHAR(191)    DEFAULT NULL,
  `declaring_pkg`    VARCHAR(191)    DEFAULT NULL,
  `protection`       VARCHAR(64)     DEFAULT NULL,
  `summary`          TEXT            DEFAULT NULL,
  `doc_url`          VARCHAR(512)    DEFAULT NULL,
  `source`           VARCHAR(32)     DEFAULT NULL,
  `retrieved_at`     TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`       TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`vendor_perm_id`),
  UNIQUE KEY `ux_android_vendor_permissions_perm_name` (`perm_name`),
  KEY `ix_android_vendor_permissions_namespace` (`namespace`),
  KEY `ix_android_vendor_permissions_decl_pkg` (`declaring_pkg`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

UPSERT_VENDOR = """
INSERT INTO android_vendor_permissions
  (perm_name, namespace, declaring_pkg, protection, summary, doc_url, source)
VALUES
  (%(perm_name)s, %(namespace)s, %(declaring_pkg)s, %(protection)s, %(summary)s, %(doc_url)s, %(source)s)
ON DUPLICATE KEY UPDATE
  namespace = VALUES(namespace),
  declaring_pkg = VALUES(declaring_pkg),
  protection = VALUES(protection),
  summary = VALUES(summary),
  doc_url = VALUES(doc_url),
  source = VALUES(source),
  updated_at = CURRENT_TIMESTAMP
"""

COUNT_ROWS = """
SELECT COUNT(*) FROM android_vendor_permissions
"""

TABLE_EXISTS = """
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'android_vendor_permissions'
"""

__all__ = [
    "CREATE_TABLE",
    "UPSERT_VENDOR",
    "COUNT_ROWS",
    "TABLE_EXISTS",
]
