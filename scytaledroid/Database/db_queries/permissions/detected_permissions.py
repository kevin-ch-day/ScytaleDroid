"""SQL for per-APK detected permissions (observations)."""

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS `android_detected_permissions` (
  `detected_id`    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `apk_id`         BIGINT UNSIGNED NOT NULL,
  `package_name`   VARCHAR(191)    DEFAULT NULL,
  `artifact_label` VARCHAR(64)     DEFAULT NULL,
  `perm_name`      VARCHAR(191)    NOT NULL,
  `perm_full`      VARCHAR(191)    NOT NULL DEFAULT '',
  `perm_key`       VARCHAR(191)    NOT NULL DEFAULT '',
  `namespace`      VARCHAR(191)    NOT NULL DEFAULT '',
  `classification` VARCHAR(16)     DEFAULT NULL,
  `protection`     VARCHAR(32)     DEFAULT NULL,
  `source`         VARCHAR(32)     DEFAULT NULL,
  `observed_at`    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`     TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`detected_id`),
  UNIQUE KEY `ux_detected_perm_apk_ns` (`apk_id`, `namespace`, `perm_key`),
  KEY `ix_detected_perm_pkg` (`package_name`),
  KEY `ix_detected_perm_class` (`classification`),
  CONSTRAINT `fk_detected_apk`
    FOREIGN KEY (`apk_id`) REFERENCES `android_apk_repository` (`apk_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

UPSERT_DETECTED = """
INSERT INTO android_detected_permissions
  (apk_id, package_name, artifact_label, perm_name, perm_full, perm_key, namespace, classification, protection, source)
VALUES
  (%(apk_id)s, %(package_name)s, %(artifact_label)s, %(perm_name)s, %(perm_full)s, %(perm_key)s, %(namespace)s, %(classification)s, %(protection)s, %(source)s)
ON DUPLICATE KEY UPDATE
  namespace = VALUES(namespace),
  perm_full = VALUES(perm_full),
  perm_key = VALUES(perm_key),
  classification = VALUES(classification),
  protection = VALUES(protection),
  source = VALUES(source),
  updated_at = CURRENT_TIMESTAMP
"""

# Legacy upsert for deployments with the old schema (sha256-based uniqueness)
UPSERT_DETECTED_LEGACY = """
INSERT INTO android_detected_permissions
  (package_name, version_name, version_code, sha256, artifact_label, perm_name, namespace, classification, protection, source)
VALUES
  (%(package_name)s, %(version_name)s, %(version_code)s, %(sha256)s, %(artifact_label)s, %(perm_name)s, %(namespace)s, %(classification)s, %(protection)s, %(source)s)
ON DUPLICATE KEY UPDATE
  namespace = VALUES(namespace),
  classification = VALUES(classification),
  protection = VALUES(protection),
  source = VALUES(source),
  updated_at = CURRENT_TIMESTAMP
"""

SELECT_FRAMEWORK_PROTECTION = """
SELECT `short`, protection, added_api, deprecated_api
FROM android_framework_permissions
WHERE `short` IN ({placeholders})
"""

TABLE_EXISTS = """
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'android_detected_permissions'
"""

__all__ = [
    "CREATE_TABLE",
    "UPSERT_DETECTED",
    "UPSERT_DETECTED_LEGACY",
    "SELECT_FRAMEWORK_PROTECTION",
    "TABLE_EXISTS",
]
