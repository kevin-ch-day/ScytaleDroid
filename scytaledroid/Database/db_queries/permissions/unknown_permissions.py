"""SQL statements for the android_unknown_permissions table."""

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS `android_unknown_permissions` (
  `unknown_perm_id`  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `perm_name`        VARCHAR(191)    NOT NULL,
  `notes`            TEXT            DEFAULT NULL,
  `first_seen_at`    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last_seen_at`     TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `seen_count`       BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `last_seen_package` VARCHAR(191)   DEFAULT NULL,
  `triage_status`    ENUM(
    'UNREVIEWED','PROVISIONAL','CONFIRMED','REJECTED','DEPRECATED',
    'REVIEW_REQUIRED_ANDROID_DRIFT','REVIEW_REQUIRED_OEM',
    'ESCALATED_RESEARCH'
  ) NOT NULL DEFAULT 'UNREVIEWED',
  `triage_reason_code` VARCHAR(64)   DEFAULT NULL,
  `triage_notes`     TEXT            DEFAULT NULL,
  `triage_reviewer`  VARCHAR(128)    DEFAULT NULL,
  `triage_updated_at_utc` DATETIME   DEFAULT NULL,
  `is_ghost_aosp`    TINYINT(1)       NOT NULL DEFAULT 0,
  `ghost_baseline_version` VARCHAR(32) DEFAULT NULL,
  `ghost_first_seen_at_utc` DATETIME  DEFAULT NULL,
  `ghost_last_seen_at_utc` DATETIME   DEFAULT NULL,
  `resolved_as`      ENUM('AOSP','GMS','OEM','APP_DEFINED','THIRD_PARTY_SDK') DEFAULT NULL,
  `resolved_in_baseline` VARCHAR(32)  DEFAULT NULL,
  `resolution_timestamp_utc` DATETIME DEFAULT NULL,
  PRIMARY KEY (`unknown_perm_id`),
  UNIQUE KEY `ux_android_unknown_perm` (`perm_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

ALTER_ADD_TRIAGE_COLUMNS = """
ALTER TABLE android_unknown_permissions
  ADD COLUMN IF NOT EXISTS triage_status ENUM(
    'UNREVIEWED','PROVISIONAL','CONFIRMED','REJECTED','DEPRECATED',
    'REVIEW_REQUIRED_ANDROID_DRIFT','REVIEW_REQUIRED_OEM',
    'ESCALATED_RESEARCH'
  ) NOT NULL DEFAULT 'UNREVIEWED',
  ADD COLUMN IF NOT EXISTS triage_reason_code VARCHAR(64) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS triage_notes TEXT DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS triage_reviewer VARCHAR(128) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS triage_updated_at_utc DATETIME DEFAULT NULL;
"""

ALTER_ADD_GHOST_COLUMNS = """
ALTER TABLE android_unknown_permissions
  ADD COLUMN IF NOT EXISTS is_ghost_aosp TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS ghost_baseline_version VARCHAR(32) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS ghost_first_seen_at_utc DATETIME DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS ghost_last_seen_at_utc DATETIME DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS resolved_as VARCHAR(32) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS resolved_in_baseline VARCHAR(32) DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS resolution_timestamp_utc DATETIME DEFAULT NULL;
"""

UPSERT_UNKNOWN = """
INSERT INTO android_unknown_permissions
  (perm_name, notes, seen_count, last_seen_package)
VALUES
  (%(perm_name)s, %(notes)s, 1, %(last_seen_package)s)
ON DUPLICATE KEY UPDATE
  notes = COALESCE(VALUES(notes), android_unknown_permissions.notes),
  last_seen_at = CURRENT_TIMESTAMP,
  last_seen_package = COALESCE(VALUES(last_seen_package), android_unknown_permissions.last_seen_package),
  seen_count = android_unknown_permissions.seen_count + 1
"""

UPDATE_GHOST = """
UPDATE android_unknown_permissions
SET
  is_ghost_aosp = 1,
  ghost_baseline_version = %(ghost_baseline_version)s,
  ghost_first_seen_at_utc = COALESCE(ghost_first_seen_at_utc, CURRENT_TIMESTAMP),
  ghost_last_seen_at_utc = CURRENT_TIMESTAMP,
  triage_status = COALESCE(triage_status, 'UNREVIEWED'),
  triage_reason_code = COALESCE(triage_reason_code, 'REVIEW_REQUIRED_ANDROID_DRIFT')
WHERE perm_name = %(perm_name)s
"""

COUNT_ROWS = """
SELECT COUNT(*) FROM android_unknown_permissions
"""

TABLE_EXISTS = """
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'android_unknown_permissions'
"""

__all__ = [
    "CREATE_TABLE",
    "ALTER_ADD_TRIAGE_COLUMNS",
    "ALTER_ADD_GHOST_COLUMNS",
    "UPSERT_UNKNOWN",
    "UPDATE_GHOST",
    "COUNT_ROWS",
    "TABLE_EXISTS",
]
