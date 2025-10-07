-- Phase 3: optional split of device source paths into a dedicated table.
-- Run this script after deploying the CLI changes that write to harvest_source_paths.

CREATE TABLE IF NOT EXISTS `harvest_source_paths` (
  `apk_id`      BIGINT UNSIGNED NOT NULL,
  `source_path` VARCHAR(512)    DEFAULT NULL,
  `created_at`  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
                                 ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`apk_id`),
  CONSTRAINT `fk_hsp_apk` FOREIGN KEY (`apk_id`)
      REFERENCES `android_apk_repository` (`apk_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Backfill from legacy columns when they still exist.
DELIMITER $$

CREATE PROCEDURE migrate_legacy_source_paths()
BEGIN
    IF EXISTS (
        SELECT 1
        FROM `information_schema`.`columns`
        WHERE `table_schema` = DATABASE()
          AND `table_name` = 'harvest_artifact_paths'
          AND `column_name` = 'source_path'
    ) THEN
        SET @sql_hap := 'INSERT INTO `harvest_source_paths` (`apk_id`, `source_path`)
            SELECT `apk_id`, `source_path`
            FROM `harvest_artifact_paths`
            WHERE `source_path` IS NOT NULL
            ON DUPLICATE KEY UPDATE
              `source_path` = VALUES(`source_path`),
              `updated_at` = CURRENT_TIMESTAMP';
        PREPARE stmt FROM @sql_hap;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM `information_schema`.`columns`
        WHERE `table_schema` = DATABASE()
          AND `table_name` = 'android_apk_repository'
          AND `column_name` = 'source_path'
    ) THEN
        SET @sql_repo := 'INSERT INTO `harvest_source_paths` (`apk_id`, `source_path`)
            SELECT `apk_id`, `source_path`
            FROM `android_apk_repository`
            WHERE `source_path` IS NOT NULL
            ON DUPLICATE KEY UPDATE
              `source_path` = VALUES(`source_path`),
              `updated_at` = CURRENT_TIMESTAMP';
        PREPARE stmt FROM @sql_repo;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END$$

CALL migrate_legacy_source_paths()$$
DROP PROCEDURE migrate_legacy_source_paths$$

DELIMITER ;
