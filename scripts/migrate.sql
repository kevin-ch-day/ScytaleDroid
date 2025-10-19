-- Static persistence bootstrap/migration helper.
-- Apply these statements to ensure the static-analysis persistence schema matches the application expectations.

ALTER TABLE runs
    ADD COLUMN IF NOT EXISTS threat_profile VARCHAR(32) NOT NULL DEFAULT 'Unknown' AFTER confidence,
    ADD COLUMN IF NOT EXISTS env_profile VARCHAR(32) NOT NULL DEFAULT 'consumer' AFTER threat_profile,
    ADD INDEX IF NOT EXISTS ix_runs_session (session_stamp);

DROP PROCEDURE IF EXISTS ensure_metrics_constraints;
DELIMITER $$

CREATE PROCEDURE ensure_metrics_constraints()
BEGIN
    DECLARE has_unique INT DEFAULT 0;
    DECLARE has_duplicates INT DEFAULT 0;

    SELECT COUNT(*)
      INTO has_unique
      FROM information_schema.statistics
     WHERE table_schema = DATABASE()
       AND table_name = 'metrics'
       AND index_name = 'uq_metrics_run_key';

    IF has_unique = 0 THEN
        SELECT COUNT(*)
          INTO has_duplicates
          FROM (
              SELECT 1
                FROM metrics
            GROUP BY run_id, feature_key
              HAVING COUNT(*) > 1
              LIMIT 1
          ) AS duplicate_rows;

        IF has_duplicates > 0 THEN
            DROP TABLE IF EXISTS metrics_tmp;

            CREATE TABLE metrics_tmp (
              run_id      BIGINT UNSIGNED NOT NULL,
              feature_key VARCHAR(191)    NOT NULL,
              value_num   DECIMAL(12,4)   NULL,
              value_text  VARCHAR(512)    NULL,
              module_id   VARCHAR(64)     NULL,
              UNIQUE KEY uq_metrics_run_key (run_id, feature_key),
              KEY ix_metrics_run (run_id),
              KEY ix_metrics_feature (feature_key),
              KEY ix_metrics_run_feature (run_id, feature_key)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

            INSERT INTO metrics_tmp (run_id, feature_key, value_num, value_text, module_id)
            SELECT
              run_id,
              feature_key,
              MAX(value_num) AS value_num,
              SUBSTRING_INDEX(
                GROUP_CONCAT(COALESCE(value_text,'') ORDER BY LENGTH(value_text) DESC SEPARATOR '\x1D'),
                '\x1D', 1
              ) AS value_text,
              SUBSTRING_INDEX(
                GROUP_CONCAT(COALESCE(module_id,'') ORDER BY LENGTH(module_id) DESC SEPARATOR '\x1D'),
                '\x1D', 1
              ) AS module_id
            FROM metrics
            GROUP BY run_id, feature_key;

            RENAME TABLE metrics TO metrics_backup_tmp, metrics_tmp TO metrics;

            DROP TABLE IF EXISTS metrics_backup_tmp;
        END IF;

        ALTER TABLE metrics
            ADD UNIQUE KEY uq_metrics_run_key (run_id, feature_key);
    END IF;

    ALTER TABLE metrics
        ADD INDEX IF NOT EXISTS ix_metrics_run (run_id),
        ADD INDEX IF NOT EXISTS ix_metrics_feature (feature_key),
        ADD INDEX IF NOT EXISTS ix_metrics_run_feature (run_id, feature_key);
END $$

DELIMITER ;

CALL ensure_metrics_constraints();
DROP PROCEDURE IF EXISTS ensure_metrics_constraints;

ALTER TABLE findings
    ADD INDEX IF NOT EXISTS ix_findings_run (run_id),
    ADD INDEX IF NOT EXISTS ix_findings_rule (rule_id),
    ADD INDEX IF NOT EXISTS ix_findings_masvs (masvs);

ALTER TABLE masvs_control_coverage
    ADD INDEX IF NOT EXISTS ix_masvs_control (run_id, control_id);
