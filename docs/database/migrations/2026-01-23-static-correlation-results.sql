-- Phase-C: add static correlation results table
CREATE TABLE IF NOT EXISTS static_correlation_results (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  static_run_id BIGINT UNSIGNED NOT NULL,
  package_name VARCHAR(255) NOT NULL,
  correlation_key VARCHAR(128) NOT NULL,
  severity_band ENUM('INFO','WARN','FAIL') NOT NULL,
  score INT NOT NULL DEFAULT 0,
  rationale TEXT NOT NULL,
  evidence_path VARCHAR(1024) NULL,
  evidence_preview TEXT NULL,
  created_at_utc DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_static_corr (static_run_id, package_name, correlation_key),
  KEY ix_static_corr_run_pkg (static_run_id, package_name),
  KEY ix_static_corr_key (correlation_key),
  KEY ix_static_corr_sev (severity_band)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
