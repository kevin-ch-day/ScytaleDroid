CREATE TABLE IF NOT EXISTS permission_signal_observations (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  static_run_id BIGINT UNSIGNED NOT NULL,
  package_name VARCHAR(255) NOT NULL,
  signal_key VARCHAR(128) NOT NULL,
  severity_band ENUM('INFO','WARN','FAIL') NOT NULL DEFAULT 'INFO',
  score INT NOT NULL DEFAULT 0,
  trigger_permissions_json JSON NOT NULL,
  primary_permission VARCHAR(255) NULL,
  rationale TEXT NULL,
  evidence_path VARCHAR(1024) NULL,
  observed_at_utc DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_perm_sig (static_run_id, package_name, signal_key),
  KEY ix_perm_sig_run_pkg (static_run_id, package_name),
  KEY ix_perm_sig_key (signal_key),
  KEY ix_perm_sig_sev (severity_band)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
