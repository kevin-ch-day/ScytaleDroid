-- Phase-B: widen static_analysis_runs.session_stamp and add cohort rollups
ALTER TABLE static_analysis_runs
  MODIFY session_stamp VARCHAR(128) NULL;

CREATE TABLE IF NOT EXISTS static_session_rollups (
  session_stamp VARCHAR(128) NOT NULL,
  scope_label   VARCHAR(191) NOT NULL DEFAULT '',
  apps_total    INT UNSIGNED NOT NULL DEFAULT 0,
  completed     INT UNSIGNED NOT NULL DEFAULT 0,
  failed        INT UNSIGNED NOT NULL DEFAULT 0,
  aborted       INT UNSIGNED NOT NULL DEFAULT 0,
  running       INT UNSIGNED NOT NULL DEFAULT 0,
  created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (session_stamp, scope_label),
  KEY ix_static_rollup_scope (scope_label)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
