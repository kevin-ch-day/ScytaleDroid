"""SQL for canonical permission-level risk persistence."""

from __future__ import annotations

CREATE_TABLE_VNEXT = """
CREATE TABLE IF NOT EXISTS static_permission_risk_vnext (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  run_id BIGINT UNSIGNED NOT NULL,
  permission_name VARCHAR(255) NOT NULL,
  risk_score DECIMAL(7,3) NOT NULL,
  risk_class VARCHAR(32) NULL,
  rationale_code VARCHAR(64) NULL,
  created_at_utc TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY ux_spr_vnext_run_perm (run_id, permission_name),
  KEY ix_spr_vnext_run (run_id),
  CONSTRAINT fk_spr_vnext_run
    FOREIGN KEY (run_id) REFERENCES static_analysis_runs(id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

__all__ = [
    "CREATE_TABLE_VNEXT",
]
