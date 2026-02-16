-- static_permission_risk vNext migration (deferred activation)
--
-- Decision lock:
--   static_permission_risk must be permission-granular and run-aware with
--   UNIQUE(run_id, permission_name).
--
-- This migration is prepared now, but activation (table swap) is deferred until
-- Paper #2 review closes. Phase 1 is safe to run immediately; it only creates the
-- vNext table and does not alter current readers/writers.

START TRANSACTION;

CREATE TABLE IF NOT EXISTS static_permission_risk_vnext (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  run_id BIGINT UNSIGNED NOT NULL,
  permission_name VARCHAR(255) NOT NULL,
  risk_score DECIMAL(7,3) NOT NULL,
  risk_class VARCHAR(32) NULL,
  rationale_code VARCHAR(64) NULL,
  created_at_utc TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY ux_spr_vnext_run_permission (run_id, permission_name),
  KEY ix_spr_vnext_run (run_id),
  KEY ix_spr_vnext_permission (permission_name),
  CONSTRAINT fk_spr_vnext_run
    FOREIGN KEY (run_id)
    REFERENCES static_analysis_runs(id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

COMMIT;

-- Deferred activation (run only after Paper #2 review freeze is lifted):
-- 1) deploy writers that target static_permission_risk_vnext behind feature gate
-- 2) validate with determinism + persistence rollback gates
-- 3) cut over table name if required by readers:
--
-- START TRANSACTION;
-- RENAME TABLE static_permission_risk TO static_permission_risk_legacy,
--              static_permission_risk_vnext TO static_permission_risk;
-- COMMIT;
--
-- Rollback (if needed):
-- START TRANSACTION;
-- RENAME TABLE static_permission_risk TO static_permission_risk_vnext,
--              static_permission_risk_legacy TO static_permission_risk;
-- COMMIT;
