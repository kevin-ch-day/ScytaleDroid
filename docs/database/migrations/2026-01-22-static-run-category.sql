ALTER TABLE static_analysis_runs
  ADD COLUMN IF NOT EXISTS category VARCHAR(64) NULL AFTER scope_label;

CREATE INDEX IF NOT EXISTS ix_static_runs_category
  ON static_analysis_runs (category);
