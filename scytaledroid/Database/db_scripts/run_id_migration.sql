-- Add run_id columns to static-analysis dependent tables to enable per-run queries.
-- Execute these statements manually against your MySQL schema after reviewing.

ALTER TABLE static_findings
    ADD COLUMN run_id BIGINT UNSIGNED NULL AFTER id,
    ADD INDEX idx_static_findings_run_id (run_id);

ALTER TABLE static_findings_summary
    ADD COLUMN run_id BIGINT UNSIGNED NULL AFTER id,
    ADD INDEX idx_static_findings_summary_run_id (run_id);

ALTER TABLE static_string_samples
    ADD COLUMN run_id BIGINT UNSIGNED NULL AFTER id,
    ADD INDEX idx_static_string_samples_run_id (run_id);

ALTER TABLE static_string_summary
    ADD COLUMN run_id BIGINT UNSIGNED NULL AFTER id,
    ADD INDEX idx_static_string_summary_run_id (run_id);

ALTER TABLE permission_audit_snapshots
    ADD COLUMN run_id BIGINT UNSIGNED NULL AFTER snapshot_id,
    ADD INDEX idx_permission_audit_snapshots_run_id (run_id);

ALTER TABLE permission_audit_apps
    ADD COLUMN run_id BIGINT UNSIGNED NULL AFTER audit_id,
    ADD INDEX idx_permission_audit_apps_run_id (run_id);

ALTER TABLE buckets
    ADD COLUMN run_id BIGINT UNSIGNED NULL AFTER bucket,
    ADD INDEX idx_buckets_run_id (run_id);

ALTER TABLE metrics
    ADD COLUMN run_id BIGINT UNSIGNED NULL AFTER run_id; -- run_id column exists; keep index consistent
