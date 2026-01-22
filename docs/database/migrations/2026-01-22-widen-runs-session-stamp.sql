-- 2026-01-22 widen runs.session_stamp for auto session labels
-- Fixes MariaDB error 1406 ("Data too long for column 'session_stamp'") caused by auto session labels > 32 chars

ALTER TABLE runs
  MODIFY session_stamp VARCHAR(128) NULL;
