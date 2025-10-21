"""SQL for static string analysis persistence."""

from __future__ import annotations

# Summary of string buckets per package/session
CREATE_STRING_SUMMARY = """
CREATE TABLE IF NOT EXISTS static_string_summary (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  package_name VARCHAR(191) NOT NULL,
  session_stamp VARCHAR(32) NOT NULL,
  scope_label VARCHAR(191) NOT NULL,
  run_id BIGINT UNSIGNED NULL,
  endpoints INT UNSIGNED NOT NULL DEFAULT 0,
  http_cleartext INT UNSIGNED NOT NULL DEFAULT 0,
  api_keys INT UNSIGNED NOT NULL DEFAULT 0,
  analytics_ids INT UNSIGNED NOT NULL DEFAULT 0,
  cloud_refs INT UNSIGNED NOT NULL DEFAULT 0,
  ipc INT UNSIGNED NOT NULL DEFAULT 0,
  uris INT UNSIGNED NOT NULL DEFAULT 0,
  flags INT UNSIGNED NOT NULL DEFAULT 0,
  certs INT UNSIGNED NOT NULL DEFAULT 0,
  high_entropy INT UNSIGNED NOT NULL DEFAULT 0,
  placeholders_downgraded INT UNSIGNED NOT NULL DEFAULT 0,
  placeholders_suppressed INT UNSIGNED NOT NULL DEFAULT 0,
  doc_hosts_suppressed INT UNSIGNED NOT NULL DEFAULT 0,
  doc_cdns_suppressed INT UNSIGNED NOT NULL DEFAULT 0,
  trailing_punct_trimmed INT UNSIGNED NOT NULL DEFAULT 0,
  ws_wss_seen INT UNSIGNED NOT NULL DEFAULT 0,
  ipv6_seen INT UNSIGNED NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY ux_string_summary (package_name, session_stamp, scope_label),
  UNIQUE KEY ux_string_summary_run_scope (run_id, scope_label),
  KEY ix_string_summary_session (session_stamp),
  KEY ix_string_summary_run (run_id),
  CONSTRAINT fk_string_summary_run FOREIGN KEY (run_id)
    REFERENCES runs (run_id)
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

# Top-N samples for selected buckets
CREATE_STRING_SAMPLES = """
CREATE TABLE IF NOT EXISTS static_string_samples (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  summary_id BIGINT UNSIGNED NOT NULL,
  bucket VARCHAR(32) NOT NULL,
  value_masked VARCHAR(512) NULL,
  src VARCHAR(512) NULL,
  tag VARCHAR(64) NULL,
  source_type VARCHAR(16) NULL,
  finding_type VARCHAR(32) NULL,
  provider VARCHAR(64) NULL,
  risk_tag VARCHAR(32) NULL,
  confidence VARCHAR(16) NULL,
  sample_hash CHAR(40) NULL,
  root_domain VARCHAR(191) NULL,
  resource_name VARCHAR(191) NULL,
  scheme VARCHAR(32) NULL,
  rank INT UNSIGNED NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY ix_samples_summary (summary_id),
  CONSTRAINT fk_samples_summary FOREIGN KEY (summary_id)
    REFERENCES static_string_summary (id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_STRING_MATCH_CACHE = """
CREATE TABLE IF NOT EXISTS string_match_cache (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  fingerprint CHAR(64) NOT NULL,
  tag VARCHAR(64) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_string_match_cache_fingerprint_tag (fingerprint, tag)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

INSERT_STRING_SUMMARY = """
INSERT INTO static_string_summary (
  package_name, session_stamp, scope_label, run_id,
  endpoints, http_cleartext, api_keys, analytics_ids, cloud_refs, ipc, uris, flags, certs, high_entropy,
  placeholders_downgraded, placeholders_suppressed, doc_hosts_suppressed, doc_cdns_suppressed,
  trailing_punct_trimmed, ws_wss_seen, ipv6_seen
) VALUES (
  %(package_name)s, %(session_stamp)s, %(scope_label)s, %(run_id)s,
  %(endpoints)s, %(http_cleartext)s, %(api_keys)s, %(analytics_ids)s, %(cloud_refs)s, %(ipc)s, %(uris)s, %(flags)s, %(certs)s, %(high_entropy)s,
  %(placeholders_downgraded)s, %(placeholders_suppressed)s, %(doc_hosts_suppressed)s, %(doc_cdns_suppressed)s,
  %(trailing_punct_trimmed)s, %(ws_wss_seen)s, %(ipv6_seen)s
)
ON DUPLICATE KEY UPDATE
  run_id=VALUES(run_id),
  endpoints=VALUES(endpoints),
  http_cleartext=VALUES(http_cleartext),
  api_keys=VALUES(api_keys),
  analytics_ids=VALUES(analytics_ids),
  cloud_refs=VALUES(cloud_refs),
  ipc=VALUES(ipc),
  uris=VALUES(uris),
  flags=VALUES(flags),
  certs=VALUES(certs),
  high_entropy=VALUES(high_entropy),
  placeholders_downgraded=VALUES(placeholders_downgraded),
  placeholders_suppressed=VALUES(placeholders_suppressed),
  doc_hosts_suppressed=VALUES(doc_hosts_suppressed),
  doc_cdns_suppressed=VALUES(doc_cdns_suppressed),
  trailing_punct_trimmed=VALUES(trailing_punct_trimmed),
  ws_wss_seen=VALUES(ws_wss_seen),
  ipv6_seen=VALUES(ipv6_seen)
"""

SELECT_SUMMARY_ID = """
SELECT id FROM static_string_summary
WHERE package_name=%s AND session_stamp=%s AND scope_label=%s
"""

SELECT_SUMMARY_ID_BY_RUN = """
SELECT id FROM static_string_summary
WHERE run_id=%s AND scope_label=%s
"""

DELETE_SAMPLES_FOR_SUMMARY = """
DELETE FROM static_string_samples WHERE summary_id=%s
"""

INSERT_SAMPLE = """
INSERT INTO static_string_samples (
  summary_id,
  bucket,
  value_masked,
  src,
  tag,
  rank,
  source_type,
  finding_type,
  provider,
  risk_tag,
  confidence,
  sample_hash,
  root_domain,
  resource_name,
  scheme
)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""

CREATE_DOC_HOSTS_TABLE = """
CREATE TABLE IF NOT EXISTS doc_hosts (
  host VARCHAR(191) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (host)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

INSERT_DOC_HOST = """
INSERT INTO doc_hosts (host)
VALUES (%s)
ON DUPLICATE KEY UPDATE host=VALUES(host)
"""

CREATE_STRINGS_NORMALIZED_VIEW = """
CREATE OR REPLACE VIEW v_strings_normalized AS
SELECT
  sm.*,
  s.package_name,
  s.session_stamp,
  s.scope_label,
  s.run_id,
  COALESCE(
    sm.root_domain,
    SUBSTRING_INDEX(SUBSTRING_INDEX(sm.value_masked,'/',3),'//',-1)
  ) AS host_normalized
FROM static_string_samples AS sm
JOIN static_string_summary AS s ON sm.summary_id = s.id;
"""

CREATE_DOC_POLICY_DRIFT_VIEW = """
CREATE OR REPLACE VIEW v_doc_policy_drift AS
SELECT
  sn.package_name,
  sn.run_id,
  sn.summary_id,
  sn.bucket,
  sn.scheme,
  sn.host_normalized AS host,
  sn.value_masked AS url,
  sn.src AS source_artifact
FROM v_strings_normalized AS sn
JOIN doc_hosts AS dh ON sn.host_normalized = dh.host
WHERE sn.bucket IN ('endpoints','http_cleartext');
"""

CREATE_STRINGS_EFFECTIVE_VIEW = """
CREATE OR REPLACE VIEW v_strings_effective AS
SELECT sn.*
FROM v_strings_normalized AS sn
LEFT JOIN doc_hosts AS dh ON sn.host_normalized = dh.host
WHERE
  sn.bucket IN ('endpoints','http_cleartext')
  AND dh.host IS NULL;
"""

CREATE_STRINGS_ROOT_BUCKET_INDEX = """
CREATE INDEX idx_static_string_samples_root_bucket
ON static_string_samples (root_domain, bucket)
"""

CREATE_STRING_FINDINGS_VIEW = """
CREATE OR REPLACE VIEW v_string_findings_enriched AS
SELECT
  s.id AS apk_id,
  s.package_name,
  s.run_id,
  sm.finding_type,
  sm.provider,
  sm.risk_tag,
  sm.confidence,
  sm.root_domain,
  sm.scheme,
  sm.resource_name,
  sm.source_type,
  sm.src AS source_ref,
  sm.sample_hash
FROM static_string_samples AS sm
JOIN static_string_summary AS s ON sm.summary_id = s.id;
"""

TABLE_EXISTS_SUMMARY = """
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name='static_string_summary'
"""

TABLE_EXISTS_SAMPLES = """
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name='static_string_samples'
"""

__all__ = [
    "CREATE_STRING_SUMMARY",
    "CREATE_STRING_SAMPLES",
    "CREATE_STRING_MATCH_CACHE",
    "INSERT_STRING_SUMMARY",
    "SELECT_SUMMARY_ID",
    "DELETE_SAMPLES_FOR_SUMMARY",
    "INSERT_SAMPLE",
    "CREATE_DOC_HOSTS_TABLE",
    "INSERT_DOC_HOST",
    "CREATE_STRINGS_NORMALIZED_VIEW",
    "CREATE_DOC_POLICY_DRIFT_VIEW",
    "CREATE_STRINGS_EFFECTIVE_VIEW",
    "CREATE_STRINGS_ROOT_BUCKET_INDEX",
    "CREATE_STRING_FINDINGS_VIEW",
    "TABLE_EXISTS_SUMMARY",
    "TABLE_EXISTS_SAMPLES",
]

