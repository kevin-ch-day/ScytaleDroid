"""Schema for APK install-set identity and harvest observations."""

CREATE_APK_SETS = """
CREATE TABLE IF NOT EXISTS apk_sets (
  apk_set_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  app_id BIGINT UNSIGNED DEFAULT NULL,
  app_version_id BIGINT UNSIGNED DEFAULT NULL,
  package_name VARCHAR(255) NOT NULL,
  version_code VARCHAR(64) DEFAULT NULL,
  version_name VARCHAR(191) DEFAULT NULL,
  base_apk_id BIGINT UNSIGNED DEFAULT NULL,
  base_apk_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_set_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  artifact_set_hash_version VARCHAR(16) NOT NULL DEFAULT 'v1',
  member_count INT UNSIGNED NOT NULL DEFAULT 0,
  split_count INT UNSIGNED NOT NULL DEFAULT 0,
  completeness_state VARCHAR(32) NOT NULL DEFAULT 'unknown',
  source_kind VARCHAR(32) NOT NULL DEFAULT 'unknown',
  first_seen_at DATETIME DEFAULT NULL,
  last_seen_at DATETIME DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (apk_set_id),
  UNIQUE KEY ux_apk_sets_hash_version (artifact_set_hash, artifact_set_hash_version),
  KEY ix_apk_sets_package_version (package_name, version_code, version_name),
  KEY ix_apk_sets_base_hash (base_apk_sha256),
  KEY ix_apk_sets_app_version (app_version_id),
  KEY ix_apk_sets_source_kind (source_kind)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_APK_SET_MEMBERS = """
CREATE TABLE IF NOT EXISTS apk_set_members (
  apk_set_member_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  apk_set_id BIGINT UNSIGNED NOT NULL,
  apk_id BIGINT UNSIGNED DEFAULT NULL,
  role VARCHAR(16) NOT NULL,
  split_name VARCHAR(191) NOT NULL,
  sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_path TEXT DEFAULT NULL,
  local_relpath TEXT DEFAULT NULL,
  canonical_relpath TEXT DEFAULT NULL,
  member_status VARCHAR(32) NOT NULL DEFAULT 'unknown',
  ordinal INT UNSIGNED NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (apk_set_member_id),
  UNIQUE KEY ux_apk_set_member_identity (apk_set_id, role, split_name, sha256),
  KEY ix_apk_set_members_set (apk_set_id),
  KEY ix_apk_set_members_sha (sha256),
  KEY ix_apk_set_members_apk_id (apk_id),
  CONSTRAINT fk_apk_set_members_set
    FOREIGN KEY (apk_set_id)
    REFERENCES apk_sets(apk_set_id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_HARVEST_SESSIONS = """
CREATE TABLE IF NOT EXISTS harvest_sessions (
  harvest_session_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  session_label VARCHAR(191) NOT NULL,
  device_serial VARCHAR(128) DEFAULT NULL,
  inventory_snapshot_id BIGINT DEFAULT NULL,
  generated_at_utc DATETIME DEFAULT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'unknown',
  receipt_root TEXT DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (harvest_session_id),
  UNIQUE KEY ux_harvest_sessions_label (session_label),
  KEY ix_harvest_sessions_device (device_serial),
  KEY ix_harvest_sessions_snapshot (inventory_snapshot_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_HARVEST_APK_OBSERVATIONS = """
CREATE TABLE IF NOT EXISTS harvest_apk_observations (
  observation_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  harvest_session_id BIGINT UNSIGNED DEFAULT NULL,
  apk_set_id BIGINT UNSIGNED DEFAULT NULL,
  apk_id BIGINT UNSIGNED DEFAULT NULL,
  package_name VARCHAR(255) NOT NULL,
  version_code VARCHAR(64) DEFAULT NULL,
  version_name VARCHAR(191) DEFAULT NULL,
  role VARCHAR(16) NOT NULL DEFAULT 'unknown',
  split_name VARCHAR(191) DEFAULT NULL,
  sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL,
  source_path TEXT DEFAULT NULL,
  local_relpath TEXT DEFAULT NULL,
  canonical_relpath TEXT DEFAULT NULL,
  pull_status VARCHAR(32) NOT NULL DEFAULT 'unknown',
  error_code VARCHAR(128) DEFAULT NULL,
  observed_at_utc DATETIME DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (observation_id),
  UNIQUE KEY ux_harvest_obs_member (
    harvest_session_id,
    package_name,
    role,
    split_name,
    sha256
  ),
  KEY ix_harvest_obs_session (harvest_session_id),
  KEY ix_harvest_obs_set (apk_set_id),
  KEY ix_harvest_obs_package (package_name, version_code),
  KEY ix_harvest_obs_sha (sha256),
  CONSTRAINT fk_harvest_obs_session
    FOREIGN KEY (harvest_session_id)
    REFERENCES harvest_sessions(harvest_session_id)
    ON DELETE SET NULL,
  CONSTRAINT fk_harvest_obs_set
    FOREIGN KEY (apk_set_id)
    REFERENCES apk_sets(apk_set_id)
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_V_APK_SET_COVERAGE_V1 = """
CREATE OR REPLACE VIEW v_apk_set_coverage_v1 AS
SELECT
  s.apk_set_id,
  s.package_name,
  s.version_code,
  s.version_name,
  s.base_apk_id,
  s.base_apk_sha256,
  s.artifact_set_hash,
  s.artifact_set_hash_version,
  s.member_count,
  s.split_count,
  s.completeness_state,
  s.source_kind,
  s.first_seen_at,
  s.last_seen_at,
  COALESCE(m.members_with_canonical_relpath, 0) AS members_with_canonical_relpath,
  COALESCE(m.members_with_recorded_relpath, 0) AS members_with_recorded_relpath,
  COALESCE(st.static_runs, 0) AS static_runs,
  COALESCE(st.static_runs_linked_by_apk_set_id, 0) AS static_runs_linked_by_apk_set_id,
  COALESCE(st.canonical_completed_identity_valid_runs, 0) AS canonical_completed_identity_valid_runs,
  st.latest_static_run_id,
  COALESCE(ds.dynamic_sessions, 0) AS dynamic_sessions,
  COALESCE(ds.dynamic_sessions_linked_by_apk_set_id, 0) AS dynamic_sessions_linked_by_apk_set_id,
  COALESCE(ds.dynamic_unlinked_sessions, 0) AS dynamic_unlinked_sessions,
  CASE
    WHEN COALESCE(st.canonical_completed_identity_valid_runs, 0) > 0 THEN 1
    ELSE 0
  END AS has_canonical_static,
  CASE
    WHEN COALESCE(ds.dynamic_sessions, 0) > 0
     AND COALESCE(st.canonical_completed_identity_valid_runs, 0) = 0 THEN 1
    ELSE 0
  END AS exact_dynamic_static_gap
FROM apk_sets s
LEFT JOIN (
  SELECT
    apk_set_id,
    SUM(CASE WHEN canonical_relpath IS NOT NULL AND canonical_relpath <> '' THEN 1 ELSE 0 END)
      AS members_with_canonical_relpath,
    SUM(CASE WHEN local_relpath IS NOT NULL AND local_relpath <> '' THEN 1 ELSE 0 END)
      AS members_with_recorded_relpath
  FROM apk_set_members
  GROUP BY apk_set_id
) m ON m.apk_set_id = s.apk_set_id
LEFT JOIN (
  SELECT
    artifact_set_hash,
    COUNT(*) AS static_runs,
    SUM(CASE WHEN apk_set_id IS NOT NULL THEN 1 ELSE 0 END) AS static_runs_linked_by_apk_set_id,
    SUM(CASE
          WHEN status = 'COMPLETED'
           AND run_class = 'CANONICAL'
           AND COALESCE(identity_valid, 0) = 1
          THEN 1 ELSE 0
        END) AS canonical_completed_identity_valid_runs,
    MAX(id) AS latest_static_run_id
  FROM static_analysis_runs
  WHERE artifact_set_hash IS NOT NULL
  GROUP BY artifact_set_hash
) st ON st.artifact_set_hash = s.artifact_set_hash
LEFT JOIN (
  SELECT
    artifact_set_hash,
    COUNT(*) AS dynamic_sessions,
    SUM(CASE WHEN apk_set_id IS NOT NULL THEN 1 ELSE 0 END) AS dynamic_sessions_linked_by_apk_set_id,
    SUM(CASE WHEN static_run_id IS NULL THEN 1 ELSE 0 END) AS dynamic_unlinked_sessions
  FROM dynamic_sessions
  WHERE artifact_set_hash IS NOT NULL
  GROUP BY artifact_set_hash
) ds ON ds.artifact_set_hash = s.artifact_set_hash;
"""

_DDL_STATEMENTS = [
    CREATE_HARVEST_SESSIONS,
    CREATE_APK_SETS,
    CREATE_APK_SET_MEMBERS,
    CREATE_HARVEST_APK_OBSERVATIONS,
]

UPSERT_HARVEST_SESSION = """
INSERT INTO harvest_sessions (
  session_label, device_serial, inventory_snapshot_id, generated_at_utc,
  status, receipt_root
) VALUES (%s, %s, %s, %s, %s, %s)
ON DUPLICATE KEY UPDATE
  harvest_session_id = LAST_INSERT_ID(harvest_session_id),
  device_serial = COALESCE(VALUES(device_serial), device_serial),
  inventory_snapshot_id = COALESCE(VALUES(inventory_snapshot_id), inventory_snapshot_id),
  generated_at_utc = COALESCE(VALUES(generated_at_utc), generated_at_utc),
  status = VALUES(status),
  receipt_root = COALESCE(VALUES(receipt_root), receipt_root),
  updated_at = CURRENT_TIMESTAMP
"""

UPSERT_APK_SET = """
INSERT INTO apk_sets (
  app_id, app_version_id, package_name, version_code, version_name,
  base_apk_id, base_apk_sha256, artifact_set_hash,
  artifact_set_hash_version, member_count, split_count,
  completeness_state, source_kind, first_seen_at, last_seen_at
) VALUES (
  %s, %s, %s, %s, %s,
  %s, %s, %s,
  %s, %s, %s,
  %s, %s, %s, %s
)
ON DUPLICATE KEY UPDATE
  apk_set_id = LAST_INSERT_ID(apk_set_id),
  app_id = COALESCE(VALUES(app_id), app_id),
  app_version_id = COALESCE(VALUES(app_version_id), app_version_id),
  package_name = VALUES(package_name),
  version_code = COALESCE(VALUES(version_code), version_code),
  version_name = COALESCE(VALUES(version_name), version_name),
  base_apk_id = COALESCE(VALUES(base_apk_id), base_apk_id),
  base_apk_sha256 = VALUES(base_apk_sha256),
  member_count = GREATEST(member_count, VALUES(member_count)),
  split_count = GREATEST(split_count, VALUES(split_count)),
  completeness_state = VALUES(completeness_state),
  source_kind = VALUES(source_kind),
  first_seen_at = COALESCE(LEAST(first_seen_at, VALUES(first_seen_at)), VALUES(first_seen_at), first_seen_at),
  last_seen_at = COALESCE(GREATEST(last_seen_at, VALUES(last_seen_at)), VALUES(last_seen_at), last_seen_at),
  updated_at = CURRENT_TIMESTAMP
"""

UPSERT_APK_SET_MEMBER = """
INSERT INTO apk_set_members (
  apk_set_id, apk_id, role, split_name, sha256, source_path,
  local_relpath, canonical_relpath, member_status, ordinal
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON DUPLICATE KEY UPDATE
  apk_id = COALESCE(VALUES(apk_id), apk_id),
  source_path = COALESCE(VALUES(source_path), source_path),
  local_relpath = COALESCE(VALUES(local_relpath), local_relpath),
  canonical_relpath = COALESCE(VALUES(canonical_relpath), canonical_relpath),
  member_status = VALUES(member_status),
  ordinal = VALUES(ordinal),
  updated_at = CURRENT_TIMESTAMP
"""

UPSERT_HARVEST_OBSERVATION = """
INSERT INTO harvest_apk_observations (
  harvest_session_id, apk_set_id, apk_id, package_name, version_code,
  version_name, role, split_name, sha256, source_path, local_relpath,
  canonical_relpath, pull_status, observed_at_utc
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON DUPLICATE KEY UPDATE
  apk_set_id = COALESCE(VALUES(apk_set_id), apk_set_id),
  apk_id = COALESCE(VALUES(apk_id), apk_id),
  version_code = COALESCE(VALUES(version_code), version_code),
  version_name = COALESCE(VALUES(version_name), version_name),
  source_path = COALESCE(VALUES(source_path), source_path),
  local_relpath = COALESCE(VALUES(local_relpath), local_relpath),
  canonical_relpath = COALESCE(VALUES(canonical_relpath), canonical_relpath),
  pull_status = VALUES(pull_status),
  observed_at_utc = COALESCE(VALUES(observed_at_utc), observed_at_utc),
  updated_at = CURRENT_TIMESTAMP
"""

SELECT_APP_VERSION_FOR_PACKAGE = """
SELECT a.id AS app_id, av.id AS app_version_id
FROM apps a
LEFT JOIN app_versions av
  ON av.app_id = a.id
 AND COALESCE(CAST(av.version_code AS CHAR), '') = COALESCE(%s, '')
 AND COALESCE(av.version_name, '') = COALESCE(%s, '')
WHERE LOWER(TRIM(a.package_name)) = LOWER(TRIM(%s))
ORDER BY av.id DESC
LIMIT 1
"""

__all__ = [
    "CREATE_APK_SETS",
    "CREATE_APK_SET_MEMBERS",
    "CREATE_HARVEST_SESSIONS",
    "CREATE_HARVEST_APK_OBSERVATIONS",
    "CREATE_V_APK_SET_COVERAGE_V1",
    "UPSERT_HARVEST_SESSION",
    "UPSERT_APK_SET",
    "UPSERT_APK_SET_MEMBER",
    "UPSERT_HARVEST_OBSERVATION",
    "SELECT_APP_VERSION_FOR_PACKAGE",
    "_DDL_STATEMENTS",
]
