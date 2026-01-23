"""Schema for permission governance snapshots (Erebus-aligned)."""

CREATE_GOVERNANCE_SNAPSHOTS = """
CREATE TABLE IF NOT EXISTS permission_governance_snapshots (
  governance_version VARCHAR(32) NOT NULL,
  snapshot_sha256 CHAR(64) NOT NULL,
  source_system ENUM('EREBUS','SCYTALEDROID') NOT NULL DEFAULT 'EREBUS',
  created_at_utc DATETIME NULL,
  loaded_at_utc DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  notes TEXT NULL,
  PRIMARY KEY (governance_version),
  UNIQUE KEY uq_gov_sha (snapshot_sha256)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

CREATE_GOVERNANCE_ENTRIES = """
CREATE TABLE IF NOT EXISTS permission_governance_snapshot_rows (
  governance_version VARCHAR(32) NOT NULL,
  permission_string VARCHAR(255) NOT NULL,
  namespace_type ENUM('AOSP','GMS','OEM','APP_DEFINED','THIRD_PARTY_SDK','UNKNOWN') NOT NULL,
  theme_primary VARCHAR(64) NOT NULL,
  theme_tags_json JSON NULL,
  risk_class ENUM('A','B','C','U') NOT NULL,
  triage_status VARCHAR(32) NOT NULL,
  last_reviewed_at_utc DATETIME NULL,
  reviewer_id VARCHAR(128) NULL,
  notes TEXT NULL,
  PRIMARY KEY (governance_version, permission_string),
  KEY ix_gov_ns (namespace_type),
  KEY ix_gov_theme (theme_primary),
  KEY ix_gov_risk (risk_class)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

__all__ = [
    "CREATE_GOVERNANCE_SNAPSHOTS",
    "CREATE_GOVERNANCE_ENTRIES",
]
