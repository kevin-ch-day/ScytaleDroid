"""SQL statements for permission analytics support tables."""

from __future__ import annotations

CREATE_SIGNAL_CATALOG = """
CREATE TABLE IF NOT EXISTS permission_signal_catalog (
    signal_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    signal_key VARCHAR(64) NOT NULL,
    display_name VARCHAR(128) NOT NULL,
    description TEXT NULL,
    default_weight DECIMAL(8,3) NOT NULL DEFAULT 0.000,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (signal_id),
    UNIQUE KEY ux_permission_signal_catalog_key (signal_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_SIGNAL_MAPPINGS = """
CREATE TABLE IF NOT EXISTS permission_signal_mappings (
    mapping_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    signal_key VARCHAR(64) NOT NULL,
    perm_name VARCHAR(191) NOT NULL,
    namespace VARCHAR(64) NULL,
    confidence ENUM('low','medium','high') NOT NULL DEFAULT 'high',
    notes VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (mapping_id),
    UNIQUE KEY ux_permission_signal_mappings_pair (signal_key, perm_name, namespace),
    KEY ix_permission_signal_mappings_perm (perm_name),
    CONSTRAINT fk_permission_signal_mappings_signal
        FOREIGN KEY (signal_key)
        REFERENCES permission_signal_catalog (signal_key)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_COHORT_EXPECTATIONS = """
CREATE TABLE IF NOT EXISTS permission_cohort_expectations (
    expectation_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    cohort VARCHAR(64) NOT NULL,
    signal_key VARCHAR(64) NOT NULL,
    expected TINYINT(1) NOT NULL DEFAULT 0,
    notes VARCHAR(255) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (expectation_id),
    UNIQUE KEY ux_permission_cohort_expectations (cohort, signal_key),
    CONSTRAINT fk_permission_cohort_expectations_signal
        FOREIGN KEY (signal_key)
        REFERENCES permission_signal_catalog (signal_key)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_AUDIT_SNAPSHOTS = """
CREATE TABLE IF NOT EXISTS permission_audit_snapshots (
    snapshot_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    snapshot_key VARCHAR(64) NOT NULL,
    scope_label VARCHAR(128) NULL,
    apps_total INT UNSIGNED NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    metadata JSON NULL,
    PRIMARY KEY (snapshot_id),
    UNIQUE KEY ux_permission_audit_snapshots_key (snapshot_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_AUDIT_APPS = """
CREATE TABLE IF NOT EXISTS permission_audit_apps (
    audit_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    snapshot_id BIGINT UNSIGNED NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    app_label VARCHAR(255) NULL,
    score_raw DECIMAL(8,3) NULL,
    score_capped DECIMAL(8,3) NULL,
    grade CHAR(1) NULL,
    dangerous_count INT UNSIGNED NULL,
    signature_count INT UNSIGNED NULL,
    vendor_count INT UNSIGNED NULL,
    combos_total DECIMAL(8,3) NULL,
    surprises_total DECIMAL(8,3) NULL,
    legacy_total DECIMAL(8,3) NULL,
    vendor_modifier DECIMAL(8,3) NULL,
    modernization_credit DECIMAL(8,3) NULL,
    details JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (audit_id),
    UNIQUE KEY ux_permission_audit_apps_snapshot_pkg (snapshot_id, package_name),
    KEY ix_permission_audit_apps_score (snapshot_id, score_capped),
    CONSTRAINT fk_permission_audit_apps_snapshot
        FOREIGN KEY (snapshot_id)
        REFERENCES permission_audit_snapshots (snapshot_id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

__all__ = [
    "CREATE_SIGNAL_CATALOG",
    "CREATE_SIGNAL_MAPPINGS",
    "CREATE_COHORT_EXPECTATIONS",
    "CREATE_AUDIT_SNAPSHOTS",
    "CREATE_AUDIT_APPS",
]
