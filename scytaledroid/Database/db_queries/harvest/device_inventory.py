"""SQL statements for persisting device inventory snapshots and package rows."""

CREATE_SNAPSHOTS_TABLE = """
CREATE TABLE IF NOT EXISTS device_inventory_snapshots (
  snapshot_id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  device_serial          VARCHAR(64)     NOT NULL,
  captured_at            DATETIME        NOT NULL,
  package_count          INT UNSIGNED    NOT NULL,
  duration_seconds       DOUBLE          DEFAULT NULL,
  package_hash           CHAR(64)        DEFAULT NULL,
  package_list_hash      CHAR(64)        DEFAULT NULL,
  package_signature_hash CHAR(64)        DEFAULT NULL,
  build_fingerprint      VARCHAR(191)    DEFAULT NULL,
  scope_hash             CHAR(64)        DEFAULT NULL,
  snapshot_type          VARCHAR(32)     DEFAULT NULL,
  scope_variant          VARCHAR(64)     DEFAULT NULL,
  scope_size             INT UNSIGNED    DEFAULT NULL,
  extras                 JSON            DEFAULT NULL,
  created_at             TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at             TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
                                            ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (snapshot_id),
  KEY idx_inventory_device_time (device_serial, captured_at),
  KEY idx_inventory_hash (device_serial, package_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


CREATE_INVENTORY_TABLE = """
CREATE TABLE IF NOT EXISTS device_inventory (
  snapshot_id        BIGINT UNSIGNED NOT NULL,
  device_serial      VARCHAR(64)     NOT NULL,
  package_name       VARCHAR(191)    NOT NULL,
  app_label          VARCHAR(255)    DEFAULT NULL,
  version_name       VARCHAR(191)    DEFAULT NULL,
  version_code       VARCHAR(64)     DEFAULT NULL,
  installer          VARCHAR(191)    DEFAULT NULL,
  category_name      VARCHAR(128)    DEFAULT NULL,
  category_id        BIGINT          DEFAULT NULL,
  inferred_category  TINYINT(1)      NOT NULL DEFAULT 0,
  source_label       VARCHAR(64)     DEFAULT NULL,
  partition_label    VARCHAR(64)     DEFAULT NULL,
  profile_id         VARCHAR(64)     DEFAULT NULL,
  profile_name       VARCHAR(191)    DEFAULT NULL,
  inferred_profile   TINYINT(1)      NOT NULL DEFAULT 0,
  split_count        INT UNSIGNED    NOT NULL DEFAULT 1,
  is_split           TINYINT(1)      NOT NULL DEFAULT 0,
  review_needed      TINYINT(1)      NOT NULL DEFAULT 0,
  first_install      VARCHAR(64)     DEFAULT NULL,
  last_update        VARCHAR(64)     DEFAULT NULL,
  primary_path       VARCHAR(512)    DEFAULT NULL,
  apk_dirs           JSON            DEFAULT NULL,
  apk_paths          JSON            DEFAULT NULL,
  extras             JSON            DEFAULT NULL,
  created_at         TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (snapshot_id, package_name),
  KEY idx_device_inventory_device_pkg (device_serial, package_name),
  KEY idx_device_inventory_snapshot (snapshot_id),
  CONSTRAINT fk_device_inventory_snapshot
      FOREIGN KEY (snapshot_id)
      REFERENCES device_inventory_snapshots (snapshot_id)
      ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


INSERT_SNAPSHOT = """
INSERT INTO device_inventory_snapshots (
    device_serial,
    captured_at,
    package_count,
    duration_seconds,
    package_hash,
    package_list_hash,
    package_signature_hash,
    build_fingerprint,
    scope_hash,
    snapshot_type,
    scope_variant,
    scope_size,
    extras
) VALUES (
    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
)
"""


DELETE_PACKAGES_FOR_SNAPSHOT = """
DELETE FROM device_inventory
WHERE snapshot_id = %s
"""


INSERT_PACKAGE = """
INSERT INTO device_inventory (
    snapshot_id,
    device_serial,
    package_name,
    app_label,
    version_name,
    version_code,
    installer,
    category_name,
    category_id,
    inferred_category,
    source_label,
    partition_label,
    profile_id,
    profile_name,
    inferred_profile,
    split_count,
    is_split,
    review_needed,
    first_install,
    last_update,
    primary_path,
    apk_dirs,
    apk_paths,
    extras
) VALUES (
    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
)
"""


__all__ = [
    "CREATE_SNAPSHOTS_TABLE",
    "CREATE_INVENTORY_TABLE",
    "INSERT_SNAPSHOT",
    "DELETE_PACKAGES_FOR_SNAPSHOT",
    "INSERT_PACKAGE",
]
