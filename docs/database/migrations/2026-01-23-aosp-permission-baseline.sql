CREATE TABLE IF NOT EXISTS aosp_permission_baseline (
  android_release VARCHAR(16) NOT NULL,
  source_type ENUM('AOSP_MANIFEST','OFFICIAL_DOCS','PLATFORM_EXTRACT') NOT NULL,
  baseline_sha256 CHAR(64) NOT NULL,
  generated_at_utc DATETIME NULL,
  permission_string VARCHAR(255) NOT NULL,
  PRIMARY KEY (android_release, permission_string),
  KEY ix_aosp_perm (permission_string)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
