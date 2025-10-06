# Harvest Path Tables

Use these DDL snippets to create the tables introduced in phase 2. Run them once in your ScytaleDroid schema.

```sql
CREATE TABLE `harvest_storage_roots` (
  `root_id`     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `host_name`   VARCHAR(255)    NOT NULL,
  `data_root`   VARCHAR(512)    NOT NULL,
  `created_at`  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
                               ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`root_id`),
  UNIQUE KEY `uniq_host_root` (`host_name`, `data_root`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `harvest_artifact_paths` (
  `apk_id`          BIGINT UNSIGNED NOT NULL,
  `storage_root_id` BIGINT UNSIGNED NOT NULL,
  `source_path`     VARCHAR(512)    DEFAULT NULL,
  `local_rel_path`  VARCHAR(512)    DEFAULT NULL,
  `created_at`      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
                                   ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`apk_id`),
  KEY `idx_storage_root` (`storage_root_id`),
  CONSTRAINT `fk_hap_apk` FOREIGN KEY (`apk_id`)
      REFERENCES `android_apk_repository` (`apk_id`) ON DELETE CASCADE,
  CONSTRAINT `fk_hap_root` FOREIGN KEY (`storage_root_id`)
      REFERENCES `harvest_storage_roots` (`root_id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

## Usage notes
* The CLI registers the ingest environment via `harvest_storage_roots` (host + data root) before recording artifacts.
* Each artifact row in `android_apk_repository` gets a companion row in `harvest_artifact_paths` that references the storage root and stores both the device `source_path` and local relative path.
* Delete cascades ensure path entries are removed automatically when an artifact row is deleted.
