"""Web-owned additive tables for Phase-1 integration."""

from __future__ import annotations

CREATE_WEB_ANNOTATIONS = """
CREATE TABLE IF NOT EXISTS web_annotations (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  entity_type VARCHAR(64) NOT NULL,
  entity_id VARCHAR(191) NOT NULL,
  note_text TEXT NOT NULL,
  created_at_utc TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_by VARCHAR(128) NULL,
  PRIMARY KEY (id),
  KEY ix_web_annot_entity (entity_type, entity_id),
  KEY ix_web_annot_created (created_at_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

CREATE_WEB_USER_PREFS = """
CREATE TABLE IF NOT EXISTS web_user_prefs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(128) NOT NULL,
  pref_key VARCHAR(191) NOT NULL,
  value_json JSON NULL,
  updated_at_utc TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY ux_web_prefs_user_key (username, pref_key),
  KEY ix_web_prefs_updated (updated_at_utc)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

__all__ = [
  "CREATE_WEB_ANNOTATIONS",
  "CREATE_WEB_USER_PREFS",
]
