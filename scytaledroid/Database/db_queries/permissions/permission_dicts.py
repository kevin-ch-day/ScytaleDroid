"""SQL helpers for permission dictionary + vendor metadata tables."""

from __future__ import annotations


SELECT_AOSP_BY_VALUE = """
SELECT constant_value,
       name,
       protection_level,
       hard_restricted,
       soft_restricted,
       not_for_third_party_apps,
       is_deprecated,
       added_in_api_level,
       deprecated_in_api_level
FROM android_permission_dict_aosp
WHERE constant_value IN ({placeholders})
"""


SELECT_AOSP_BY_VALUE_LOWER = """
SELECT constant_value,
       name,
       protection_level,
       hard_restricted,
       soft_restricted,
       not_for_third_party_apps,
       is_deprecated,
       added_in_api_level,
       deprecated_in_api_level
FROM android_permission_dict_aosp
WHERE LOWER(constant_value) IN ({placeholders})
"""


SELECT_AOSP_BY_NAME = """
SELECT name,
       protection_level,
       hard_restricted,
       soft_restricted,
       not_for_third_party_apps,
       is_deprecated,
       added_in_api_level,
       deprecated_in_api_level
FROM android_permission_dict_aosp
WHERE name IN ({placeholders})
"""


SELECT_OEM_BY_VALUE = """
SELECT permission_string,
       vendor_id,
       display_name,
       protection_level,
       confidence,
       classification_source
FROM android_permission_dict_oem
WHERE permission_string IN ({placeholders})
"""


SELECT_VENDOR_PREFIX_RULES = """
SELECT vendor_id, namespace_prefix, match_type
FROM android_permission_meta_oem_prefix
WHERE is_enabled=1
ORDER BY CHAR_LENGTH(namespace_prefix) DESC, prefix_id ASC
"""


SELECT_VENDOR_META = """
SELECT vendor_id, vendor_name, vendor_slug
FROM android_permission_meta_oem_vendor
"""


UPSERT_UNKNOWN = """
INSERT INTO android_permission_dict_unknown
  (permission_string, triage_status, notes,
   first_seen_at_utc, last_seen_at_utc, seen_count, example_package_name, example_sample_id)
VALUES
  (%(permission_string)s, %(triage_status)s, %(notes)s,
   %(first_seen_at_utc)s, %(last_seen_at_utc)s, %(seen_count)s, %(example_package_name)s, %(example_sample_id)s)
ON DUPLICATE KEY UPDATE
  last_seen_at_utc = VALUES(last_seen_at_utc),
  seen_count = seen_count + 1,
  example_package_name = COALESCE(example_package_name, VALUES(example_package_name)),
  example_sample_id = COALESCE(example_sample_id, VALUES(example_sample_id)),
  notes = COALESCE(notes, VALUES(notes)),
  triage_status = CASE WHEN triage_status = 'new' THEN VALUES(triage_status) ELSE triage_status END
"""


INSERT_QUEUE = """
INSERT INTO android_permission_dict_queue
  (permission_string, queue_action, proposed_bucket, proposed_classification, triage_status,
   notes, requested_by, source_system, status, created_at_utc, updated_at_utc)
VALUES
  (%(permission_string)s, %(queue_action)s, %(proposed_bucket)s, %(proposed_classification)s, %(triage_status)s,
   %(notes)s, %(requested_by)s, %(source_system)s, %(status)s, %(created_at_utc)s, %(updated_at_utc)s)
ON DUPLICATE KEY UPDATE
  updated_at_utc = VALUES(updated_at_utc),
  triage_status = VALUES(triage_status),
  notes = COALESCE(notes, VALUES(notes))
"""


UPDATE_OEM_SEEN = """
UPDATE android_permission_dict_oem
SET last_seen_at_utc = %(last_seen_at_utc)s,
    seen_count = seen_count + 1
WHERE permission_string = %(permission_string)s
"""


__all__ = [
    "SELECT_AOSP_BY_VALUE",
    "SELECT_AOSP_BY_VALUE_LOWER",
    "SELECT_AOSP_BY_NAME",
    "SELECT_OEM_BY_VALUE",
    "SELECT_VENDOR_PREFIX_RULES",
    "SELECT_VENDOR_META",
    "UPSERT_UNKNOWN",
    "INSERT_QUEUE",
    "UPDATE_OEM_SEEN",
]
