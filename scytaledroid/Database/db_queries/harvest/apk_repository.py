"""SQL statements related to the android_apk_repository and associated tables."""

UPSERT_APK = """
INSERT INTO android_apk_repository (
    app_id,
    package_name,
    file_name,
    file_size,
    is_system,
    installer,
    version_name,
    version_code,
    md5,
    sha1,
    sha256,
    signer_fingerprint,
    device_serial,
    harvested_at,
    is_split_member,
    split_group_id
) VALUES (
    %(app_id)s,
    %(package_name)s,
    %(file_name)s,
    %(file_size)s,
    %(is_system)s,
    %(installer)s,
    %(version_name)s,
    %(version_code)s,
    %(md5)s,
    %(sha1)s,
    %(sha256)s,
    %(signer_fingerprint)s,
    %(device_serial)s,
    %(harvested_at)s,
    %(is_split_member)s,
    %(split_group_id)s
)
ON DUPLICATE KEY UPDATE
    app_id = COALESCE(VALUES(app_id), app_id),
    file_name = VALUES(file_name),
    file_size = VALUES(file_size),
    is_system = VALUES(is_system),
    installer = VALUES(installer),
    version_name = VALUES(version_name),
    version_code = VALUES(version_code),
    signer_fingerprint = COALESCE(VALUES(signer_fingerprint), signer_fingerprint),
    device_serial = VALUES(device_serial),
    harvested_at = COALESCE(VALUES(harvested_at), harvested_at),
    is_split_member = GREATEST(is_split_member, VALUES(is_split_member)),
    split_group_id = COALESCE(VALUES(split_group_id), split_group_id),
    updated_at = CURRENT_TIMESTAMP
"""

SELECT_APK_ID_BY_SHA256 = """
SELECT apk_id
FROM android_apk_repository
WHERE sha256 = %s
LIMIT 1
"""

SELECT_APK_BY_SHA256 = """
SELECT *
FROM android_apk_repository
WHERE sha256 = %s
LIMIT 1
"""

SELECT_DUPLICATE_HASHES = """
SELECT sha256, COUNT(*) AS occurrences
FROM android_apk_repository
WHERE sha256 IS NOT NULL
GROUP BY sha256
HAVING COUNT(*) > 1
ORDER BY occurrences DESC
LIMIT %s
"""

UPSERT_STORAGE_ROOT = """
INSERT INTO harvest_storage_roots (host_name, data_root)
VALUES (%s, %s)
ON DUPLICATE KEY UPDATE
    data_root = VALUES(data_root),
    updated_at = CURRENT_TIMESTAMP
"""

SELECT_STORAGE_ROOT_ID = """
SELECT root_id
FROM harvest_storage_roots
WHERE host_name = %s AND data_root = %s
LIMIT 1
"""

UPSERT_ARTIFACT_PATH = """
INSERT INTO harvest_artifact_paths (
    apk_id,
    storage_root_id,
    local_rel_path
) VALUES (%s, %s, %s)
ON DUPLICATE KEY UPDATE
    storage_root_id = VALUES(storage_root_id),
    local_rel_path = VALUES(local_rel_path),
    updated_at = CURRENT_TIMESTAMP
"""

UPSERT_SOURCE_PATH = """
INSERT INTO harvest_source_paths (
    apk_id,
    source_path
) VALUES (%s, %s)
ON DUPLICATE KEY UPDATE
    source_path = VALUES(source_path),
    updated_at = CURRENT_TIMESTAMP
"""

UPDATE_APK_SPLIT_GROUP_TEMPLATE = """
UPDATE android_apk_repository
SET split_group_id = %s,
    is_split_member = 1,
    updated_at = CURRENT_TIMESTAMP
WHERE apk_id IN ({placeholders})
"""

SELECT_SPLIT_MEMBERS = """
SELECT apk_id, package_name, file_name, sha256
FROM android_apk_repository
WHERE split_group_id = %s
ORDER BY apk_id
"""

SELECT_APK_IDS_FOR_PACKAGE = """
SELECT apk_id
FROM android_apk_repository
WHERE package_name = %s
ORDER BY created_at DESC
"""

INSERT_SPLIT_GROUP = """
INSERT INTO apk_split_groups (package_name)
VALUES (%s)
"""

SELECT_SPLIT_GROUP_BY_PACKAGE = """
SELECT split_group_id
FROM apk_split_groups
WHERE package_name = %s
ORDER BY created_at DESC
LIMIT 1
"""

UPSERT_APP_DEFINITION = """
INSERT INTO android_app_definitions (package_name, app_name)
VALUES (%s, %s)
ON DUPLICATE KEY UPDATE
    app_name = COALESCE(VALUES(app_name), app_name),
    updated_at = CURRENT_TIMESTAMP
"""

SELECT_APP_ID_BY_PACKAGE = """
SELECT app_id
FROM android_app_definitions
WHERE package_name = %s
LIMIT 1
"""

SELECT_APP_DEFINITION_DETAILS = """
SELECT app_name, category_id, profile_id, profile_name
FROM android_app_definitions
WHERE app_id = %s
LIMIT 1
"""

SELECT_CATEGORY_ID = """
SELECT category_id
FROM android_app_categories
WHERE category_name = %s
LIMIT 1
"""

INSERT_CATEGORY = """
INSERT INTO android_app_categories (category_name)
VALUES (%s)
"""

LIST_CATEGORIES = """
SELECT category_id, category_name
FROM android_app_categories
ORDER BY category_name
"""

__all__ = [name for name in globals() if name.isupper()]
