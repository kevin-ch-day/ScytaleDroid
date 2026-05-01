"""apk_repository.py - High level helpers for the APK repository tables."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache

from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...db_core import database_session, run_sql, run_sql_many
from ...db_queries.harvest import apk_repository as queries
from ...db_utils.package_utils import normalize_package_name
from ...db_utils.publisher_rules import apply_publisher_mapping
from ...db_utils.reference_seed import ensure_default_reference_rows


@dataclass
class ApkRecord:
    """Payload used when ingesting APK metadata into the repository."""

    package_name: str
    app_id: int | None = None
    file_name: str | None = None
    file_size: int | None = None
    is_system: bool = False
    installer: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    signer_fingerprint: str | None = None
    device_serial: str | None = None
    harvested_at: datetime | str | None = None
    is_split_member: bool = False
    split_group_id: int | None = None

    def to_parameters(self) -> dict[str, object]:
        if not self.package_name:
            raise ValueError("package_name is required")
        if not self.sha256:
            raise ValueError("sha256 is required for deduplication")

        harvested_at: object | None
        if isinstance(self.harvested_at, str):
            try:
                harvested_at = datetime.fromisoformat(self.harvested_at)
            except ValueError:
                harvested_at = self.harvested_at
        else:
            harvested_at = self.harvested_at
        return {
            "app_id": self.app_id,
            "package_name": normalize_package_name(self.package_name, context="database"),
            "file_name": self.file_name,
            "file_size": self.file_size,
            "is_system": 1 if self.is_system else 0,
            "installer": self.installer,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "signer_fingerprint": self.signer_fingerprint,
            "device_serial": self.device_serial,
            "harvested_at": harvested_at,
            "is_split_member": 1 if self.is_split_member else 0,
            "split_group_id": self.split_group_id,
        }


def upsert_apk_record(
    record: ApkRecord,
    *,
    context: Mapping[str, object] | None = None,
) -> int:
    """Insert or update an APK row and return the apk_id."""

    params = record.to_parameters()
    query_context = dict(context or {})
    query_context.setdefault("package_name", record.package_name)
    query_context.setdefault("sha256", record.sha256)

    with database_session():
        run_sql(
            queries.UPSERT_APK,
            params,
            query_name="harvest.apk.upsert",
            context=query_context,
        )
        row = run_sql(
            queries.SELECT_APK_ID_BY_SHA256,
            (record.sha256,),
            fetch="one",
            query_name="harvest.apk.lookup_sha",
            context=query_context,
        )
    if not row:
        raise RuntimeError("Failed to resolve apk_id after upsert")
    return int(row[0])


def get_apk_by_sha256(sha256: str) -> dict[str, object] | None:
    """Return a dictionary of APK metadata for the given sha256."""
    return run_sql(queries.SELECT_APK_BY_SHA256, (sha256,), fetch="one", dictionary=True)


def ensure_split_group(
    package_name: str,
    *,
    context: Mapping[str, object] | None = None,
) -> int:
    """Get or create a split group id for the given package."""

    cleaned_package = normalize_package_name(package_name, context="database")
    if not cleaned_package:
        raise ValueError("package_name is required")
    query_context = dict(context or {})
    query_context.setdefault("package_name", cleaned_package)

    with database_session():
        row = run_sql(
            queries.SELECT_SPLIT_GROUP_BY_PACKAGE,
            (cleaned_package,),
            fetch="one",
            query_name="harvest.split_group.lookup",
            context=query_context,
        )
        if row:
            return int(row[0])
        group_id = run_sql(
            queries.INSERT_SPLIT_GROUP,
            (cleaned_package,),
            return_lastrowid=True,
            query_name="harvest.split_group.insert",
            context=query_context,
        )
        if group_id:
            return int(group_id)
        row = run_sql(
            queries.SELECT_SPLIT_GROUP_BY_PACKAGE,
            (cleaned_package,),
            fetch="one",
            query_name="harvest.split_group.lookup",
            context=query_context,
        )
    if not row:
        raise RuntimeError("Failed to create split group")
    return int(row[0])


def mark_split_members(group_id: int, apk_ids: Sequence[int]) -> None:
    """Update the provided apk_ids to belong to the supplied split group."""
    if not apk_ids:
        return
    placeholders = ", ".join(["%s"] * len(apk_ids))
    query = queries.UPDATE_APK_SPLIT_GROUP_TEMPLATE.format(placeholders=placeholders)
    params: list[int] = [group_id]
    params.extend(int(apk_id) for apk_id in apk_ids)
    run_sql(
        query,
        tuple(params),
        query_name="harvest.split_group.mark_members",
    )


def fetch_split_members(group_id: int) -> list[dict[str, object]]:
    """Return metadata for all APKs linked to a split group."""
    return run_sql(queries.SELECT_SPLIT_MEMBERS, (group_id,), fetch="all", dictionary=True)


def fetch_duplicate_hashes(limit: int = 100) -> list[dict[str, object]]:
    """Return SHA-256 values that appear in more than one repository row.

    Expected when the **same APK bytes** were harvested from multiple devices;
    caller interprets multiplicity as reusable content, not necessarily corruption.

    Rows include ``sha256`` and ``occurrences`` counts (see ``SELECT_DUPLICATE_HASHES``).
    """
    return run_sql(queries.SELECT_DUPLICATE_HASHES, (limit,), fetch="all", dictionary=True)


def ensure_app_definition(
    package_name: str,
    app_name: str | None = None,
    *,
    category_name: str | None = None,
    profile_key: str | None = None,
    profile_name: str | None = None,
    context: Mapping[str, object] | None = None,
) -> int:
    """Upsert a canonical app definition row and return app_id."""
    cleaned_package = normalize_package_name(package_name, context="database")
    if not cleaned_package:
        raise ValueError("package_name is required")

    label: str | None
    if app_name and app_name.strip():
        candidate = app_name.strip()
        if candidate.lower() == cleaned_package.lower():
            label = None
        else:
            label = candidate
    else:
        label = None

    query_context = dict(context or {})
    query_context.setdefault("package_name", cleaned_package)

    with database_session():
        # Defensive: some deployments enforce FK constraints from apps.publisher_key/profile_key.
        # Ensure the default dictionary rows exist before inserting into apps.
        ensure_default_reference_rows()
        run_sql(
            queries.UPSERT_APP_DEFINITION,
            (cleaned_package, label),
            query_name="harvest.app_definition.upsert",
            context=query_context,
        )
        row = run_sql(
            queries.SELECT_APP_ID_BY_PACKAGE,
            (cleaned_package,),
            fetch="one",
            query_name="harvest.app_definition.lookup",
            context=query_context,
        )
        if not row:
            raise RuntimeError(f"Failed to resolve app_id for package {package_name}")
        app_id = int(row[0])

        update_fields: list[str] = []
        update_params: list[object] = []

        column_flags = _get_definition_profile_columns()
        if category_name and category_name.strip():
            category_id = get_category_id(category_name.strip())
            update_fields.append("category_id = %s")
            update_params.append(category_id)

        if profile_key and str(profile_key).strip():
            if column_flags["profile_key"]:
                update_fields.append("profile_key = %s")
                update_params.append(str(profile_key).strip())
            else:
                _warn_missing_profile_columns()

        if profile_name and profile_name.strip():
            log.debug(
                "Profile display names are now sourced from android_app_profiles; "
                "skipping direct apps.profile_name updates.",
                category="database",
            )

        if update_fields:
            set_clause = ", ".join(update_fields + ["updated_at = CURRENT_TIMESTAMP"])
            update_params.append(cleaned_package)
            run_sql(
                f"""UPDATE apps
                SET {set_clause}
                WHERE package_name = %s""",
                tuple(update_params),
                query_name="harvest.app_definition.update",
                context=query_context,
            )
        apply_publisher_mapping([cleaned_package], context=query_context)

    return app_id


def bulk_ensure_app_definitions(
    package_rows: Sequence[tuple[str, str | None]],
) -> int:
    """Upsert many canonical app definitions in one DB session.

    Rows are inventory-style ``(package_name, app_label)`` pairs; normalization
    and display-name trimming match ``ensure_app_definition``.
    """

    merged: dict[str, tuple[str, str | None]] = {}
    for raw_pkg, app_name in package_rows:
        cleaned = normalize_package_name(str(raw_pkg), context="database")
        if not cleaned:
            continue
        if app_name and str(app_name).strip():
            candidate = str(app_name).strip()
            label: str | None = None if candidate.lower() == cleaned.lower() else candidate
        else:
            label = None
        merged[cleaned] = (cleaned, label)

    batch = list(merged.values())
    if not batch:
        return 0

    query_context = {"bulk_app_definitions": len(batch)}
    with database_session():
        ensure_default_reference_rows()
        run_sql_many(
            queries.UPSERT_APP_DEFINITION,
            batch,
            query_name="harvest.app_definition.upsert_bulk",
            context=query_context,
        )
        apply_publisher_mapping([row[0] for row in batch], context=query_context)
    return len(batch)


@lru_cache(maxsize=1)
def _get_definition_profile_columns() -> dict[str, bool]:
    """Return availability flags for profile columns on apps."""

    try:
        rows = run_sql(
            """
            SELECT COLUMN_NAME
            FROM information_schema.columns
            WHERE table_schema = DATABASE() AND table_name = 'apps'
            """,
            fetch="all",
            dictionary=True,
        ) or []
    except Exception as exc:  # pragma: no cover - defensive
        log.warning(
            f"Failed to inspect apps columns: {exc}",
            category="database",
        )
        return {"profile_key": False}

    normalised = {
        str(entry.get("COLUMN_NAME")).lower()
        for entry in rows
        if isinstance(entry, dict) and entry.get("COLUMN_NAME")
    }
    return {
        "profile_key": "profile_key" in normalised,
    }


_PROFILE_WARNING_EMITTED = False


def _warn_missing_profile_columns() -> None:
    """Log a single actionable warning when profile columns are missing."""

    global _PROFILE_WARNING_EMITTED
    if _PROFILE_WARNING_EMITTED:
        return

    _PROFILE_WARNING_EMITTED = True
    log.warning(
        "Profile metadata detected but apps lacks profile_key."
        " Run the database migration to add it.",
        category="database",
    )


def get_category_id(category_name: str) -> int:
    """Fetch or create a category and return its id."""
    row = run_sql(queries.SELECT_CATEGORY_ID, (category_name,), fetch="one")
    if row:
        return int(row[0])
    category_id = run_sql(queries.INSERT_CATEGORY, (category_name,), return_lastrowid=True)
    if category_id:
        return int(category_id)
    row = run_sql(queries.SELECT_CATEGORY_ID, (category_name,), fetch="one")
    if not row:
        raise RuntimeError("Failed to create category")
    return int(row[0])


def list_categories() -> list[dict[str, object]]:
    """Return all available categories sorted alphabetically."""
    return run_sql(queries.LIST_CATEGORIES, fetch="all", dictionary=True)


def assign_split_members(package_name: str, apk_ids: Iterable[int]) -> int:
    """Convenience helper to create a split group and assign members."""
    apk_ids_list = [int(apk_id) for apk_id in apk_ids]
    if not apk_ids_list:
        raise ValueError("assign_split_members requires at least one apk_id")
    group_id = ensure_split_group(package_name)
    mark_split_members(group_id, apk_ids_list)
    return group_id


def ensure_storage_root(
    host_name: str,
    data_root: str,
    *,
    context: Mapping[str, object] | None = None,
) -> int:
    """Insert or update a storage root entry and return its identifier."""

    query_context = dict(context or {})
    query_context.setdefault("host_name", host_name)
    query_context.setdefault("data_root", data_root)

    run_sql(
        queries.UPSERT_STORAGE_ROOT,
        (host_name, data_root),
        query_name="harvest.storage_root.upsert",
        context=query_context,
    )
    row = run_sql(
        queries.SELECT_STORAGE_ROOT_ID,
        (host_name, data_root),
        fetch="one",
        query_name="harvest.storage_root.lookup",
        context=query_context,
    )
    if not row:
        raise RuntimeError("Failed to resolve storage root id")
    return int(row[0])


def upsert_artifact_path(
    apk_id: int,
    *,
    storage_root_id: int,
    local_rel_path: str | None,
    context: Mapping[str, object] | None = None,
) -> None:
    """Persist or update path metadata for the given artifact."""

    query_context = dict(context or {})
    query_context.setdefault("apk_id", apk_id)

    run_sql(
        queries.UPSERT_ARTIFACT_PATH,
        (
            apk_id,
            storage_root_id,
            local_rel_path,
        ),
        query_name="harvest.artifact_path.upsert",
        context=query_context,
    )


def upsert_source_path(
    apk_id: int,
    source_path: str | None,
    *,
    context: Mapping[str, object] | None = None,
) -> None:
    """Persist the source path metadata for an artifact."""

    if not source_path:
        return

    query_context = dict(context or {})
    query_context.setdefault("apk_id", apk_id)
    query_context.setdefault("artifact_path", source_path)

    run_sql(
        queries.UPSERT_SOURCE_PATH,
        (
            apk_id,
            source_path,
        ),
        query_name="harvest.source_path.upsert",
        context=query_context,
    )


__all__ = [
    "ApkRecord",
    "upsert_apk_record",
    "get_apk_by_sha256",
    "ensure_split_group",
    "mark_split_members",
    "fetch_split_members",
    "fetch_duplicate_hashes",
    "get_category_id",
    "list_categories",
    "assign_split_members",
    "bulk_ensure_app_definitions",
    "ensure_app_definition",
    "ensure_storage_root",
    "upsert_artifact_path",
    "upsert_source_path",
]
