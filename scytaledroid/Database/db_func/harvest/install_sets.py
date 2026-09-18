"""Helpers for receipt-backed APK install-set identity tables."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from scytaledroid.Utils.install_set_identity import (
    NEW_INSTALL_SET_HASH_VERSION,
    V1,
    V2,
    compute_artifact_set_hash,
)
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...db_core import run_sql
from ...db_queries.harvest import install_sets as q


@dataclass(frozen=True)
class InstallSetMember:
    apk_id: int | None
    role: str
    split_name: str
    sha256: str
    source_path: str | None = None
    local_relpath: str | None = None
    canonical_relpath: str | None = None
    member_status: str = "written"
    ordinal: int = 0


@dataclass(frozen=True)
class InstallSetRecord:
    session_label: str
    package_name: str
    device_serial: str | None
    snapshot_id: int | None
    app_id: int | None
    version_code: str | None
    version_name: str | None
    status: str
    generated_at_utc: datetime | None
    receipt_root: str | None
    members: tuple[InstallSetMember, ...]
    source_kind: str = "harvest_runner"


def ensure_tables() -> None:
    """Create additive install-set tables and coverage view if missing."""

    for stmt in q._DDL_STATEMENTS:
        run_sql(stmt, query_name="harvest.install_sets.ensure_table")
    run_sql(q.CREATE_V_APK_SET_COVERAGE_V1, query_name="harvest.install_sets.ensure_view")


def artifact_set_hash_v1(members: Sequence[InstallSetMember]) -> str:
    """Return the historical v1 digest for install-set members."""

    return compute_artifact_set_hash(members, version=V1)


def artifact_set_hash_v2(members: Sequence[InstallSetMember]) -> str:
    """Return the current new-set v2 digest for install-set members."""

    return compute_artifact_set_hash(members, version=V2)


def lookup_stored_install_set_identity(
    *,
    v1_hash: str | None,
    v2_hash: str | None,
) -> dict[str, str] | None:
    """Return an existing apk_sets identity, preferring stored v1 over a parallel v2."""

    first = str(v1_hash or "").strip().lower()
    second = str(v2_hash or "").strip().lower()
    if not first and not second:
        return None
    row = run_sql(
        q.SELECT_EXISTING_APK_SET_IDENTITY,
        (first or second, second or first),
        fetch="one_dict",
        query_name="harvest.install_sets.lookup_existing_identity",
    )
    if not isinstance(row, Mapping):
        return None
    digest = str(row.get("artifact_set_hash") or "").strip().lower()
    version = str(row.get("artifact_set_hash_version") or "").strip()
    apk_set_id = row.get("apk_set_id")
    if not digest or not version or apk_set_id is None:
        return None
    return {
        "apk_set_id": str(int(apk_set_id)),
        "artifact_set_hash": digest,
        "artifact_set_hash_version": version,
    }


def upsert_install_set(record: InstallSetRecord) -> int | None:
    """Upsert harvest session, APK set, members, and observations.

    Returns the ``apk_set_id`` when a complete-enough record was written.  Raises
    on DB errors so the harvest runner can record a mirror failure while keeping
    filesystem harvest behavior intact.
    """

    if not record.members:
        return None
    base_members = [member for member in record.members if member.role == "base"]
    if len(base_members) != 1:
        return None
    if any(not _valid_sha(member.sha256) for member in record.members):
        return None

    ensure_tables()
    app = _lookup_app_version(record)
    session_id = _upsert_harvest_session(record)
    v1_hash = artifact_set_hash_v1(record.members)
    v2_hash = artifact_set_hash_v2(record.members)
    stored = lookup_stored_install_set_identity(v1_hash=v1_hash, v2_hash=v2_hash)
    if stored:
        artifact_hash = stored["artifact_set_hash"]
        hash_version = stored["artifact_set_hash_version"]
    else:
        artifact_hash = v2_hash
        hash_version = NEW_INSTALL_SET_HASH_VERSION
    apk_set_id = _upsert_apk_set(
        record,
        app=app,
        artifact_set_hash=artifact_hash,
        artifact_set_hash_version=hash_version,
        base_member=base_members[0],
    )
    for member in record.members:
        _upsert_apk_set_member(apk_set_id, member)
        _upsert_observation(
            record,
            member,
            harvest_session_id=session_id,
            apk_set_id=apk_set_id,
        )
    return apk_set_id


def _upsert_harvest_session(record: InstallSetRecord) -> int:
    return int(
        run_sql(
            q.UPSERT_HARVEST_SESSION,
            (
                record.session_label,
                record.device_serial,
                record.snapshot_id,
                _naive_utc(record.generated_at_utc),
                record.status,
                record.receipt_root,
            ),
            return_lastrowid=True,
            query_name="harvest.install_sets.upsert_session",
        )
    )


def _upsert_apk_set(
    record: InstallSetRecord,
    *,
    app: Mapping[str, Any],
    artifact_set_hash: str,
    artifact_set_hash_version: str,
    base_member: InstallSetMember,
) -> int:
    return int(
        run_sql(
            q.UPSERT_APK_SET,
            (
                app.get("app_id") or record.app_id,
                app.get("app_version_id"),
                record.package_name,
                record.version_code,
                record.version_name,
                base_member.apk_id,
                base_member.sha256,
                artifact_set_hash,
                artifact_set_hash_version,
                len(record.members),
                len([member for member in record.members if member.role == "split"]),
                _completeness_state(record),
                record.source_kind,
                _naive_utc(record.generated_at_utc),
                _naive_utc(record.generated_at_utc),
            ),
            return_lastrowid=True,
            query_name="harvest.install_sets.upsert_set",
        )
    )


def _upsert_apk_set_member(apk_set_id: int, member: InstallSetMember) -> None:
    run_sql(
        q.UPSERT_APK_SET_MEMBER,
        (
            apk_set_id,
            member.apk_id,
            member.role,
            member.split_name,
            member.sha256,
            member.source_path,
            member.local_relpath,
            member.canonical_relpath,
            member.member_status,
            member.ordinal,
        ),
        query_name="harvest.install_sets.upsert_member",
    )


def _upsert_observation(
    record: InstallSetRecord,
    member: InstallSetMember,
    *,
    harvest_session_id: int,
    apk_set_id: int,
) -> None:
    run_sql(
        q.UPSERT_HARVEST_OBSERVATION,
        (
            harvest_session_id,
            apk_set_id,
            member.apk_id,
            record.package_name,
            record.version_code,
            record.version_name,
            member.role,
            member.split_name,
            member.sha256,
            member.source_path,
            member.local_relpath,
            member.canonical_relpath,
            member.member_status,
            _naive_utc(record.generated_at_utc),
        ),
        query_name="harvest.install_sets.upsert_observation",
    )


def _lookup_app_version(record: InstallSetRecord) -> dict[str, Any]:
    row = run_sql(
        q.SELECT_APP_VERSION_FOR_PACKAGE,
        (record.version_code, record.version_name, record.package_name),
        fetch="one_dict",
        query_name="harvest.install_sets.lookup_app_version",
    )
    return dict(row or {})


def _ordered_members(members: Sequence[InstallSetMember]) -> list[InstallSetMember]:
    base = [member for member in members if member.role == "base"]
    splits = sorted((member for member in members if member.role != "base"), key=lambda item: item.split_name)
    return base + splits


def _valid_sha(value: str | None) -> bool:
    text = str(value or "").strip().lower()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _naive_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(UTC).replace(tzinfo=None)
    return value


def _completeness_state(record: InstallSetRecord) -> str:
    if record.status == "clean":
        return "complete"
    if record.status in {"partial", "drifted"}:
        return "partial"
    return "unknown"


def log_mirror_failure(package_name: str, exc: Exception) -> None:
    log.warning(
        f"Failed to persist install-set spine for {package_name}: {exc}",
        category="database",
    )


__all__ = [
    "InstallSetMember",
    "InstallSetRecord",
    "artifact_set_hash_v1",
    "artifact_set_hash_v2",
    "ensure_tables",
    "log_mirror_failure",
    "lookup_stored_install_set_identity",
    "upsert_install_set",
]
