"""Exact APK-hash target resolution for static analysis.

This module intentionally refuses package/name/version fallbacks.  It resolves
repository APK identity by ``apk_id`` and/or base SHA-256, verifies local bytes,
and builds a ``ScopeSelection`` that can be passed to the normal static runner.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.Utils.IO.atomic_write import atomic_write_text

from ...core.repository import ArtifactGroup, RepositoryArtifact, group_artifacts
from ..core.models import ScopeSelection

try:  # optional DB access for offline imports/tests
    from scytaledroid.Database.db_core import db_queries as core_q
except Exception:  # pragma: no cover - DB optional
    core_q = None

SplitMode = Literal["auto", "base-only", "require"]


class ExactTargetResolutionError(RuntimeError):
    """Raised when exact-hash target resolution cannot be completed safely."""


@dataclass(frozen=True)
class VerifiedArtifact:
    apk_id: str | None
    package_name: str
    path: Path
    expected_sha256: str
    actual_sha256: str
    is_split_member: bool
    artifact_label: str | None = None


@dataclass(frozen=True)
class ExactStaticTarget:
    package_name: str
    apk_id: str | None
    expected_base_sha256: str
    actual_base_sha256: str
    base_path: Path
    split_mode: str
    receipt_backed: bool
    session_stamp: str | None
    capture_id: str | None
    group_key: str
    artifacts: tuple[VerifiedArtifact, ...]
    selection: ScopeSelection

    @property
    def split_count(self) -> int:
        return sum(1 for artifact in self.artifacts if artifact.is_split_member)


@dataclass(frozen=True)
class ExactTargetReadiness:
    package_name: str
    apk_id: str | None
    base_apk_sha256: str | None
    dynamic_runs: int | None
    repository_row_exists: bool
    db_split_members_count: int
    receipt_backed_group_available: bool
    base_file_available: bool
    base_file_hash_verified: bool
    split_files_available: int
    split_files_expected: int
    canonical_store_file_available: bool
    recorded_local_file_available: bool
    storage_root_id: str | None
    recorded_storage_root: str | None
    recorded_storage_root_exists: bool
    recorded_abs_path: str | None
    canonical_store_path: str | None
    recommended_action: str
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "package_name": self.package_name,
            "apk_id": self.apk_id,
            "base_apk_sha256": self.base_apk_sha256,
            "dynamic_runs": self.dynamic_runs,
            "repository_row_exists": self.repository_row_exists,
            "db_split_members_count": self.db_split_members_count,
            "receipt_backed_group_available": self.receipt_backed_group_available,
            "base_file_available": self.base_file_available,
            "base_file_hash_verified": self.base_file_hash_verified,
            "split_files_available": self.split_files_available,
            "split_files_expected": self.split_files_expected,
            "canonical_store_file_available": self.canonical_store_file_available,
            "recorded_local_file_available": self.recorded_local_file_available,
            "storage_root_id": self.storage_root_id,
            "recorded_storage_root": self.recorded_storage_root,
            "recorded_storage_root_exists": self.recorded_storage_root_exists,
            "recorded_abs_path": self.recorded_abs_path,
            "canonical_store_path": self.canonical_store_path,
            "recommended_action": self.recommended_action,
            "reason": self.reason,
        }


def resolve_exact_static_target(
    *,
    apk_id: int | str | None = None,
    base_apk_sha256: str | None = None,
    package_name: str | None = None,
    include_splits: SplitMode = "auto",
) -> ExactStaticTarget:
    """Resolve and validate an exact static-analysis target.

    ``include_splits='auto'`` uses a receipt-backed group when available and
    aborts when the split set cannot be reconstructed.  ``base-only`` is the only
    mode that permits single-base analysis without receipt-backed split context.
    """

    mode = _normalize_split_mode(include_splits)
    expected_hash = _normalize_sha256(base_apk_sha256)
    requested_apk_id = _normalize_apk_id(apk_id)
    if not requested_apk_id and not expected_hash:
        raise ExactTargetResolutionError("Provide apk_id or base_apk_sha256 for exact target resolution.")

    row = _lookup_repository_row(
        apk_id=requested_apk_id,
        base_apk_sha256=expected_hash,
        package_name=package_name,
    )
    if row is None:
        raise ExactTargetResolutionError("No android_apk_repository row matched the requested exact target.")

    row_apk_id = _normalize_apk_id(row.get("apk_id"))
    row_hash = _normalize_sha256(row.get("sha256"))
    row_package = _normalize_package(row.get("package_name"))
    requested_package = _normalize_package(package_name)
    if requested_package and row_package and requested_package != row_package:
        raise ExactTargetResolutionError(
            f"Requested package {requested_package} does not match repository row package {row_package}."
        )
    if expected_hash and row_hash and expected_hash != row_hash:
        raise ExactTargetResolutionError(
            f"Requested base_apk_sha256 {expected_hash} does not match apk_id {row_apk_id} hash {row_hash}."
        )
    expected_hash = expected_hash or row_hash
    if not expected_hash:
        raise ExactTargetResolutionError("Repository row has no SHA-256 for exact target validation.")
    package = requested_package or row_package
    if not package:
        raise ExactTargetResolutionError("Repository row has no package_name for exact target validation.")

    receipt_group = _find_receipt_group(
        apk_id=row_apk_id,
        base_apk_sha256=expected_hash,
        package_name=package,
    )
    if mode in {"auto", "require"}:
        if receipt_group is None:
            raise ExactTargetResolutionError(
                "Receipt-backed split set unavailable for exact target. "
                "Re-run with include-splits=base-only only if base-only analysis is intentional."
            )
        return _target_from_group(
            receipt_group,
            expected_base_sha256=expected_hash,
            requested_apk_id=row_apk_id,
            split_mode="receipt-backed-group",
        )

    base_artifact = None
    if receipt_group is not None:
        base_artifact = _matching_base_artifact(receipt_group, row_apk_id, expected_hash)
    if base_artifact is None:
        base_artifact = _artifact_from_repository_row(row)
    base_verified = _verify_repository_artifact(
        base_artifact,
        expected_sha256=expected_hash,
        require_metadata_hash=True,
    )
    group = ArtifactGroup(
        group_key=f"exact-base-only-{expected_hash}",
        package_name=package,
        version_display=base_artifact.version_display,
        session_stamp=base_artifact.session_stamp,
        capture_id=base_artifact.capture_id,
        artifacts=(base_artifact,),
        grouping_reason="exact_base_only",
        grouping_confidence="high",
        harvest_manifest_path=str(base_artifact.metadata.get("harvest_manifest_path") or "") or None,
    )
    label = f"Exact base-only | {package} | {expected_hash[:12]}... | split-set-unavailable"
    selection = ScopeSelection("app", label, (group,), selection_rule_summary="Exact base APK only")
    return ExactStaticTarget(
        package_name=package,
        apk_id=row_apk_id,
        expected_base_sha256=expected_hash,
        actual_base_sha256=base_verified.actual_sha256,
        base_path=base_verified.path,
        split_mode="base-only",
        receipt_backed=receipt_group is not None,
        session_stamp=group.session_stamp,
        capture_id=group.capture_id,
        group_key=group.group_key,
        artifacts=(base_verified,),
        selection=selection,
    )


def assess_exact_target_readiness(
    *,
    apk_id: int | str | None = None,
    base_apk_sha256: str | None = None,
    package_name: str | None = None,
    dynamic_runs: int | None = None,
    groups: tuple[ArtifactGroup, ...] | None = None,
) -> ExactTargetReadiness:
    """Report whether a dynamic/static worklist row has analyzable local bytes.

    This is deliberately read-only.  It does not create receipts, static runs, or
    dynamic links, and it never falls back to newest package captures.
    """

    expected_hash = _normalize_sha256(base_apk_sha256)
    requested_apk_id = _normalize_apk_id(apk_id)
    requested_package = _normalize_package(package_name)
    if not requested_apk_id and not expected_hash:
        raise ExactTargetResolutionError("Provide apk_id or base_apk_sha256 for exact target readiness.")

    row = _lookup_repository_row(
        apk_id=requested_apk_id,
        base_apk_sha256=expected_hash,
        package_name=requested_package,
    )
    if row is None:
        return ExactTargetReadiness(
            package_name=requested_package,
            apk_id=requested_apk_id,
            base_apk_sha256=expected_hash,
            dynamic_runs=dynamic_runs,
            repository_row_exists=False,
            db_split_members_count=0,
            receipt_backed_group_available=False,
            base_file_available=False,
            base_file_hash_verified=False,
            split_files_available=0,
            split_files_expected=0,
            canonical_store_file_available=False,
            recorded_local_file_available=False,
            storage_root_id=None,
            recorded_storage_root=None,
            recorded_storage_root_exists=False,
            recorded_abs_path=None,
            canonical_store_path=None,
            recommended_action="explicit_reharvest_needed",
            reason="no android_apk_repository row matched this exact target",
        )

    row_apk_id = _normalize_apk_id(row.get("apk_id"))
    row_hash = _normalize_sha256(row.get("sha256"))
    row_package = _normalize_package(row.get("package_name")) or requested_package
    if expected_hash and row_hash and expected_hash != row_hash:
        return ExactTargetReadiness(
            package_name=row_package,
            apk_id=row_apk_id,
            base_apk_sha256=expected_hash,
            dynamic_runs=dynamic_runs,
            repository_row_exists=True,
            db_split_members_count=0,
            receipt_backed_group_available=False,
            base_file_available=False,
            base_file_hash_verified=False,
            split_files_available=0,
            split_files_expected=0,
            canonical_store_file_available=False,
            recorded_local_file_available=False,
            storage_root_id=_text_or_none(row.get("storage_root_id")),
            recorded_storage_root=_text_or_none(row.get("data_root")),
            recorded_storage_root_exists=_path_exists(row.get("data_root")),
            recorded_abs_path=_candidate_recorded_abs_path(row),
            canonical_store_path=_candidate_canonical_store_path(row),
            recommended_action="hash_mismatch",
            reason=f"requested hash does not match repository hash {row_hash}",
        )
    expected_hash = expected_hash or row_hash

    split_rows = _lookup_same_capture_split_rows(row)
    split_files_expected = len(split_rows)
    recorded_base_path = _resolve_recorded_local_path(row)
    canonical_base_path = _resolve_canonical_store_path(row)
    recorded_abs_path = _candidate_recorded_abs_path(row)
    canonical_store_path = _candidate_canonical_store_path(row)
    recorded_available = bool(recorded_base_path and recorded_base_path.exists())
    canonical_available = bool(canonical_base_path and canonical_base_path.exists())
    base_path = recorded_base_path if recorded_available else canonical_base_path if canonical_available else None
    base_hash_verified = False
    base_hash_mismatch = False
    if base_path and expected_hash:
        actual = _sha256_file(base_path)
        base_hash_verified = actual == expected_hash
        base_hash_mismatch = actual != expected_hash

    split_files_available = 0
    split_hash_mismatch = False
    for split_row in split_rows:
        split_path = _resolve_recorded_local_path(split_row) or _resolve_canonical_store_path(split_row)
        split_sha = _normalize_sha256(split_row.get("sha256"))
        if split_path and split_path.exists() and split_sha:
            actual = _sha256_file(split_path)
            if actual == split_sha:
                split_files_available += 1
            else:
                split_hash_mismatch = True

    search_groups = groups if groups is not None else tuple(group_artifacts())
    receipt_group = _find_receipt_group(
        apk_id=row_apk_id,
        base_apk_sha256=expected_hash or "",
        package_name=row_package,
        groups=search_groups,
    ) if expected_hash else None
    receipt_available = receipt_group is not None

    if base_hash_mismatch or split_hash_mismatch:
        action = "hash_mismatch"
        reason = "local bytes exist but at least one hash does not match repository identity"
    elif receipt_available and base_hash_verified:
        if split_files_available == split_files_expected:
            action = "exact_static_available"
            reason = "receipt-backed group and required local bytes are available"
        else:
            action = "partial_split_restore_needed"
            reason = "receipt-backed group exists but one or more split files are missing"
    elif not base_path:
        root_exists = _path_exists(row.get("data_root"))
        if root_exists:
            action = "explicit_reharvest_needed"
            reason = (
                "recorded storage root exists, but base APK bytes are missing from "
                "the recorded path and canonical SHA store"
            )
        else:
            action = (
                "restore_artifacts"
                if _has_recorded_or_canonical_location(row, split_rows)
                else "explicit_reharvest_needed"
            )
            reason = "base APK bytes are not available from recorded path or canonical SHA store"
    elif not base_hash_verified:
        action = "hash_mismatch"
        reason = "base APK bytes failed exact SHA-256 verification"
    elif split_files_expected and split_files_available < split_files_expected:
        action = "partial_split_restore_needed"
        reason = "base bytes are verified but one or more DB split member files are missing"
    elif split_files_expected:
        action = "split_context_unavailable"
        reason = "base and DB split bytes are present but no receipt-backed split group is available"
    else:
        action = "base_only_available_explicit"
        reason = "verified base bytes are available; no split members were found for this capture"

    return ExactTargetReadiness(
        package_name=row_package,
        apk_id=row_apk_id,
        base_apk_sha256=expected_hash,
        dynamic_runs=dynamic_runs,
        repository_row_exists=True,
        db_split_members_count=len(split_rows),
        receipt_backed_group_available=receipt_available,
        base_file_available=bool(base_path and base_path.exists()),
        base_file_hash_verified=base_hash_verified,
        split_files_available=split_files_available,
        split_files_expected=split_files_expected,
        canonical_store_file_available=canonical_available,
        recorded_local_file_available=recorded_available,
        storage_root_id=_text_or_none(row.get("storage_root_id")),
        recorded_storage_root=_text_or_none(row.get("data_root")),
        recorded_storage_root_exists=_path_exists(row.get("data_root")),
        recorded_abs_path=recorded_abs_path,
        canonical_store_path=canonical_store_path,
        recommended_action=action,
        reason=reason,
    )


def write_exact_target_receipt(
    target: ExactStaticTarget,
    *,
    source_worklist_bucket: str | None = None,
) -> Path:
    """Write a small receipt documenting exact-hash preflight validation."""

    created = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    root = artifact_store.receipts_root() / "static_exact_targets"
    root.mkdir(parents=True, exist_ok=True)
    name = (
        f"{artifact_store.safe_filesystem_slug(target.package_name)}-"
        f"{target.expected_base_sha256[:12]}-{created}.json"
    )
    path = root / name
    payload = {
        "created_at": created,
        "package_name": target.package_name,
        "requested_base_apk_sha256": target.expected_base_sha256,
        "resolved_apk_id": target.apk_id,
        "actual_base_apk_sha256": target.actual_base_sha256,
        "split_mode": target.split_mode,
        "receipt_backed": target.receipt_backed,
        "session_stamp": target.session_stamp,
        "capture_id": target.capture_id,
        "group_key": target.group_key,
        "source_worklist_bucket": source_worklist_bucket,
        "hash_verification_status": "verified",
        "split_members": [
            {
                "apk_id": artifact.apk_id,
                "package_name": artifact.package_name,
                "path": artifact_store.repo_relative_path(artifact.path),
                "expected_sha256": artifact.expected_sha256,
                "actual_sha256": artifact.actual_sha256,
                "is_split_member": artifact.is_split_member,
                "artifact_label": artifact.artifact_label,
            }
            for artifact in target.artifacts
        ],
    }
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def count_linkable_dynamic_sessions_for_hash(base_apk_sha256: str) -> int | None:
    """Return a dry-run count of dynamic rows now linkable by exact hash."""

    if core_q is None:
        return None
    sha = _normalize_sha256(base_apk_sha256)
    if not sha:
        return None
    try:
        row = core_q.run_sql(
            """
            SELECT COUNT(*) AS c
            FROM dynamic_sessions ds
            WHERE ds.static_run_id IS NULL
              AND ds.base_apk_sha256 = %s
              AND EXISTS (
                SELECT 1
                FROM v_static_handoff_v1 h
                WHERE h.base_apk_sha256 = ds.base_apk_sha256
              )
            """,
            (sha,),
            fetch="one_dict",
        )
    except Exception:
        return None
    if not isinstance(row, Mapping):
        return None
    return int(row.get("c") or 0)


def _target_from_group(
    group: ArtifactGroup,
    *,
    expected_base_sha256: str,
    requested_apk_id: str | None,
    split_mode: str,
) -> ExactStaticTarget:
    base = _matching_base_artifact(group, requested_apk_id, expected_base_sha256)
    if base is None:
        raise ExactTargetResolutionError("Receipt-backed group did not contain the requested base APK.")
    verified = tuple(
        _verify_repository_artifact(
            artifact,
            expected_sha256=_expected_artifact_sha(artifact),
            require_metadata_hash=True,
        )
        for artifact in group.artifacts
    )
    base_verified = next((item for item in verified if not item.is_split_member), None)
    if base_verified is None:
        raise ExactTargetResolutionError("Receipt-backed group has no verified base APK.")
    if base_verified.actual_sha256 != expected_base_sha256:
        raise ExactTargetResolutionError(
            "Receipt-backed group base hash did not match requested base_apk_sha256."
        )
    label = (
        f"Exact dynamic base hash + harvested split set | "
        f"{group.package_name} | {expected_base_sha256[:12]}..."
    )
    selection = ScopeSelection(
        "app",
        label,
        (group,),
        selection_rule_summary="Exact base APK hash with receipt-backed split set",
    )
    return ExactStaticTarget(
        package_name=group.package_name,
        apk_id=requested_apk_id or base_verified.apk_id,
        expected_base_sha256=expected_base_sha256,
        actual_base_sha256=base_verified.actual_sha256,
        base_path=base_verified.path,
        split_mode=split_mode,
        receipt_backed=True,
        session_stamp=group.session_stamp,
        capture_id=group.capture_id,
        group_key=group.group_key,
        artifacts=verified,
        selection=selection,
    )


def _lookup_repository_row(
    *,
    apk_id: str | None,
    base_apk_sha256: str | None,
    package_name: str | None,
) -> Mapping[str, object] | None:
    if core_q is None:
        raise ExactTargetResolutionError("Database query support is unavailable for exact target resolution.")
    clauses: list[str] = []
    params: list[object] = []
    if apk_id:
        clauses.append("r.apk_id = %s")
        params.append(int(apk_id))
    if base_apk_sha256:
        clauses.append("LOWER(TRIM(r.sha256)) = %s")
        params.append(base_apk_sha256)
    package = _normalize_package(package_name)
    if package:
        clauses.append("LOWER(TRIM(r.package_name)) = %s")
        params.append(package)
    where = " AND ".join(clauses)
    rows = core_q.run_sql(
        f"""
        SELECT
          r.apk_id,
          r.package_name,
          r.file_name,
          r.file_size,
          r.version_name,
          r.version_code,
          r.sha256,
          r.is_split_member,
          r.split_group_id,
          h.storage_root_id,
          h.local_rel_path,
          sr.data_root,
          s.source_path
        FROM android_apk_repository r
        LEFT JOIN harvest_artifact_paths h ON h.apk_id = r.apk_id
        LEFT JOIN harvest_storage_roots sr ON sr.root_id = h.storage_root_id
        LEFT JOIN harvest_source_paths s ON s.apk_id = r.apk_id
        WHERE {where}
        ORDER BY h.updated_at DESC, r.updated_at DESC
        LIMIT 2
        """,
        tuple(params),
        fetch="all_dict",
        query_name="static.exact_target.lookup_repository_row",
    )
    if not rows:
        return None
    if not apk_id and len(rows) > 1:
        raise ExactTargetResolutionError(
            "base_apk_sha256 matched multiple repository rows; provide apk_id for exact target resolution."
        )
    row = rows[0]
    return row if isinstance(row, Mapping) else None


def _find_receipt_group(
    *,
    apk_id: str | None,
    base_apk_sha256: str,
    package_name: str,
    groups: tuple[ArtifactGroup, ...] | None = None,
) -> ArtifactGroup | None:
    for group in groups if groups is not None else group_artifacts():
        if _normalize_package(group.package_name) != package_name:
            continue
        if _matching_base_artifact(group, apk_id, base_apk_sha256) is not None:
            if _is_receipt_backed(group):
                return group
    return None


def _lookup_same_capture_split_rows(base_row: Mapping[str, object]) -> tuple[Mapping[str, object], ...]:
    if core_q is None:
        return ()
    package = _normalize_package(base_row.get("package_name"))
    split_group_id = base_row.get("split_group_id")
    if not package or split_group_id is None:
        return ()
    try:
        rows = core_q.run_sql(
            """
            SELECT
              r.apk_id,
              r.package_name,
              r.file_name,
              r.file_size,
              r.version_name,
              r.version_code,
              r.sha256,
              r.is_split_member,
              r.split_group_id,
              h.storage_root_id,
              h.local_rel_path,
              sr.data_root,
              s.source_path
            FROM android_apk_repository r
            LEFT JOIN harvest_artifact_paths h ON h.apk_id = r.apk_id
            LEFT JOIN harvest_storage_roots sr ON sr.root_id = h.storage_root_id
            LEFT JOIN harvest_source_paths s ON s.apk_id = r.apk_id
            WHERE LOWER(TRIM(r.package_name)) = %s
              AND r.split_group_id = %s
              AND r.apk_id <> %s
              AND COALESCE(r.is_split_member, 0) = 1
            ORDER BY r.apk_id
            """,
            (package, split_group_id, int(str(base_row.get("apk_id") or "0"))),
            fetch="all_dict",
            query_name="static.exact_target.lookup_same_capture_splits",
        )
    except Exception:
        return ()
    source_parent = _parent_text(base_row.get("source_path"))
    local_parent = _parent_text(base_row.get("local_rel_path"))
    selected: list[Mapping[str, object]] = []
    for row in rows or []:
        if not isinstance(row, Mapping):
            continue
        if source_parent and _parent_text(row.get("source_path")) == source_parent:
            selected.append(row)
        elif not source_parent and local_parent and _parent_text(row.get("local_rel_path")) == local_parent:
            selected.append(row)
    return tuple(selected)


def _parent_text(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return str(Path(text).parent)


def _matching_base_artifact(
    group: ArtifactGroup,
    apk_id: str | None,
    base_apk_sha256: str,
) -> RepositoryArtifact | None:
    base = group.base_artifact
    if base is None:
        return None
    base_sha = _normalize_sha256(base.sha256)
    base_apk_id = _normalize_apk_id(base.apk_id)
    if apk_id and base_apk_id and apk_id != base_apk_id:
        return None
    if base_sha != base_apk_sha256:
        return None
    return base


def _is_receipt_backed(group: ArtifactGroup) -> bool:
    if group.harvest_manifest_path:
        return True
    for artifact in group.artifacts:
        metadata = artifact.metadata if isinstance(artifact.metadata, Mapping) else {}
        if metadata.get("receipt_path") or metadata.get("harvest_manifest_path"):
            return True
    return False


def _artifact_from_repository_row(row: Mapping[str, object]) -> RepositoryArtifact:
    sha = _normalize_sha256(row.get("sha256"))
    path = _resolve_local_path(row)
    if path is None:
        raise ExactTargetResolutionError("Local artifact path is missing or does not exist for exact target.")
    metadata = {
        "apk_id": row.get("apk_id"),
        "package_name": row.get("package_name"),
        "version_name": row.get("version_name"),
        "version_code": row.get("version_code"),
        "sha256": sha,
        "is_split_member": bool(row.get("is_split_member")),
        "split_group_id": row.get("split_group_id"),
        "local_artifact_path": row.get("local_rel_path"),
    }
    return RepositoryArtifact(path=path, display_path=artifact_store.repo_relative_path(path), metadata=metadata)


def _resolve_local_path(row: Mapping[str, object]) -> Path | None:
    recorded = _resolve_recorded_local_path(row)
    if recorded and recorded.exists():
        return recorded
    canonical = _resolve_canonical_store_path(row)
    if canonical and canonical.exists():
        return canonical
    return None


def _resolve_recorded_local_path(row: Mapping[str, object]) -> Path | None:
    candidates = _recorded_path_candidates(row)
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate
        if resolved.exists():
            return resolved
    return None


def _recorded_path_candidates(row: Mapping[str, object]) -> list[Path]:
    raw = str(row.get("local_rel_path") or "").strip()
    candidates: list[Path] = []
    if not raw:
        return candidates
    p = Path(raw).expanduser()
    candidates.append(p if p.is_absolute() else (Path.cwd() / p))
    data_root = str(row.get("data_root") or "").strip()
    if data_root:
        root = Path(data_root).expanduser()
        candidates.append((root / raw) if root.is_absolute() else (Path.cwd() / root / raw))
    return candidates


def _candidate_recorded_abs_path(row: Mapping[str, object]) -> str | None:
    candidates = _recorded_path_candidates(row)
    if not candidates:
        return None
    preferred = candidates[-1]
    try:
        return preferred.resolve(strict=False).as_posix()
    except OSError:
        return preferred.as_posix()


def _candidate_canonical_store_path(row: Mapping[str, object]) -> str | None:
    path = _resolve_canonical_store_path(row)
    if path is None:
        return None
    try:
        return path.resolve(strict=False).as_posix()
    except OSError:
        return path.as_posix()


def _resolve_canonical_store_path(row: Mapping[str, object]) -> Path | None:
    sha = _normalize_sha256(row.get("sha256"))
    if sha:
        return artifact_store.canonical_apk_path(sha)
    return None


def _has_recorded_or_canonical_location(
    base_row: Mapping[str, object],
    split_rows: tuple[Mapping[str, object], ...],
) -> bool:
    if base_row.get("local_rel_path") or _normalize_sha256(base_row.get("sha256")):
        return True
    return any(row.get("local_rel_path") or _normalize_sha256(row.get("sha256")) for row in split_rows)


def _text_or_none(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _path_exists(value: object) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    return Path(text).expanduser().exists()


def _verify_repository_artifact(
    artifact: RepositoryArtifact,
    *,
    expected_sha256: str | None,
    require_metadata_hash: bool,
) -> VerifiedArtifact:
    expected = _normalize_sha256(expected_sha256)
    if not expected and require_metadata_hash:
        raise ExactTargetResolutionError(
            f"Missing expected SHA-256 for artifact {artifact.display_path}; refusing exact analysis."
        )
    if not artifact.path.exists():
        raise ExactTargetResolutionError(f"Local artifact missing: {artifact.path}")
    actual = _sha256_file(artifact.path)
    if expected and actual != expected:
        raise ExactTargetResolutionError(
            f"Hash mismatch for {artifact.path}: expected {expected}, actual {actual}."
        )
    return VerifiedArtifact(
        apk_id=_normalize_apk_id(artifact.apk_id),
        package_name=artifact.package_name,
        path=artifact.path.resolve(),
        expected_sha256=expected or actual,
        actual_sha256=actual,
        is_split_member=bool(artifact.is_split_member),
        artifact_label=str(artifact.artifact_label or "") or None,
    )


def _expected_artifact_sha(artifact: RepositoryArtifact) -> str | None:
    return _normalize_sha256(artifact.sha256)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_split_mode(value: object) -> SplitMode:
    text = str(value or "auto").strip().lower()
    if text not in {"auto", "base-only", "require"}:
        raise ExactTargetResolutionError("include_splits must be one of: auto, base-only, require.")
    return text  # type: ignore[return-value]


def _normalize_sha256(value: object) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise ExactTargetResolutionError(f"Invalid SHA-256 value: {text!r}")
    return text


def _normalize_apk_id(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return str(int(text))
    except ValueError as exc:
        raise ExactTargetResolutionError(f"Invalid apk_id value: {text!r}") from exc


def _normalize_package(value: object) -> str:
    return str(value or "").strip().lower()


__all__ = [
    "ExactStaticTarget",
    "ExactTargetReadiness",
    "ExactTargetResolutionError",
    "SplitMode",
    "VerifiedArtifact",
    "assess_exact_target_readiness",
    "count_linkable_dynamic_sessions_for_hash",
    "resolve_exact_static_target",
    "write_exact_target_receipt",
]
