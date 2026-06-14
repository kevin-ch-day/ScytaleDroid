"""Artifact-level pull and persistence orchestration for harvest."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

from .models import ArtifactError, ArtifactPlan, ArtifactResult, PackagePlan

EmitFn = Callable[[str, str, Mapping[str, object | None], str | None], None]


@dataclass(frozen=True)
class ArtifactExecutionRequest:
    serial: str
    adb_path: str
    package_dir: Path
    plan: PackagePlan
    artifact: ArtifactPlan
    app_id: int | None
    group_id: int | None
    verbose: bool
    options: object
    tracker: object
    session_stamp: str
    storage_root_id: int | None
    artifact_index: int
    artifact_total: int
    verbose_output: bool
    base_context: Mapping[str, object]
    db_repo: ModuleType | None
    emit: EmitFn
    stats: dict[str, int]
    snapshot_id: int | None
    snapshot_captured_at: str | None


@dataclass(frozen=True)
class ArtifactExecutionDeps:
    adb_pull: Callable[..., object]
    compute_hashes: Callable[[Path], Mapping[str, str]]
    tracker_register: Callable[[str], tuple[bool, int]]
    cleanup_duplicate: Callable[[Path], None]
    materialize_apk: Callable[[Path, str, str], Path]
    repo_relative_path: Callable[[Path], str]
    inventory_signer_fingerprint: Callable[[object], str | None]
    inventory_payload: Callable[[object], Mapping[str, object]]
    write_metadata_sidecar: Callable[..., None]
    print_artifact_status: Callable[[str, str, int, int, str, str], None]
    replace_session_apk_with_symlink_to_canonical: Callable[[Path, Path, bool], None]
    format_file_size: Callable[[int], str]
    artifact_status_suffix: Callable[[str], str]
    is_system_package: Callable[[object], bool]
    normalise_local_path: Callable[[Path], str]
    log_warning: Callable[[str, str], None]
    log_error: Callable[[str, str], None]


def pull_and_record(
    request: ArtifactExecutionRequest,
    deps: ArtifactExecutionDeps,
) -> tuple[ArtifactResult | ArtifactError | None, str | None]:
    dest_path = request.package_dir / request.artifact.file_name
    pull_result = deps.adb_pull(
        adb_path=request.adb_path,
        serial=request.serial,
        source_path=request.artifact.source_path,
        dest_path=dest_path,
        package_name=request.plan.inventory.package_name,
        verbose=request.verbose_output,
        overwrite_existing=request.options.overwrite_existing,
    )
    if isinstance(pull_result, ArtifactError):
        return _handle_pull_error(request, deps, pull_result)

    try:
        hashes = deps.compute_hashes(dest_path)
    except FileNotFoundError as exc:  # pragma: no cover - IO race
        return ArtifactError(source_path=request.artifact.source_path, reason=str(exc)), None

    keep, occurrence = deps.tracker_register(hashes["sha256"])
    if not keep:
        return _handle_duplicate(request, deps, dest_path)

    canonical_store_path, canonical_abs = _materialize_canonical_copy(request, deps, dest_path, hashes["sha256"])
    apk_id, mirror_failure_reasons = _persist_db_mirror(
        request=request,
        deps=deps,
        dest_path=dest_path,
        hashes=hashes,
    )
    _write_sidecar(
        request=request,
        deps=deps,
        dest_path=dest_path,
        hashes=hashes,
        apk_id=apk_id,
        occurrence=occurrence,
        canonical_store_path=canonical_store_path,
    )
    _report_success(request, deps, dest_path, apk_id)

    if canonical_abs is not None:
        deps.replace_session_apk_with_symlink_to_canonical(
            session_artifact_path=dest_path,
            canonical_absolute=canonical_abs,
            enabled=request.options.thin_session,
        )

    return (
        ArtifactResult(
            file_name=dest_path.name,
            apk_id=apk_id,
            dest_path=dest_path,
            source_path=request.artifact.source_path,
            sha256=hashes.get("sha256"),
            file_size=dest_path.stat().st_size if dest_path.exists() else None,
            pulled_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            artifact_label=request.artifact.artifact,
            is_base=not request.artifact.is_split_member,
            observed_source_path=request.artifact.source_path,
            mirror_failure_reasons=mirror_failure_reasons,
            canonical_store_path=canonical_store_path,
        ),
        None,
    )


def _handle_pull_error(
    request: ArtifactExecutionRequest,
    deps: ArtifactExecutionDeps,
    pull_result: ArtifactError,
) -> tuple[ArtifactError, None]:
    retryable_stale_path = pull_result.reason == "path_stale"
    deps.print_artifact_status(
        request.plan.inventory.display_name(),
        request.artifact.file_name,
        request.artifact_index,
        request.artifact_total,
        deps.artifact_status_suffix(pull_result.reason),
        "warn" if retryable_stale_path else "error",
    )
    request.emit(
        "warning" if retryable_stale_path else "error",
        "harvest.artifact.retryable" if retryable_stale_path else "harvest.artifact.error",
        extra={
            "package_name": request.plan.inventory.package_name,
            "artifact_path": request.artifact.source_path,
            "file_name": request.artifact.file_name,
            "error": pull_result.reason,
        },
    )
    return pull_result, None


def _handle_duplicate(
    request: ArtifactExecutionRequest,
    deps: ArtifactExecutionDeps,
    dest_path: Path,
) -> tuple[None, str]:
    deps.cleanup_duplicate(dest_path)
    deps.print_artifact_status(
        request.plan.inventory.display_name(),
        request.artifact.file_name,
        request.artifact_index,
        request.artifact_total,
        "skipped duplicate (sha256 match)",
        "warn",
    )
    request.emit(
        "info",
        "harvest.artifact.skipped",
        extra={
            "package_name": request.plan.inventory.package_name,
            "artifact_path": request.artifact.source_path,
            "file_name": request.artifact.file_name,
            "skip_reason": "dedupe_sha256",
        },
    )
    return None, "dedupe_sha256"


def _materialize_canonical_copy(
    request: ArtifactExecutionRequest,
    deps: ArtifactExecutionDeps,
    dest_path: Path,
    sha256_digest: str,
) -> tuple[str | None, Path | None]:
    canonical_store_path: str | None = None
    canonical_abs: Path | None = None
    try:
        canonical_path = deps.materialize_apk(
            dest_path,
            sha256_digest=sha256_digest,
            suffix=dest_path.suffix or ".apk",
        )
        canonical_abs = canonical_path.expanduser().resolve()
        canonical_store_path = deps.repo_relative_path(canonical_path)
    except Exception as exc:
        deps.log_warning(
            f"Failed to materialize canonical APK store entry for {dest_path}: {exc}",
            "filesystem",
        )
    return canonical_store_path, canonical_abs


def _persist_db_mirror(
    *,
    request: ArtifactExecutionRequest,
    deps: ArtifactExecutionDeps,
    dest_path: Path,
    hashes: Mapping[str, str],
) -> tuple[int | None, list[str]]:
    apk_id: int | None = None
    mirror_failure_reasons: list[str] = []
    if not (request.options.write_db and request.db_repo is not None):
        return apk_id, mirror_failure_reasons

    record = request.db_repo.ApkRecord(
        package_name=request.plan.inventory.package_name,
        app_id=request.app_id,
        file_name=dest_path.name,
        file_size=dest_path.stat().st_size,
        is_system=deps.is_system_package(request.plan.inventory),
        installer=request.plan.inventory.installer,
        version_name=request.plan.inventory.version_name,
        version_code=request.plan.inventory.version_code,
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        sha256=hashes["sha256"],
        signer_fingerprint=deps.inventory_signer_fingerprint(request.plan.inventory),
        device_serial=request.serial,
        harvested_at=datetime.now(UTC),
        is_split_member=request.artifact.is_split_member,
        split_group_id=request.group_id,
    )
    try:
        apk_id = request.db_repo.upsert_apk_record(
            record,
            context={
                **request.base_context,
                "package_name": request.plan.inventory.package_name,
                "artifact_path": request.artifact.source_path,
                "sha256": hashes["sha256"],
            },
        )
        request.stats["db_apk_rows"] += 1
    except Exception as exc:
        deps.log_error(
            f"Failed to upsert APK metadata for {request.plan.inventory.package_name} ({request.artifact.source_path}): {exc}",
            "database",
        )
        request.stats["db_errors"] += 1
        request.emit(
            "error",
            "harvest.db.error",
            extra={
                "package_name": request.plan.inventory.package_name,
                "artifact_path": request.artifact.source_path,
                "stage": "upsert_apk_record",
                "error": str(exc),
            },
        )
        mirror_failure_reasons.append("apk_record_failed")

    if apk_id and request.storage_root_id is not None:
        _persist_artifact_path(request, deps, apk_id)
    if apk_id and request.artifact.source_path:
        _persist_source_path(request, deps, apk_id, mirror_failure_reasons)
    return apk_id, mirror_failure_reasons


def _persist_artifact_path(
    request: ArtifactExecutionRequest,
    deps: ArtifactExecutionDeps,
    apk_id: int,
) -> None:
    try:
        request.db_repo.upsert_artifact_path(
            apk_id,
            storage_root_id=request.storage_root_id,
            local_rel_path=deps.normalise_local_path(request.package_dir / request.artifact.file_name),
            context={
                **request.base_context,
                "package_name": request.plan.inventory.package_name,
                "artifact_path": request.artifact.source_path,
                "apk_id": apk_id,
            },
        )
        request.stats["db_artifact_paths"] += 1
    except Exception as exc:
        deps.log_warning(f"Failed to persist artifact path for apk_id={apk_id}: {exc}", "database")
        request.stats["db_errors"] += 1
        request.emit(
            "warning",
            "harvest.db.error",
            extra={
                "package_name": request.plan.inventory.package_name,
                "artifact_path": request.artifact.source_path,
                "stage": "upsert_artifact_path",
                "error": str(exc),
            },
        )


def _persist_source_path(
    request: ArtifactExecutionRequest,
    deps: ArtifactExecutionDeps,
    apk_id: int,
    mirror_failure_reasons: list[str],
) -> None:
    try:
        request.db_repo.upsert_source_path(
            apk_id,
            request.artifact.source_path,
            context={
                **request.base_context,
                "package_name": request.plan.inventory.package_name,
                "artifact_path": request.artifact.source_path,
                "apk_id": apk_id,
            },
        )
        request.stats["db_source_paths"] += 1
    except Exception as exc:
        deps.log_warning(f"Failed to persist source path for apk_id={apk_id}: {exc}", "database")
        request.stats["db_errors"] += 1
        request.emit(
            "warning",
            "harvest.db.error",
            extra={
                "package_name": request.plan.inventory.package_name,
                "artifact_path": request.artifact.source_path,
                "stage": "upsert_source_path",
                "error": str(exc),
            },
        )
        mirror_failure_reasons.append("source_path_failed")


def _write_sidecar(
    *,
    request: ArtifactExecutionRequest,
    deps: ArtifactExecutionDeps,
    dest_path: Path,
    hashes: Mapping[str, str],
    apk_id: int | None,
    occurrence: int,
    canonical_store_path: str | None,
) -> None:
    artifact_payload = {
        "source_path": request.artifact.source_path,
        "is_split_member": request.artifact.is_split_member,
        "split_group_id": request.group_id,
    }
    inventory_meta = deps.inventory_payload(request.plan.inventory)
    extra_meta = {
        "apk_id": apk_id,
        "occurrence_index": occurrence,
        "artifact": request.artifact.artifact,
        "artifact_kind": "apk",
        "canonical_store_path": canonical_store_path,
    }
    if request.snapshot_id is not None:
        extra_meta["snapshot_id"] = request.snapshot_id
    if request.snapshot_captured_at:
        extra_meta["snapshot_captured_at"] = request.snapshot_captured_at
    try:
        deps.write_metadata_sidecar(
            dest_path,
            inventory=inventory_meta,
            artifact=artifact_payload,
            hashes=hashes,
            serial=request.serial,
            session_stamp=request.session_stamp,
            options=request.options,
            extra=extra_meta,
        )
    except Exception as exc:  # pragma: no cover
        deps.log_warning(f"Failed to write metadata sidecar for {dest_path}: {exc}", "filesystem")


def _report_success(
    request: ArtifactExecutionRequest,
    deps: ArtifactExecutionDeps,
    dest_path: Path,
    apk_id: int | None,
) -> None:
    file_size_text = deps.format_file_size(dest_path.stat().st_size)
    deps.print_artifact_status(
        request.plan.inventory.display_name(),
        request.artifact.file_name,
        request.artifact_index,
        request.artifact_total,
        f"saved ({file_size_text})",
        "success",
    )
    request.emit(
        "info",
        "harvest.artifact.saved",
        extra={
            "package_name": request.plan.inventory.package_name,
            "artifact_path": request.artifact.source_path,
            "file_name": dest_path.name,
            "bytes": dest_path.stat().st_size if dest_path.exists() else None,
            "apk_id": apk_id,
        },
    )


__all__ = [
    "ArtifactExecutionDeps",
    "ArtifactExecutionRequest",
    "pull_and_record",
]
