"""APK library registry and compatibility helpers.

The byte store remains ``data/store/apk/sha256``.  This module adds the
package/version/split-set layer under ``data/android_apks`` so harvest sessions
can record observations without becoming the primary APK storage location.
"""

from __future__ import annotations

import csv
import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.DeviceAnalysis.harvest.models import (
    ArtifactPlan,
    ArtifactResult,
    InventoryRow,
    PackagePlan,
    PullResult,
)
from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, group_artifacts
from scytaledroid.Utils.IO.atomic_write import atomic_write_text


@dataclass(frozen=True)
class ApkLibraryArtifact:
    role: str
    split_name: str
    file_name: str
    device_path: str
    sha256: str
    size_bytes: int | None
    canonical_path: Path
    canonical_relpath: str


@dataclass(frozen=True)
class ApkLibraryEntry:
    package_name: str
    version_code: str
    version_name: str | None
    planned_split_set_hash: str
    split_set_hash: str
    entry_dir: Path
    manifest_path: Path
    artifacts: tuple[ApkLibraryArtifact, ...]
    source: str


def library_root() -> Path:
    return artifact_store.data_root() / "android_apks"


def package_version_dir(package_name: str, version_code: str) -> Path:
    return library_root() / "packages" / _safe_segment(package_name) / _safe_segment(version_code or "unknown")


def split_set_dir(package_name: str, version_code: str, planned_split_set_hash: str) -> Path:
    return package_version_dir(package_name, version_code) / "split_sets" / planned_split_set_hash


def planned_split_set_hash_for_plan(plan: PackagePlan) -> str:
    """Hash the pre-pull split identity available from inventory/planning."""

    entries = [
        {
            "role": "split" if artifact.is_split_member else "base",
            "split_name": _split_name(artifact.artifact, artifact.file_name, artifact.is_split_member),
            "file_name": artifact.file_name,
        }
        for artifact in plan.artifacts
    ]
    entries.sort(key=lambda row: (str(row["role"]), str(row["split_name"]), str(row["file_name"])))
    payload = {
        "package_name": plan.inventory.package_name,
        "version_code": str(plan.inventory.version_code or ""),
        "artifacts": entries,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def find_entry_for_plan(plan: PackagePlan, *, promote_legacy_receipt: bool = True) -> ApkLibraryEntry | None:
    """Return a complete library entry for *plan* if one is already available."""

    planned_hash = planned_split_set_hash_for_plan(plan)
    manifest_path = split_set_dir(
        plan.inventory.package_name,
        str(plan.inventory.version_code or "unknown"),
        planned_hash,
    ) / "package_manifest.json"
    entry = _entry_from_manifest(manifest_path)
    if entry is not None and _entry_matches_plan(entry, plan):
        return entry
    if not promote_legacy_receipt:
        return None
    receipt = _find_legacy_receipt_for_plan(plan)
    if receipt is None:
        return None
    return register_legacy_receipt(receipt, plan=plan)


def artifact_results_for_entry(entry: ApkLibraryEntry, plan: PackagePlan) -> list[ArtifactResult]:
    """Build harvest results for a library hit without pulling bytes."""

    by_key = {
        (_role_key(artifact.role), artifact.split_name, artifact.file_name): artifact
        for artifact in entry.artifacts
    }
    results: list[ArtifactResult] = []
    for planned in plan.artifacts:
        key = (
            "split" if planned.is_split_member else "base",
            _split_name(planned.artifact, planned.file_name, planned.is_split_member),
            planned.file_name,
        )
        hit = by_key.get(key)
        if hit is None:
            return []
        results.append(
            ArtifactResult(
                file_name=planned.file_name,
                apk_id=None,
                dest_path=hit.canonical_path,
                source_path=planned.source_path,
                sha256=hit.sha256,
                status="library_hit",
                skip_reason="apk_library_hit",
                file_size=hit.size_bytes,
                pulled_at=None,
                artifact_label=planned.artifact,
                is_base=not planned.is_split_member,
                observed_source_path=planned.source_path,
                canonical_store_path=hit.canonical_relpath,
            )
        )
    return results


def register_result(
    result: PullResult,
    *,
    serial: str,
    session_stamp: str,
    source: str = "harvest_runner",
) -> ApkLibraryEntry | None:
    """Register a completed pulled result in the APK library."""

    if not result.ok:
        return None
    artifacts: list[dict[str, Any]] = []
    for planned, observed in _pair_planned_observed(result):
        sha256 = str(observed.sha256 or "").strip().lower()
        canonical_rel = str(observed.canonical_store_path or "").strip()
        if len(sha256) != 64 or not canonical_rel:
            return None
        canonical_path = _resolve_repo_path(canonical_rel)
        if not canonical_path.exists():
            return None
        artifacts.append(
            _artifact_payload(
                role="split" if planned.is_split_member else "base",
                split_name=_split_name(planned.artifact, planned.file_name, planned.is_split_member),
                file_name=planned.file_name,
                device_path=planned.source_path,
                sha256=sha256,
                size_bytes=observed.file_size if observed.file_size is not None else _safe_size(canonical_path),
                canonical_relpath=artifact_store.repo_relative_path(canonical_path),
            )
        )
    if not artifacts:
        return None
    return _write_entry(
        plan=result.plan,
        artifacts=artifacts,
        serial=serial,
        session_stamp=session_stamp,
        source=source,
        pull_action="pulled",
    )


def register_legacy_receipt(receipt_path: Path, *, plan: PackagePlan | None = None) -> ApkLibraryEntry | None:
    payload = _read_json(receipt_path)
    if not payload:
        return None
    package = payload.get("package") if isinstance(payload.get("package"), dict) else {}
    execution = payload.get("execution") if isinstance(payload.get("execution"), dict) else {}
    observed = execution.get("observed_artifacts")
    if not isinstance(observed, list):
        return None
    if plan is None:
        plan = _plan_from_legacy_receipt(payload)
    if plan is None:
        return None
    artifacts: list[dict[str, Any]] = []
    for planned in plan.artifacts:
        hit = _matching_observed_artifact(planned, observed)
        if hit is None:
            return None
        canonical_rel = str(hit.get("canonical_store_path") or "").strip()
        sha256 = str(hit.get("sha256") or "").strip().lower()
        canonical_path = _resolve_repo_path(canonical_rel)
        if len(sha256) != 64 or not canonical_rel or not canonical_path.exists():
            return None
        artifacts.append(
            _artifact_payload(
                role="split" if planned.is_split_member else "base",
                split_name=_split_name(planned.artifact, planned.file_name, planned.is_split_member),
                file_name=planned.file_name,
                device_path=planned.source_path,
                sha256=sha256,
                size_bytes=_as_int(hit.get("file_size")) or _safe_size(canonical_path),
                canonical_relpath=artifact_store.repo_relative_path(canonical_path),
            )
        )
    return _write_entry(
        plan=plan,
        artifacts=artifacts,
        serial=str(package.get("device_serial") or ""),
        session_stamp=str(package.get("session_label") or receipt_path.parent.name),
        source="legacy_harvest_receipt",
        pull_action="indexed_legacy_receipt",
    )


def legacy_receipt_seedable(receipt_path: Path) -> tuple[bool, str]:
    """Return whether a receipt has enough canonical data to seed the APK library."""

    payload = _read_json(receipt_path)
    if not payload:
        return False, "unreadable_receipt"
    plan = _plan_from_legacy_receipt(payload)
    if plan is None or not plan.artifacts:
        return False, "missing_planned_artifacts"
    execution = payload.get("execution") if isinstance(payload.get("execution"), dict) else {}
    observed = execution.get("observed_artifacts")
    if not isinstance(observed, list):
        return False, "missing_observed_artifacts"
    for artifact in plan.artifacts:
        hit = _matching_observed_artifact(artifact, observed)
        if hit is None:
            return False, "missing_matching_observed_artifact"
        canonical_rel = str(hit.get("canonical_store_path") or "").strip()
        sha256 = str(hit.get("sha256") or "").strip().lower()
        if len(sha256) != 64:
            return False, "missing_sha256"
        if not canonical_rel:
            return False, "missing_canonical_store_path"
        if not _resolve_repo_path(canonical_rel).exists():
            return False, "missing_canonical_blob"
    return True, "seedable"


def record_observation(
    entry: ApkLibraryEntry,
    *,
    plan: PackagePlan,
    serial: str,
    session_stamp: str,
    pull_action: str,
) -> None:
    artifact_store.ensure_external_path_available(library_root(), description="External APK library")
    _append_harvest_history(
        entry.entry_dir / "harvest_history.csv",
        {
            "observed_at_utc": _now_z(),
            "session_label": session_stamp,
            "device_serial": serial,
            "package_name": plan.inventory.package_name,
            "version_code": str(plan.inventory.version_code or ""),
            "version_name": str(plan.inventory.version_name or ""),
            "planned_split_set_hash": entry.planned_split_set_hash,
            "split_set_hash": entry.split_set_hash,
            "pull_action": pull_action,
            "source": "harvest_runner",
        },
    )
    _touch_version_manifest(plan, entry)


def list_groups(
    *,
    base_dir: Path | None = None,
    device_filter: Sequence[str | None] = None,
    session_filter: Sequence[str | None] = None,
) -> list[ArtifactGroup]:
    """Return grouped APK artifacts with optional device/session filters."""

    resolved_dir = base_dir or artifact_store.harvest_receipts_root()
    device_filter_set = {s.strip() for s in device_filter or () if s} or None
    session_filter_set = {s.strip() for s in session_filter or () if s} or None

    def _predicate(group: ArtifactGroup) -> bool:
        if device_filter_set:
            has_match = False
            for artifact in group.artifacts:
                serial = artifact.metadata.get("device_serial")
                if isinstance(serial, str) and serial in device_filter_set:
                    has_match = True
                    break
            if not has_match:
                return False
        if session_filter_set and group.session_stamp:
            return group.session_stamp in session_filter_set
        if session_filter_set and not group.session_stamp:
            return False
        return True

    return list(group_artifacts(resolved_dir, predicate=_predicate))


def list_sessions(groups: Iterable[ArtifactGroup]) -> list[str]:
    """Return unique session stamps from artifact groups."""
    sessions = []
    seen = set()
    for group in groups:
        stamp = group.session_stamp
        if isinstance(stamp, str) and stamp and stamp not in seen:
            seen.add(stamp)
            sessions.append(stamp)
    return sessions


def _write_entry(
    *,
    plan: PackagePlan,
    artifacts: list[dict[str, Any]],
    serial: str,
    session_stamp: str,
    source: str,
    pull_action: str,
) -> ApkLibraryEntry | None:
    artifact_store.ensure_external_path_available(library_root(), description="External APK library")
    planned_hash = planned_split_set_hash_for_plan(plan)
    content_hash = _content_split_set_hash(artifacts)
    entry_dir = split_set_dir(plan.inventory.package_name, str(plan.inventory.version_code or "unknown"), planned_hash)
    entry_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = entry_dir / "package_manifest.json"
    payload = {
        "schema": "apk_library_entry_v1",
        "generated_at_utc": _now_z(),
        "package_name": plan.inventory.package_name,
        "version_code": str(plan.inventory.version_code or ""),
        "version_name": plan.inventory.version_name,
        "first_seen_at": _existing_first_seen(manifest_path) or _now_z(),
        "last_seen_at": _now_z(),
        "installer": plan.inventory.installer,
        "planned_split_set_hash": planned_hash,
        "split_set_hash": content_hash,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "source_device_serials": sorted({serial for serial in [serial] if serial}),
        "status": "available",
        "source": source,
    }
    atomic_write_text(manifest_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    _write_artifacts_csv(entry_dir / "artifacts.csv", artifacts)
    _append_harvest_history(
        entry_dir / "harvest_history.csv",
        {
            "observed_at_utc": _now_z(),
            "session_label": session_stamp,
            "device_serial": serial,
            "package_name": plan.inventory.package_name,
            "version_code": str(plan.inventory.version_code or ""),
            "version_name": str(plan.inventory.version_name or ""),
            "planned_split_set_hash": planned_hash,
            "split_set_hash": content_hash,
            "pull_action": pull_action,
            "source": source,
        },
    )
    _touch_version_manifest(plan, _entry_from_manifest(manifest_path))
    return _entry_from_manifest(manifest_path)


def _touch_version_manifest(plan: PackagePlan, entry: ApkLibraryEntry | None) -> None:
    if entry is None:
        return
    path = package_version_dir(plan.inventory.package_name, str(plan.inventory.version_code or "unknown")) / "package_manifest.json"
    existing = _read_json(path)
    first_seen = str(existing.get("first_seen_at") or entry.manifest_path.stat().st_mtime_ns)
    payload = {
        "schema": "apk_library_package_version_v1",
        "package_name": plan.inventory.package_name,
        "version_code": str(plan.inventory.version_code or ""),
        "version_name": plan.inventory.version_name,
        "first_seen_at": first_seen,
        "last_seen_at": _now_z(),
        "split_sets": sorted(
            p.name
            for p in (path.parent / "split_sets").iterdir()
            if p.is_dir() and (p / "package_manifest.json").exists()
        )
        if (path.parent / "split_sets").exists()
        else [entry.planned_split_set_hash],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _entry_from_manifest(path: Path) -> ApkLibraryEntry | None:
    payload = _read_json(path)
    if not payload:
        return None
    raw_artifacts = payload.get("artifacts")
    if not isinstance(raw_artifacts, list):
        return None
    artifacts: list[ApkLibraryArtifact] = []
    for item in raw_artifacts:
        if not isinstance(item, dict):
            return None
        canonical_rel = str(item.get("canonical_path") or "").strip()
        sha256 = str(item.get("sha256") or "").strip().lower()
        canonical_path = _resolve_repo_path(canonical_rel)
        if len(sha256) != 64 or not canonical_rel or not canonical_path.exists():
            return None
        artifacts.append(
            ApkLibraryArtifact(
                role=_role_key(str(item.get("role") or "")),
                split_name=str(item.get("split_name") or "").strip(),
                file_name=str(item.get("file_name") or "").strip(),
                device_path=str(item.get("device_path") or "").strip(),
                sha256=sha256,
                size_bytes=_as_int(item.get("size_bytes")),
                canonical_path=canonical_path,
                canonical_relpath=artifact_store.repo_relative_path(canonical_path),
            )
        )
    return ApkLibraryEntry(
        package_name=str(payload.get("package_name") or "").strip(),
        version_code=str(payload.get("version_code") or "").strip(),
        version_name=str(payload.get("version_name") or "").strip() or None,
        planned_split_set_hash=str(payload.get("planned_split_set_hash") or "").strip(),
        split_set_hash=str(payload.get("split_set_hash") or "").strip(),
        entry_dir=path.parent,
        manifest_path=path,
        artifacts=tuple(artifacts),
        source=str(payload.get("source") or "apk_library"),
    )


def _find_legacy_receipt_for_plan(plan: PackagePlan) -> Path | None:
    root = artifact_store.harvest_receipts_root()
    if not root.exists():
        return None
    package_name = plan.inventory.package_name.strip().lower()
    version_code = str(plan.inventory.version_code or "").strip()
    matches: list[Path] = []
    for receipt in root.rglob("*.json"):
        payload = _read_json(receipt)
        package = payload.get("package") if isinstance(payload.get("package"), dict) else {}
        if str(package.get("package_name") or "").strip().lower() != package_name:
            continue
        if str(package.get("version_code") or "").strip() != version_code:
            continue
        if _receipt_matches_plan(payload, plan):
            matches.append(receipt)
    return sorted(matches, key=lambda p: p.stat().st_mtime, reverse=True)[0] if matches else None


def _receipt_matches_plan(payload: Mapping[str, Any], plan: PackagePlan) -> bool:
    execution = payload.get("execution") if isinstance(payload.get("execution"), dict) else {}
    observed = execution.get("observed_artifacts")
    if not isinstance(observed, list):
        return False
    return all(_matching_observed_artifact(artifact, observed) is not None for artifact in plan.artifacts)


def _matching_observed_artifact(planned: Any, observed: list[Any]) -> Mapping[str, Any] | None:
    wanted_role = "split" if planned.is_split_member else "base"
    wanted_split = _split_name(planned.artifact, planned.file_name, planned.is_split_member)
    for item in observed:
        if not isinstance(item, dict):
            continue
        item_role = "base" if bool(item.get("is_base")) else "split"
        item_split = _split_name(str(item.get("split_label") or ""), str(item.get("file_name") or ""), item_role == "split")
        if item_role == wanted_role and item_split == wanted_split:
            return item
    return None


def _plan_from_legacy_receipt(payload: Mapping[str, Any]) -> PackagePlan | None:
    package = payload.get("package") if isinstance(payload.get("package"), dict) else {}
    inventory = payload.get("inventory") if isinstance(payload.get("inventory"), dict) else {}
    planning = payload.get("planning") if isinstance(payload.get("planning"), dict) else {}
    package_name = str(package.get("package_name") or "").strip()
    version_code = str(package.get("version_code") or "").strip()
    if not package_name or not version_code:
        return None
    expected = planning.get("expected_artifacts")
    if not isinstance(expected, list) or not expected:
        return None
    apk_paths = [str(path) for path in inventory.get("apk_paths") or [] if str(path).strip()]
    artifacts: list[ArtifactPlan] = []
    for item in expected:
        if not isinstance(item, dict):
            continue
        file_name = str(item.get("file_name") or "").strip()
        source_path = str(item.get("planned_source_path") or "").strip()
        if not file_name or not source_path:
            continue
        is_base = item.get("is_base") is True
        artifacts.append(
            ArtifactPlan(
                source_path=source_path,
                artifact=_split_name(str(item.get("split_label") or ""), file_name, not is_base),
                file_name=file_name,
                is_split_member=not is_base,
            )
        )
        if source_path not in apk_paths:
            apk_paths.append(source_path)
    if not artifacts:
        return None
    row = InventoryRow(
        raw=dict(inventory),
        package_name=package_name,
        app_label=str(package.get("app_label") or "").strip() or None,
        installer=str(inventory.get("installer") or "").strip() or None,
        category=str(inventory.get("category") or "").strip() or None,
        primary_path=str(inventory.get("primary_path") or "").strip() or (apk_paths[0] if apk_paths else None),
        profile_key=str(inventory.get("profile_key") or "").strip() or None,
        profile=str(inventory.get("profile_name") or "").strip() or None,
        version_name=str(package.get("version_name") or "").strip() or None,
        version_code=version_code,
        apk_paths=apk_paths,
        split_count=_as_int(inventory.get("split_count")) or len(apk_paths),
    )
    return PackagePlan(
        inventory=row,
        artifacts=artifacts,
        total_paths=_as_int(planning.get("total_paths")) or len(apk_paths) or len(artifacts),
        policy_filtered_count=_as_int(planning.get("policy_filtered_count")) or 0,
        policy_filtered_reason=str(planning.get("policy_filtered_reason") or "").strip() or None,
        skip_reason=str(planning.get("preflight_reason") or "").strip() or None,
    )


def _entry_matches_plan(entry: ApkLibraryEntry, plan: PackagePlan) -> bool:
    if entry.package_name.lower() != plan.inventory.package_name.lower():
        return False
    if entry.version_code != str(plan.inventory.version_code or ""):
        return False
    if len(entry.artifacts) != len(plan.artifacts):
        return False
    keys = {(_role_key(a.role), a.split_name, a.file_name) for a in entry.artifacts}
    expected = {
        (
            "split" if artifact.is_split_member else "base",
            _split_name(artifact.artifact, artifact.file_name, artifact.is_split_member),
            artifact.file_name,
        )
        for artifact in plan.artifacts
    }
    return keys == expected


def _pair_planned_observed(result: PullResult) -> list[tuple[Any, ArtifactResult]]:
    by_file = {artifact.file_name: artifact for artifact in result.ok}
    pairs = []
    for planned in result.plan.artifacts:
        observed = by_file.get(planned.file_name)
        if observed is None:
            return []
        pairs.append((planned, observed))
    return pairs


def _artifact_payload(
    *,
    role: str,
    split_name: str,
    file_name: str,
    device_path: str,
    sha256: str,
    size_bytes: int | None,
    canonical_relpath: str,
) -> dict[str, Any]:
    return {
        "role": _role_key(role),
        "split_name": split_name,
        "file_name": file_name,
        "device_path": device_path,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "canonical_path": canonical_relpath,
    }


def _content_split_set_hash(artifacts: list[Mapping[str, Any]]) -> str:
    rows = [
        {
            "role": _role_key(str(item.get("role") or "")),
            "split_name": str(item.get("split_name") or ""),
            "sha256": str(item.get("sha256") or "").lower(),
        }
        for item in artifacts
    ]
    rows.sort(key=lambda row: (row["role"], row["split_name"], row["sha256"]))
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _write_artifacts_csv(path: Path, artifacts: list[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["role", "split_name", "file_name", "device_path", "sha256", "size_bytes", "canonical_path"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in artifacts:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _append_harvest_history(path: Path, row: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "observed_at_utc",
        "session_label",
        "device_serial",
        "package_name",
        "version_code",
        "version_name",
        "planned_split_set_hash",
        "split_set_hash",
        "pull_action",
        "source",
    ]
    exists = path.exists()
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        writer.writerow({key: row.get(key, "") for key in fieldnames})


def _existing_first_seen(path: Path) -> str | None:
    payload = _read_json(path)
    value = payload.get("first_seen_at") if payload else None
    return str(value) if value else None


def _split_name(label: str, file_name: str, is_split: bool) -> str:
    cleaned = str(label or "").strip()
    if cleaned:
        return cleaned
    if not is_split:
        return "base"
    name = str(file_name or "").strip()
    marker = "__split_"
    if marker in name:
        return "split_" + name.split(marker, 1)[1].removesuffix(".apk")
    return name.removesuffix(".apk") or "split"


def _role_key(role: str) -> str:
    return "base" if str(role or "").strip().lower() == "base" else "split"


def _safe_segment(value: str) -> str:
    return artifact_store.safe_filesystem_slug(str(value or "unknown").strip() or "unknown")


def _resolve_repo_path(value: str) -> Path:
    path = Path(str(value or "").strip())
    if path.is_absolute():
        return path
    return (Path.cwd() / path).resolve()


def _safe_size(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def _as_int(value: Any) -> int | None:
    try:
        if value is None or str(value).strip() == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _now_z() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


__all__ = [
    "ApkLibraryArtifact",
    "ApkLibraryEntry",
    "artifact_results_for_entry",
    "find_entry_for_plan",
    "library_root",
    "list_groups",
    "list_sessions",
    "package_version_dir",
    "planned_split_set_hash_for_plan",
    "record_observation",
    "legacy_receipt_seedable",
    "register_legacy_receipt",
    "register_result",
    "split_set_dir",
]
