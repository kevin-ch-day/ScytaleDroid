"""Identity and hashing helpers for static analysis scans."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Mapping, Optional, Sequence

from scytaledroid.DeviceAnalysis.harvest.common import compute_hashes

from ..core.models import RunParameters


def _artifact_sha256(artifact) -> str | None:
    sha = getattr(artifact, "sha256", None)
    if isinstance(sha, str) and sha.strip():
        return sha.strip()
    try:
        hashes = compute_hashes(Path(artifact.path))
        sha = hashes.get("sha256")
        return sha.strip() if isinstance(sha, str) and sha.strip() else None
    except Exception:
        return None


def _split_name_for_artifact(artifact) -> str | None:
    meta = getattr(artifact, "metadata", {}) or {}
    if isinstance(meta, Mapping):
        name = meta.get("split_name") or meta.get("split") or meta.get("artifact")
        if isinstance(name, str) and name.strip():
            return name.strip().lower()
    try:
        stem = Path(artifact.path).stem
    except Exception:
        stem = None
    if isinstance(stem, str) and stem.strip():
        return stem.strip().lower()
    return None


def _compute_run_identity(group) -> dict:
    base = getattr(group, "base_artifact", None)
    identity = {
        "base_apk_sha256": None,
        "artifact_set_hash": None,
        "run_signature_version": "v1",
        "identity_valid": False,
        "identity_error_reason": None,
    }
    if base is None:
        identity["identity_error_reason"] = "missing_base_artifact"
        return identity

    base_sha = _artifact_sha256(base)
    if not base_sha:
        identity["identity_error_reason"] = "base_sha256_missing"
        return identity

    entries = []
    for artifact in _dedupe_artifacts(group.artifacts):
        sha = _artifact_sha256(artifact)
        if not sha:
            identity["identity_error_reason"] = "artifact_sha256_missing"
            return identity
        split_name = _split_name_for_artifact(artifact)
        if not split_name:
            identity["identity_error_reason"] = "split_name_missing"
            return identity
        is_base = artifact == base or not getattr(artifact, "is_split_member", True)
        entries.append({"split_name": split_name, "sha256": sha, "is_base": is_base})

    ordered = [e for e in entries if e["is_base"]]
    ordered.extend(sorted((e for e in entries if not e["is_base"]), key=lambda item: item["split_name"]))
    split_hashes = [e["sha256"] for e in ordered]
    artifact_set_hash = sha256(json.dumps(split_hashes).encode("utf-8")).hexdigest()

    identity["base_apk_sha256"] = base_sha
    identity["artifact_set_hash"] = artifact_set_hash
    identity["identity_valid"] = True
    return identity


def _compute_config_hash(params: RunParameters) -> str:
    payload = {
        "profile": params.profile,
        "profile_label": params.profile_label,
        "scope": params.scope,
        "selected_tests": list(params.selected_tests),
        "strings_mode": params.strings_mode,
        "string_min_entropy": params.string_min_entropy,
        "string_max_samples": params.string_max_samples,
        "string_cleartext_only": params.string_cleartext_only,
        "string_include_https_risk": params.string_include_https_risk,
        "secrets_entropy": params.secrets_entropy,
        "secrets_hits_per_bucket": params.secrets_hits_per_bucket,
        "secrets_scope": params.secrets_scope_canonical,
        "workers": params.workers,
        "reuse_cache": params.reuse_cache,
        "log_level": params.log_level,
        "trace_detectors": list(params.trace_detectors),
        "permission_snapshot_refresh": params.permission_snapshot_refresh,
    }
    return sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _run_signature_sha256(
    base_apk_sha256: str | None,
    artifact_set_hash: str | None,
    *,
    config_hash: str,
    profile: str,
    pipeline_version: str | None,
    run_signature_version: str,
) -> str:
    payload = {
        "base_apk_sha256": base_apk_sha256 or "unknown",
        "artifact_set_hash": artifact_set_hash or "unknown",
        "config_hash": config_hash,
        "profile": profile,
        "pipeline_version": pipeline_version or "",
        "run_signature_version": run_signature_version,
    }
    return sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _artifact_manifest_sha256(group) -> str | None:
    entries = []
    for artifact in _dedupe_artifacts(group.artifacts):
        sha = _artifact_sha256(artifact)
        meta = getattr(artifact, "metadata", {}) or {}
        label = None
        if isinstance(meta, Mapping):
            label = meta.get("split_name") or meta.get("split") or meta.get("artifact")
        label = str(label or artifact.path.name)
        entries.append({"split": label, "sha256": sha or "unknown"})
    if not entries:
        return None
    payload = {
        "package": group.package_name,
        "version": getattr(group, "version_display", None),
        "artifacts": sorted(entries, key=lambda item: item["split"]),
    }
    return sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def _dedupe_artifacts(artifacts: Sequence) -> list:
    """Return artifacts de-duplicated by digest + split label, preferring newest."""

    preferred: dict[tuple[str, str], tuple[object, float, int]] = {}
    for index, artifact in enumerate(artifacts):
        try:
            sha = getattr(artifact, "sha256", None)
        except Exception:
            sha = None
        try:
            split_label = getattr(artifact, "artifact_label", None) or getattr(artifact, "display_path", "")
        except Exception:
            split_label = ""
        key = (_normalise_digest(sha, artifact), split_label or "")
        mtime = _artifact_mtime(artifact)
        existing = preferred.get(key)
        if existing is None or mtime > existing[1]:
            preferred[key] = (artifact, mtime, index)
    ordered = sorted(preferred.values(), key=lambda item: item[2])
    return [item[0] for item in ordered]


def _normalise_digest(sha: Optional[str], artifact) -> str:
    if isinstance(sha, str) and sha.strip():
        return sha.strip().lower()
    alt = None
    try:
        alt = getattr(artifact, "apk_id", None)
    except Exception:
        alt = None
    if isinstance(alt, str) and alt.strip():
        return f"apk:{alt.strip().lower()}"
    try:
        path = getattr(artifact, "path", None)
        if path:
            return f"path:{Path(path).resolve()}"
    except Exception:
        pass
    return f"uid:{id(artifact)}"


def _artifact_mtime(artifact) -> float:
    try:
        path = getattr(artifact, "path", None)
        if path and Path(path).exists():
            return float(Path(path).stat().st_mtime)
    except Exception:
        return 0.0
    return 0.0


__all__ = [
    "_artifact_manifest_sha256",
    "_artifact_mtime",
    "_artifact_sha256",
    "_compute_config_hash",
    "_compute_run_identity",
    "_dedupe_artifacts",
    "_normalise_digest",
    "_run_signature_sha256",
    "_split_name_for_artifact",
]
