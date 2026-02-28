"""Identity and hashing helpers for static analysis scans."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import Path

from scytaledroid.DeviceAnalysis.harvest.common import compute_hashes

from ..core.models import RunParameters


def _artifact_identity_label(artifact) -> str:
    path = getattr(artifact, "display_path", None) or getattr(artifact, "path", None)
    if path is not None:
        return f"path={path}"
    return f"artifact_id={id(artifact)}"


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


def _artifact_sha256_with_reason(artifact) -> tuple[str | None, str | None]:
    sha = getattr(artifact, "sha256", None)
    if isinstance(sha, str) and sha.strip():
        return sha.strip(), None
    try:
        hashes = compute_hashes(Path(artifact.path))
        sha = hashes.get("sha256")
        if isinstance(sha, str) and sha.strip():
            return sha.strip(), None
        return None, f"{_artifact_identity_label(artifact)}; missing sha256"
    except Exception as exc:
        reason = f"{exc.__class__.__name__}"
        detail = str(exc).strip()
        if detail:
            reason = f"{reason}:{detail}"
        return None, f"{_artifact_identity_label(artifact)}; hash_error={reason}"


def _split_name_for_artifact_with_reason(artifact) -> tuple[str | None, str | None]:
    meta = getattr(artifact, "metadata", {}) or {}
    if isinstance(meta, Mapping):
        name = meta.get("split_name") or meta.get("split") or meta.get("artifact")
        if isinstance(name, str) and name.strip():
            return name.strip().lower(), None
    try:
        stem = Path(artifact.path).stem
    except Exception:
        stem = None
    if isinstance(stem, str) and stem.strip():
        return stem.strip().lower(), None
    keys = sorted(str(key) for key in meta.keys()) if isinstance(meta, Mapping) else []
    keys_text = ",".join(keys[:6])
    reason = f"{_artifact_identity_label(artifact)}; missing_split_name; meta_keys=[{keys_text}]"
    return None, reason


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

    base_sha, base_reason = _artifact_sha256_with_reason(base)
    if not base_sha:
        reason = base_reason or _artifact_identity_label(base)
        identity["identity_error_reason"] = f"base_sha256_missing:{reason}"
        return identity

    entries = []
    for artifact in _dedupe_artifacts(group.artifacts):
        sha, sha_reason = _artifact_sha256_with_reason(artifact)
        if not sha:
            reason = sha_reason or _artifact_identity_label(artifact)
            identity["identity_error_reason"] = f"artifact_sha256_missing:{reason}"
            return identity
        split_name, split_reason = _split_name_for_artifact_with_reason(artifact)
        if not split_name:
            reason = split_reason or _artifact_identity_label(artifact)
            identity["identity_error_reason"] = f"split_name_missing:{reason}"
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

    # Avoid filesystem mtime as a primary ordering signal; it is easy to disturb (copy, unzip, rsync)
    # and can introduce silent drift in paper-grade workflows. Instead, prefer deterministic keys
    # derived from the on-disk library structure and artifact metadata.
    preferred: dict[tuple[str, str], tuple[object, tuple, int]] = {}
    for index, artifact in enumerate(artifacts):
        try:
            sha = getattr(artifact, "sha256", None)
        except Exception:
            sha = None
        try:
            # Use stable split identifiers over paths so the same artifact set does not get scanned twice
            # due to label/path differences.
            split_name, _ = _split_name_for_artifact_with_reason(artifact)
            if split_name:
                split_label = split_name
            else:
                split_label = getattr(artifact, "artifact_label", None) or getattr(artifact, "display_path", "")
        except Exception:
            split_label = ""
        key = (_normalise_digest(sha, artifact), split_label or "")
        recency = _artifact_recency_key(artifact)
        existing = preferred.get(key)
        if existing is None or recency > existing[1]:
            preferred[key] = (artifact, recency, index)
    ordered = sorted(preferred.values(), key=lambda item: item[2])
    return [item[0] for item in ordered]


def _normalise_digest(sha: str | None, artifact) -> str:
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


def _artifact_recency_key(artifact) -> tuple:
    """Deterministic key used to prefer one artifact when duplicates are present."""

    # Prefer capture day extracted from the on-disk path: data/device_apks/<serial>/<YYYYMMDD>/...
    capture_day = 0
    try:
        path = getattr(artifact, "path", None)
        if path:
            path_obj = Path(path)
            for part in path_obj.parts:
                if len(part) == 8 and part.isdigit():
                    value = int(part)
                    if 20000101 <= value <= 20991231 and value > capture_day:
                        capture_day = value
    except Exception:
        capture_day = 0

    # Next, prefer higher version_code when present.
    version_code = 0
    try:
        meta = getattr(artifact, "metadata", {}) or {}
        raw = meta.get("version_code") if isinstance(meta, Mapping) else None
        if raw is not None:
            version_code = int(raw)
    except Exception:
        version_code = 0

    # Next, prefer explicit session stamps in metadata.
    session_stamp = ""
    try:
        meta = getattr(artifact, "metadata", {}) or {}
        if isinstance(meta, Mapping):
            session_stamp = str(meta.get("session_stamp") or "")
    except Exception:
        session_stamp = ""

    # Stable tie-breakers.
    try:
        path_text = str(Path(getattr(artifact, "path", "")).as_posix())
    except Exception:
        path_text = ""
    try:
        label = str(getattr(artifact, "artifact_label", None) or "")
    except Exception:
        label = ""
    return (
        1 if capture_day else 0,
        capture_day,
        1 if version_code else 0,
        version_code,
        1 if session_stamp else 0,
        session_stamp,
        label,
        path_text,
    )


__all__ = [
    "_artifact_manifest_sha256",
    "_artifact_mtime",
    "_artifact_sha256",
    "_compute_config_hash",
    "_compute_run_identity",
    "_dedupe_artifacts",
    "_normalise_digest",
    "_run_signature_sha256",
    "_split_name_for_artifact_with_reason",
]
