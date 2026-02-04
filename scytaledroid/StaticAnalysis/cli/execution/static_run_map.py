"""Run map helpers for static analysis sessions."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from scytaledroid.Config import app_config

REQUIRED_FIELDS = (
    "base_apk_sha256",
    "artifact_set_hash",
    "run_signature",
    "run_signature_version",
    "pipeline_version",
)


def _run_map_path(session_stamp: str) -> Path:
    return Path(app_config.DATA_DIR) / "sessions" / session_stamp / "run_map.json"


def _run_map_lock_path(session_stamp: str) -> Path:
    return Path(app_config.DATA_DIR) / "sessions" / session_stamp / ".run_map.lock"


def load_run_map(session_stamp: str | None) -> dict | None:
    if not session_stamp:
        return None
    lock_path = _run_map_lock_path(session_stamp)
    if lock_path.exists():
        raise RuntimeError(
            f"run_map.json is locked for session {session_stamp}; another process may be writing it."
        )
    path = _run_map_path(session_stamp)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(
            f"run_map.json is invalid or corrupt at {path}: {exc}"
        ) from exc
    return payload if isinstance(payload, dict) else None


def validate_run_map(run_map: dict, session_stamp: str) -> None:
    if not isinstance(run_map, dict):
        raise RuntimeError("run_map.json schema invalid: not an object.")
    if run_map.get("session_stamp") and run_map.get("session_stamp") != session_stamp:
        raise RuntimeError(
            f"run_map.json session mismatch: expected {session_stamp}, got {run_map.get('session_stamp')}"
        )
    apps = run_map.get("apps")
    if not isinstance(apps, list):
        raise RuntimeError("run_map.json schema invalid: missing apps list.")
    seen: set[str] = set()
    duplicates: set[str] = set()
    missing: list[str] = []
    for entry in apps:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package")
        static_run_id = entry.get("static_run_id")
        identity_valid = entry.get("identity_valid")
        if identity_valid is False:
            missing.append(str(package) if package else "<missing>")
            continue
        required_fields = [entry.get(field) for field in REQUIRED_FIELDS]
        if not package or static_run_id is None or any(val in (None, "") for val in required_fields):
            missing.append(str(package) if package else "<missing>")
            continue
        if package in seen:
            duplicates.add(str(package))
        else:
            seen.add(str(package))
    if duplicates:
        raise RuntimeError(
            "run_map.json contains duplicate package entries: "
            f"{', '.join(sorted(duplicates))}. "
            "Disambiguate the scope or rerun with a single package per session."
        )
    if missing:
        raise RuntimeError(
            "run_map.json missing required fields for one or more apps: "
            f"{', '.join(sorted(set(missing)))}."
        )


def resolve_run_map_entry(
    app_result,
    run_map: Mapping[str, object],
) -> tuple[Mapping[str, object] | None, str | None]:
    apps = run_map.get("apps") if isinstance(run_map, Mapping) else None
    if not isinstance(apps, Sequence) or isinstance(apps, (str, bytes)):
        return None, "run_map missing apps list"
    for entry in apps:
        if not isinstance(entry, Mapping):
            continue
        if entry.get("package") != app_result.package_name:
            continue
        static_run_id = entry.get("static_run_id")
        pipeline_version = entry.get("pipeline_version")
        if static_run_id is None or pipeline_version in (None, ""):
            return None, "run_map missing static_run_id/pipeline_version"
        return entry, None
    return None, "package missing from run_map"


def extract_static_run_ids(run_map: Mapping[str, object] | None) -> list[int]:
    if not run_map or not isinstance(run_map, Mapping):
        return []
    by_package = run_map.get("by_package")
    if isinstance(by_package, Mapping):
        ids: list[int] = []
        for entry in by_package.values():
            if not isinstance(entry, Mapping):
                continue
            srid = entry.get("static_run_id")
            if srid is None:
                continue
            try:
                ids.append(int(srid))
            except (TypeError, ValueError):
                continue
        if ids:
            return ids
    apps = run_map.get("apps")
    if not isinstance(apps, list):
        return []
    ids: list[int] = []
    for entry in apps:
        if not isinstance(entry, dict):
            continue
        srid = entry.get("static_run_id")
        if srid is None:
            continue
        try:
            ids.append(int(srid))
        except (TypeError, ValueError):
            continue
    return ids


__all__ = [
    "REQUIRED_FIELDS",
    "extract_static_run_ids",
    "load_run_map",
    "resolve_run_map_entry",
    "validate_run_map",
]