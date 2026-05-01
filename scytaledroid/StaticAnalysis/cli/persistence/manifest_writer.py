"""Run manifest writer for static analysis runs."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils import diagnostics as db_diagnostics
from scytaledroid.Database.db_utils.artifact_registry import record_artifacts
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.version_utils import get_git_commit


def _json_safe(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, Mapping):
        return {key: _json_safe(val) for key, val in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_safe(item) for item in value]
    return value


def write_static_run_manifest(
    static_run_id: int,
    *,
    grade: str,
    grade_reasons: Sequence[str] | None = None,
) -> bool:
    try:
        row = core_q.run_sql(
            """
            SELECT
              sar.id,
              sar.run_started_utc,
              sar.ended_at_utc,
              sar.profile_key,
              sar.scenario_id,
              sar.sha256,
              sar.base_apk_sha256,
              av.version_code,
              av.version_name,
              a.package_name,
              a.display_name,
              sar.tool_semver,
              sar.tool_git_commit,
              sar.schema_version
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE sar.id=%s
            """,
            (static_run_id,),
            fetch="one",
        )
    except Exception as exc:
        log.warning(f"Failed to read static run for manifest: {exc}", category="static_analysis")
        return False
    if not row:
        return False
    (
        run_id,
        run_started_utc,
        ended_at_utc,
        profile_key,
        scenario_id,
        sha256,
        base_apk_sha256,
        version_code,
        version_name,
        package_name,
        display_name,
        tool_semver,
        tool_git_commit,
        schema_version,
    ) = row

    reasons = list(grade_reasons or [])

    manifest = {
        "run_manifest_version": 1,
        "run_id": int(run_id) if run_id is not None else None,
        "run_type": "static",
        "package_name": package_name,
        "display_name": display_name,
        "profile_key": profile_key,
        "scenario_id": scenario_id,
        "version_code": version_code,
        "version_name": version_name,
        "apk_sha256": sha256,
        "base_apk_sha256": base_apk_sha256,
        "start_utc": run_started_utc,
        "end_utc": ended_at_utc,
        "tool_semver": tool_semver or app_config.APP_VERSION,
        "tool_git_commit": tool_git_commit or get_git_commit(),
        "schema_version": schema_version or (db_diagnostics.get_schema_version() or "<unknown>"),
        "run_grade": grade,
        "grade_reasons": reasons,
        "artifacts": [],
    }

    run_root = Path("evidence") / "static_runs" / str(static_run_id)
    run_root.mkdir(parents=True, exist_ok=True)
    manifest_path = run_root / "run_manifest.json"
    manifest["artifacts"].append(
        {
            "path": str(manifest_path),
            "type": "static_run_manifest",
            "sha256": None,
            "size_bytes": None,
            "created_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "status_reason": "self_reference_unhashed",
            "origin": "host",
            "pull_status": "n/a",
        }
    )
    try:
        registry_rows = core_q.run_sql(
            """
            SELECT artifact_type, host_path, device_path, origin, pull_status,
                   sha256, size_bytes, created_at_utc, pulled_at_utc
            FROM artifact_registry
            WHERE run_id=%s AND run_type='static'
            """,
            (str(static_run_id),),
            fetch="all",
        )
    except Exception:
        registry_rows = []
    seen_keys: set[tuple[str, str]] = set()
    for artifact in manifest.get("artifacts", []):
        key = (str(artifact.get("type")), str(artifact.get("path")))
        seen_keys.add(key)
    for row in registry_rows or []:
        if not row:
            continue
        artifact_type, host_path, device_path, origin, pull_status, sha256, size_bytes, created_at_utc, pulled_at_utc = row
        path_value = host_path or device_path
        if not path_value:
            continue
        key = (str(artifact_type), str(path_value))
        if key in seen_keys:
            continue
        manifest["artifacts"].append(
            {
                "path": str(path_value),
                "type": str(artifact_type),
                "sha256": sha256,
                "size_bytes": size_bytes,
                "created_at_utc": created_at_utc,
                "origin": origin,
                "device_path": device_path,
                "pull_status": pull_status,
                "pulled_at_utc": pulled_at_utc,
            }
        )
        seen_keys.add(key)
    manifest_path.write_text(json.dumps(_json_safe(manifest), indent=2, sort_keys=True))
    record_artifacts(
        run_id=str(static_run_id),
        run_type="static",
        artifacts=[
            {
                "path": str(manifest_path),
                "type": "static_run_manifest",
                "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                "size_bytes": manifest_path.stat().st_size,
                "created_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
        ],
        origin="host",
        pull_status="n/a",
    )
    return True


def refresh_static_run_manifest(
    static_run_id: int,
    *,
    grade: str,
    grade_reasons: Sequence[str] | None = None,
) -> bool:
    return write_static_run_manifest(
        static_run_id,
        grade=grade,
        grade_reasons=grade_reasons,
    )


__all__ = ["write_static_run_manifest", "refresh_static_run_manifest"]
