"""Artifact persistence helpers for static analysis output."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import status_messages

from ..views.view_renderers import write_baseline_json


def write_baseline_json_artifact(
    payload: Mapping[str, object],
    *,
    package_name: str,
    profile: str,
    scope: str,
) -> Path | None:
    try:
        return write_baseline_json(
            payload,
            package=package_name,
            profile=profile,
            scope=scope,
        )
    except Exception as exc:
        warning = f"Failed to write baseline JSON for {package_name}: {exc}"
        print(status_messages.status(warning, level="warn"))
        return None


def write_manifest_evidence(
    base_report,
    *,
    package_name: str,
    static_run_id: int,
    generated_at_utc: str,
) -> Path | None:
    try:
        metadata_map = base_report.metadata if isinstance(base_report.metadata, Mapping) else {}
        repro_bundle = metadata_map.get("repro_bundle") if isinstance(metadata_map, Mapping) else None
        manifest_evidence = (
            repro_bundle.get("manifest_evidence")
            if isinstance(repro_bundle, Mapping)
            else None
        )
        components = (
            manifest_evidence.get("components")
            if isinstance(manifest_evidence, Mapping)
            else manifest_evidence
        )
        if isinstance(components, list):
            evidence_dir = Path("evidence") / "static_runs" / str(static_run_id)
            evidence_dir.mkdir(parents=True, exist_ok=True)
            manifest_evidence_path = evidence_dir / "manifest_evidence.json"
            manifest_payload = {
                "schema": "manifest_evidence_v1",
                "generated_at_utc": generated_at_utc,
                "package_name": package_name,
                "components": components,
            }
            manifest_evidence_path.write_text(
                json.dumps(manifest_payload, indent=2, sort_keys=True, default=str)
            )
            return manifest_evidence_path
    except Exception:
        return None
    return None


def build_artifact_registry_entries(
    *,
    saved_path: Path | None,
    dynamic_plan_path: Path | None,
    manifest_evidence_path: Path | None,
    report_path: Path | None,
    created_at_utc: str,
) -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = []
    for path, artifact_type in (
        (saved_path, "static_baseline_json"),
        (dynamic_plan_path, "static_dynamic_plan_json"),
    ):
        if not path:
            continue
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            artifacts.append(
                {
                    "path": str(path),
                    "type": artifact_type,
                    "sha256": digest,
                    "size_bytes": path.stat().st_size,
                    "created_at_utc": created_at_utc,
                    "origin": "host",
                    "pull_status": "n/a",
                }
            )
        except Exception:
            continue
    if manifest_evidence_path and manifest_evidence_path.exists():
        try:
            digest = hashlib.sha256(manifest_evidence_path.read_bytes()).hexdigest()
            artifacts.append(
                {
                    "path": str(manifest_evidence_path),
                    "type": "manifest_evidence",
                    "sha256": digest,
                    "size_bytes": manifest_evidence_path.stat().st_size,
                    "created_at_utc": created_at_utc,
                    "origin": "host",
                    "pull_status": "n/a",
                }
            )
        except Exception:
            pass
    if report_path and report_path.exists():
        try:
            digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
            artifacts.append(
                {
                    "path": str(report_path),
                    "type": "static_report",
                    "sha256": digest,
                    "size_bytes": report_path.stat().st_size,
                    "created_at_utc": created_at_utc,
                    "origin": "host",
                    "pull_status": "n/a",
                }
            )
        except Exception:
            pass
    return artifacts


def update_static_aliases(
    *,
    saved_path: Path | None,
    dynamic_plan_path: Path | None,
    alias_base: str,
    canonical_action: str | None,
    prior_canonical_id: int | None,
    static_run_id: int | None,
) -> list[str]:
    notes: list[str] = []
    try:
        if saved_path:
            alias = saved_path.parent / f"{alias_base}_baseline.json"
            alias.write_bytes(saved_path.read_bytes())
            latest_alias = saved_path.parent / "latest_baseline.json"
            latest_alias.write_bytes(saved_path.read_bytes())
        if dynamic_plan_path:
            alias = dynamic_plan_path.parent / f"{alias_base}_plan.json"
            alias.write_bytes(dynamic_plan_path.read_bytes())
            latest_alias = dynamic_plan_path.parent / "latest_plan.json"
            latest_alias.write_bytes(dynamic_plan_path.read_bytes())
        if canonical_action == "replace":
            if prior_canonical_id and static_run_id:
                notes.append(
                    f"Canonical updated: static_run_id={prior_canonical_id} → {static_run_id}"
                )
        notes.append("Daily aliases updated (baseline/plan).")
    except Exception:
        return notes
    return notes


__all__ = [
    "build_artifact_registry_entries",
    "update_static_aliases",
    "write_baseline_json_artifact",
    "write_manifest_evidence",
]
