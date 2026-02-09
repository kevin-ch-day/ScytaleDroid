"""Recompute PCAP-derived analysis artifacts for existing evidence packs (pre-freeze).

This is a local maintenance utility:
- It re-runs `pcap_report.json` and `pcap_features.json` generation from the canonical PCAP.
- It updates `run_manifest.json` outputs for those artifacts (best-effort).

Paper #2 contract reminder:
- Evidence packs are authoritative.
- Do this only before dataset freeze. After freeze, recomputation must be versioned.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest
from scytaledroid.DynamicAnalysis.pcap.features import write_pcap_features
from scytaledroid.DynamicAnalysis.pcap.report import write_pcap_report


@dataclass(frozen=True)
class RecomputeResult:
    scanned: int
    updated: int
    skipped: int
    errors: int


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + f".tmp.{int(datetime.now(UTC).timestamp())}")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _build_manifest_for_tools(run_dir: Path, payload: dict[str, Any]) -> RunManifest | None:
    run_manifest_version = payload.get("run_manifest_version")
    dynamic_run_id = payload.get("dynamic_run_id") or run_dir.name
    created_at = payload.get("created_at") or datetime.now(UTC).isoformat()
    if not isinstance(run_manifest_version, int):
        return None
    if not isinstance(dynamic_run_id, str) or not dynamic_run_id.strip():
        return None
    if not isinstance(created_at, str) or not created_at.strip():
        return None

    artifacts: list[ArtifactRecord] = []
    for a in payload.get("artifacts") or []:
        if not isinstance(a, dict):
            continue
        rel = a.get("relative_path")
        typ = a.get("type")
        sha = a.get("sha256")
        prod = a.get("produced_by")
        if not (isinstance(rel, str) and isinstance(typ, str) and isinstance(sha, str) and isinstance(prod, str)):
            continue
        artifacts.append(
            ArtifactRecord(
                relative_path=rel,
                type=typ,
                sha256=sha,
                produced_by=prod,
                size_bytes=a.get("size_bytes") if isinstance(a.get("size_bytes"), int) else None,
                origin=a.get("origin") if isinstance(a.get("origin"), str) else None,
                device_path=a.get("device_path") if isinstance(a.get("device_path"), str) else None,
                pull_status=a.get("pull_status") if isinstance(a.get("pull_status"), str) else None,
            )
        )

    return RunManifest(
        run_manifest_version=run_manifest_version,
        dynamic_run_id=dynamic_run_id,
        created_at=created_at,
        batch_id=payload.get("batch_id"),
        started_at=payload.get("started_at"),
        ended_at=payload.get("ended_at"),
        status=str(payload.get("status") or "pending"),
        dataset=payload.get("dataset") if isinstance(payload.get("dataset"), dict) else {},
        qa=payload.get("qa") if isinstance(payload.get("qa"), dict) else {},
        target=payload.get("target") if isinstance(payload.get("target"), dict) else {},
        environment=payload.get("environment") if isinstance(payload.get("environment"), dict) else {},
        scenario=payload.get("scenario") if isinstance(payload.get("scenario"), dict) else {},
        observers=[],
        artifacts=artifacts,
        outputs=[],
        operator=payload.get("operator") if isinstance(payload.get("operator"), dict) else {},
        notes=payload.get("notes") if isinstance(payload.get("notes"), list) else [],
    )


def _upsert_output(payload: dict[str, Any], record: ArtifactRecord) -> None:
    outputs = payload.get("outputs")
    if not isinstance(outputs, list):
        outputs = []
    # Replace by type if present, else append.
    replaced = False
    for idx, row in enumerate(outputs):
        if not isinstance(row, dict):
            continue
        if row.get("type") != record.type:
            continue
        outputs[idx] = {
            "relative_path": record.relative_path,
            "type": record.type,
            "sha256": record.sha256,
            "size_bytes": record.size_bytes,
            "produced_by": record.produced_by,
            "origin": record.origin,
            "device_path": record.device_path,
            "pull_status": record.pull_status,
        }
        replaced = True
        break
    if not replaced:
        outputs.append(
            {
                "relative_path": record.relative_path,
                "type": record.type,
                "sha256": record.sha256,
                "size_bytes": record.size_bytes,
                "produced_by": record.produced_by,
                "origin": record.origin,
                "device_path": record.device_path,
                "pull_status": record.pull_status,
            }
        )
    payload["outputs"] = outputs


def recompute_pcap_artifacts(output_root: Path, *, dry_run: bool = False) -> RecomputeResult:
    scanned = updated = skipped = errors = 0
    if not output_root.exists():
        return RecomputeResult(scanned=0, updated=0, skipped=0, errors=0)

    for run_dir in sorted([p for p in output_root.iterdir() if p.is_dir()]):
        mf_path = run_dir / "run_manifest.json"
        if not mf_path.exists():
            continue
        scanned += 1
        payload = _read_json(mf_path)
        if not payload:
            errors += 1
            continue
        manifest = _build_manifest_for_tools(run_dir, payload)
        if manifest is None:
            skipped += 1
            continue

        # Only recompute if we have a pcapdroid_capture artifact and the file exists.
        pcap_rel = None
        for a in payload.get("artifacts") or []:
            if isinstance(a, dict) and a.get("type") == "pcapdroid_capture":
                rel = a.get("relative_path")
                if isinstance(rel, str) and rel:
                    pcap_rel = rel
                    break
        if not pcap_rel or not (run_dir / pcap_rel).exists():
            skipped += 1
            continue

        if dry_run:
            updated += 1
            continue

        try:
            rep_rec = write_pcap_report(manifest, run_dir)
            feat_rec = write_pcap_features(manifest, run_dir)
        except Exception:
            errors += 1
            continue

        if rep_rec:
            _upsert_output(payload, rep_rec)
        if feat_rec:
            _upsert_output(payload, feat_rec)
        _atomic_write_json(mf_path, payload)
        updated += 1

    return RecomputeResult(scanned=scanned, updated=updated, skipped=skipped, errors=errors)


__all__ = ["RecomputeResult", "recompute_pcap_artifacts"]

