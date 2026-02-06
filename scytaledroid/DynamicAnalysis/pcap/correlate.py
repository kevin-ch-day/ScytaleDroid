"""Static ↔ dynamic overlap reporting."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.core.event_logger import RunEventLogger
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest


@dataclass(frozen=True)
class OverlapConfig:
    max_samples: int = 20


def write_static_dynamic_overlap(
    manifest: RunManifest,
    run_dir: Path,
    *,
    config: OverlapConfig | None = None,
    event_logger: RunEventLogger | None = None,
) -> ArtifactRecord | None:
    cfg = config or OverlapConfig()
    report_path = run_dir / "analysis/pcap_report.json"
    if not report_path.exists():
        _log(event_logger, "static_dynamic_overlap_skip", {"reason": "pcap_report_missing"})
        return None
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _log(event_logger, "static_dynamic_overlap_skip", {"reason": "pcap_report_invalid"})
        return None
    static_domains = _static_domains(manifest)
    dynamic_domains = _dynamic_domains(report)
    overlap = sorted(static_domains.intersection(dynamic_domains))
    dynamic_only = sorted(dynamic_domains.difference(static_domains))
    static_only = sorted(static_domains.difference(dynamic_domains))
    overlap_ratio = None
    if static_domains:
        overlap_ratio = len(overlap) / float(len(static_domains))
    payload = {
        "static_domains_count": len(static_domains),
        "dynamic_domains_count": len(dynamic_domains),
        "overlap_count": len(overlap),
        "overlap_ratio": overlap_ratio,
        "overlap_sample": overlap[: cfg.max_samples],
        "dynamic_only_sample": dynamic_only[: cfg.max_samples],
        "static_only_sample": static_only[: cfg.max_samples],
    }
    output_path = run_dir / "analysis/static_dynamic_overlap.json"
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return ArtifactRecord(
        relative_path=str(output_path.relative_to(run_dir)),
        type="static_dynamic_overlap",
        sha256=_sha256(output_path),
        size_bytes=output_path.stat().st_size,
        produced_by="static_dynamic_overlap",
        origin="host",
        pull_status="n/a",
    )


def _static_domains(manifest: RunManifest) -> set[str]:
    static_plan = manifest.target.get("static_plan_summary") if isinstance(manifest.target, dict) else None
    if not isinstance(static_plan, dict):
        return set()
    sample = static_plan.get("network_targets_sample") or []
    return {str(item).strip() for item in sample if str(item).strip()}


def _dynamic_domains(report: dict[str, Any]) -> set[str]:
    domains = set()
    for item in report.get("top_dns") or []:
        value = item.get("value")
        if value:
            domains.add(str(value).strip())
    for item in report.get("top_sni") or []:
        value = item.get("value")
        if value:
            domains.add(str(value).strip())
    return {item for item in domains if item}


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _log(event_logger: RunEventLogger | None, event: str, payload: dict[str, Any]) -> None:
    if event_logger:
        event_logger.log(event, payload)


__all__ = ["OverlapConfig", "write_static_dynamic_overlap"]
