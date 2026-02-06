"""Dataset run tracker for dynamic collection."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.core.event_logger import RunEventLogger
from scytaledroid.DynamicAnalysis.core.manifest import RunManifest


@dataclass(frozen=True)
class DatasetTrackerConfig:
    repeats_per_app: int = 3


def update_dataset_tracker(
    manifest: RunManifest,
    run_dir: Path,
    *,
    config: DatasetTrackerConfig | None = None,
    event_logger: RunEventLogger | None = None,
) -> Path | None:
    cfg = config or DatasetTrackerConfig()
    tier = None
    if isinstance(manifest.operator, dict):
        tier = manifest.operator.get("tier")
    if tier and str(tier).lower() != "dataset":
        _log(event_logger, "dataset_tracker_skip", {"tier": tier})
        return None
    package = (manifest.target.get("package_name") or "_unknown").strip()
    if not package:
        package = "_unknown"
    tracker_path = Path(app_config.DATA_DIR) / "archive" / "dataset_plan.json"
    tracker_path.parent.mkdir(parents=True, exist_ok=True)
    payload = _load(tracker_path)
    apps = payload.setdefault("apps", {})
    app_entry = apps.setdefault(package, {"runs": []})
    run_entry = {
        "run_id": manifest.dynamic_run_id,
        "scenario": manifest.scenario.get("id"),
        "started_at": manifest.scenario.get("started_at") or manifest.started_at,
        "ended_at": manifest.scenario.get("ended_at") or manifest.ended_at,
        "pcap_size_bytes": _pcap_size(manifest),
        "report_status": _pcap_report_status(run_dir),
    }
    if not any(r.get("run_id") == manifest.dynamic_run_id for r in app_entry["runs"]):
        app_entry["runs"].append(run_entry)
    app_entry["run_count"] = len(app_entry["runs"])
    app_entry["target_runs"] = cfg.repeats_per_app
    payload["updated_at"] = datetime.now(UTC).isoformat()
    tracker_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    _log(
        event_logger,
        "dataset_tracker_update",
        {"package_name": package, "run_count": app_entry["run_count"]},
    )
    return tracker_path


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"apps": {}}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"apps": {}}


def _pcap_size(manifest: RunManifest) -> int | None:
    for artifact in manifest.artifacts:
        if artifact.type == "pcapdroid_capture":
            return int(artifact.size_bytes or 0)
    return None


def _pcap_report_status(run_dir: Path) -> str | None:
    report_path = run_dir / "analysis/pcap_report.json"
    if not report_path.exists():
        return None
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload.get("report_status")


def _log(event_logger: RunEventLogger | None, event: str, payload: dict[str, Any]) -> None:
    if event_logger:
        event_logger.log(event, payload)


__all__ = ["DatasetTrackerConfig", "update_dataset_tracker"]
