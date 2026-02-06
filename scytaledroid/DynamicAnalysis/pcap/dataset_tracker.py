"""Dataset run tracker for dynamic collection."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean, pstdev, pvariance
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.core.event_logger import RunEventLogger
from scytaledroid.DynamicAnalysis.observers.pcapdroid_capture import MIN_PCAP_BYTES
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
    run_entry["valid_dataset_run"] = _is_valid_run(run_dir, run_entry)
    if not any(r.get("run_id") == manifest.dynamic_run_id for r in app_entry["runs"]):
        app_entry["runs"].append(run_entry)
    app_entry["run_count"] = len(app_entry["runs"])
    app_entry["target_runs"] = cfg.repeats_per_app
    app_entry["valid_runs"] = sum(1 for r in app_entry["runs"] if r.get("valid_dataset_run"))
    app_entry["app_complete"] = app_entry["valid_runs"] >= cfg.repeats_per_app
    app_entry["overlap_stats"] = _compute_overlap_stats(app_entry.get("runs") or [])
    payload["updated_at"] = datetime.now(UTC).isoformat()
    tracker_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    _log(
        event_logger,
        "dataset_tracker_update",
        {"package_name": package, "run_count": app_entry["run_count"]},
    )
    return tracker_path


def load_dataset_tracker() -> dict[str, Any]:
    tracker_path = Path(app_config.DATA_DIR) / "archive" / "dataset_plan.json"
    return _load(tracker_path)


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


def _duration_ok(run_dir: Path) -> bool:
    summary_path = run_dir / "analysis" / "summary.json"
    if not summary_path.exists():
        return False
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    telemetry = (payload.get("telemetry") or {}).get("stats") or {}
    sampling_duration = telemetry.get("sampling_duration_seconds")
    try:
        return float(sampling_duration) >= float(app_config.DYNAMIC_MIN_DURATION_S)
    except Exception:
        return False


def _features_ok(run_dir: Path) -> bool:
    return (run_dir / "analysis/pcap_features.json").exists()


def _is_valid_run(run_dir: Path, entry: dict[str, Any]) -> bool:
    pcap_size = int(entry.get("pcap_size_bytes") or 0)
    if pcap_size < MIN_PCAP_BYTES:
        return False
    report_status = entry.get("report_status")
    if report_status == "skip" or report_status is None:
        return False
    if not _features_ok(run_dir):
        return False
    if not _duration_ok(run_dir):
        return False
    return True


def _compute_overlap_stats(runs: list[dict[str, Any]]) -> dict[str, Any]:
    ratios = []
    dynamic_only = []
    bytes_per_sec = []
    per_source: dict[str, list[float]] = {}
    for entry in runs:
        if not entry.get("valid_dataset_run"):
            continue
        run_id = entry.get("run_id")
        if not run_id:
            continue
        run_dir = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic" / str(run_id)
        overlap_path = run_dir / "analysis" / "static_dynamic_overlap.json"
        features_path = run_dir / "analysis" / "pcap_features.json"
        if not overlap_path.exists():
            continue
        try:
            payload = json.loads(overlap_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        features_payload = None
        if features_path.exists():
            try:
                features_payload = json.loads(features_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                features_payload = None
        ratio = payload.get("overlap_ratio")
        if isinstance(ratio, (int, float)):
            ratios.append(float(ratio))
        dyn_ratio = payload.get("dynamic_only_ratio")
        if isinstance(dyn_ratio, (int, float)):
            dynamic_only.append(float(dyn_ratio))
        if isinstance(features_payload, dict):
            metrics = features_payload.get("metrics")
            if isinstance(metrics, dict):
                byte_rate = metrics.get("data_byte_rate_bps")
                if isinstance(byte_rate, (int, float)):
                    bytes_per_sec.append(float(byte_rate))
        for source, source_payload in (payload.get("overlap_by_source") or {}).items():
            if not isinstance(source_payload, dict):
                continue
            src_ratio = source_payload.get("overlap_ratio")
            if isinstance(src_ratio, (int, float)):
                per_source.setdefault(str(source), []).append(float(src_ratio))
    return {
        "runs": len(ratios),
        "overlap_ratio_mean": _mean_or_none(ratios),
        "overlap_ratio_std": _std_or_none(ratios),
        "overlap_ratio_variance": _variance_or_none(ratios),
        "overlap_ratio_cv": _cv_or_none(ratios),
        "overlap_ratio_max_delta": _max_delta_or_none(ratios),
        "dynamic_only_ratio_mean": _mean_or_none(dynamic_only),
        "dynamic_only_ratio_std": _std_or_none(dynamic_only),
        "dynamic_only_ratio_variance": _variance_or_none(dynamic_only),
        "dynamic_only_ratio_cv": _cv_or_none(dynamic_only),
        "dynamic_only_ratio_max_delta": _max_delta_or_none(dynamic_only),
        "bytes_per_sec_mean": _mean_or_none(bytes_per_sec),
        "bytes_per_sec_std": _std_or_none(bytes_per_sec),
        "bytes_per_sec_variance": _variance_or_none(bytes_per_sec),
        "bytes_per_sec_cv": _cv_or_none(bytes_per_sec),
        "bytes_per_sec_max_delta": _max_delta_or_none(bytes_per_sec),
        "per_source": {
            source: {
                "mean": _mean_or_none(values),
                "std": _std_or_none(values),
                "variance": _variance_or_none(values),
                "cv": _cv_or_none(values),
                "max_delta": _max_delta_or_none(values),
                "runs": len(values),
            }
            for source, values in sorted(per_source.items())
        },
    }


def _mean_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    return float(mean(values))


def _std_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return 0.0
    return float(pstdev(values))


def _variance_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return 0.0
    return float(pvariance(values))


def _cv_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    avg = _mean_or_none(values)
    if avg is None or avg == 0:
        return None
    std = _std_or_none(values)
    if std is None:
        return None
    return float(std) / float(avg)


def _max_delta_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return 0.0
    return float(max(values) - min(values))


def _log(event_logger: RunEventLogger | None, event: str, payload: dict[str, Any]) -> None:
    if event_logger:
        event_logger.log(event, payload)


__all__ = ["DatasetTrackerConfig", "update_dataset_tracker"]
