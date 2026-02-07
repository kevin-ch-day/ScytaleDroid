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
    baseline_profile: str = "baseline_idle"
    interactive_profile: str = "interactive_use"
    # Dataset validity guardrail: catch cases where netstats indicates substantial
    # traffic but the PCAP spans only a few seconds (misconfiguration or capture gap).
    large_netstats_bytes_threshold: int = 5 * 1024 * 1024
    min_pcap_span_seconds_if_large_netstats: float = 30.0


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
    operator = manifest.operator if isinstance(manifest.operator, dict) else {}
    target = manifest.target if isinstance(manifest.target, dict) else {}
    interaction_level = operator.get("interaction_level")
    if interaction_level == "idle":
        interaction_level = "minimal"
    run_entry = {
        "run_id": manifest.dynamic_run_id,
        "scenario": manifest.scenario.get("id"),
        "started_at": manifest.scenario.get("started_at") or manifest.started_at,
        "ended_at": manifest.scenario.get("ended_at") or manifest.ended_at,
        "static_run_id": target.get("static_run_id"),
        "pcap_size_bytes": _pcap_size(manifest),
        "report_status": _pcap_report_status(run_dir),
        "run_profile": operator.get("run_profile"),
        "run_sequence": operator.get("run_sequence"),
        "interaction_level": interaction_level,
    }
    run_entry.update(_netstats_summary(run_dir))
    run_entry.update(_pcap_capture_stats(run_dir))
    valid, reasons = _is_valid_run(run_dir, run_entry, cfg)
    run_entry["valid_dataset_run"] = valid
    run_entry["validity_reasons"] = reasons

    # Idempotent: update existing entries so older runs can be re-evaluated when
    # QA rules evolve (e.g., PCAP span vs netstats guardrail).
    existing = next((r for r in app_entry["runs"] if r.get("run_id") == manifest.dynamic_run_id), None)
    if existing is None:
        app_entry["runs"].append(run_entry)
    else:
        existing.update(run_entry)
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
        {
            "package_name": package,
            "run_count": app_entry["run_count"],
            "valid_runs": app_entry["valid_runs"],
            "run_profile": operator.get("run_profile"),
            "run_sequence": operator.get("run_sequence"),
        },
    )
    return tracker_path


def load_dataset_tracker() -> dict[str, Any]:
    tracker_path = Path(app_config.DATA_DIR) / "archive" / "dataset_plan.json"
    return _load(tracker_path)


def peek_next_run_protocol(
    package_name: str,
    *,
    tier: str | None,
    config: DatasetTrackerConfig | None = None,
) -> dict[str, Any] | None:
    """Determine the next dataset run protocol for a package.

    This is operator protocol metadata (baseline vs interactive), not a behavioral
    feature. The intent is to keep Run #1 per app as a low-interaction baseline,
    and to make that intent explicit in run artifacts for later ML analysis.
    """
    if not tier or str(tier).lower() != "dataset":
        return None
    cfg = config or DatasetTrackerConfig()
    package = (package_name or "_unknown").strip() or "_unknown"
    tracker = load_dataset_tracker()
    apps = tracker.get("apps") if isinstance(tracker, dict) else {}
    entry = apps.get(package) if isinstance(apps, dict) else None
    runs = entry.get("runs") if isinstance(entry, dict) else []
    run_sequence = (len(runs) + 1) if isinstance(runs, list) else 1

    valid_runs = entry.get("valid_runs") if isinstance(entry, dict) else None
    if valid_runs is None and isinstance(runs, list):
        valid_runs = sum(1 for r in runs if isinstance(r, dict) and r.get("valid_dataset_run"))
    try:
        valid_runs_int = int(valid_runs or 0)
    except Exception:
        valid_runs_int = 0

    run_profile = cfg.baseline_profile if valid_runs_int <= 0 else cfg.interactive_profile
    return {
        "run_profile": run_profile,
        "run_sequence": run_sequence,
        "valid_runs_so_far": valid_runs_int,
        "protocol_note": (
            "baseline_idle is used until the first valid dataset run is recorded; "
            "later runs use interactive_use."
        ),
    }


def recompute_dataset_tracker(*, config: DatasetTrackerConfig | None = None) -> Path | None:
    """Recompute dataset tracker entries from evidence packs (backfill/QA refresh)."""
    cfg = config or DatasetTrackerConfig()
    output_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not output_root.exists():
        return None
    tracker_path = Path(app_config.DATA_DIR) / "archive" / "dataset_plan.json"
    tracker_path.parent.mkdir(parents=True, exist_ok=True)

    # Iterate all evidence packs and re-run the tracker update; update_dataset_tracker is
    # idempotent and will update existing entries.
    for run_dir in sorted([p for p in output_root.iterdir() if p.is_dir()]):
        manifest_path = run_dir / "run_manifest.json"
        if not manifest_path.exists():
            continue
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        operator = raw.get("operator") or {}
        tier = operator.get("tier")
        if not tier or str(tier).lower() != "dataset":
            continue
        target = raw.get("target") or {}
        scenario = raw.get("scenario") or {}
        environment = raw.get("environment") or {}
        if not isinstance(target, dict) or not isinstance(operator, dict):
            continue

        manifest = RunManifest(
            run_manifest_version=int(raw.get("run_manifest_version") or 1),
            dynamic_run_id=str(raw.get("dynamic_run_id") or run_dir.name),
            created_at=str(raw.get("created_at") or ""),
            batch_id=raw.get("batch_id"),
            started_at=raw.get("started_at"),
            ended_at=raw.get("ended_at"),
            status=str(raw.get("status") or "unknown"),
            target=target,
            environment=environment if isinstance(environment, dict) else {},
            scenario=scenario if isinstance(scenario, dict) else {},
            operator=operator,
        )
        # Attach artifacts so we can compute PCAP size.
        from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord

        artifacts = []
        for item in raw.get("artifacts") or []:
            if not isinstance(item, dict):
                continue
            artifacts.append(
                ArtifactRecord(
                    relative_path=str(item.get("relative_path") or ""),
                    type=str(item.get("type") or ""),
                    sha256=str(item.get("sha256") or ""),
                    produced_by=str(item.get("produced_by") or ""),
                    size_bytes=item.get("size_bytes"),
                    origin=item.get("origin"),
                    device_path=item.get("device_path"),
                    pull_status=item.get("pull_status"),
                )
            )
        manifest.artifacts = artifacts
        update_dataset_tracker(manifest, run_dir, config=cfg, event_logger=None)

    return tracker_path if tracker_path.exists() else None


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


def _is_valid_run(
    run_dir: Path,
    entry: dict[str, Any],
    cfg: DatasetTrackerConfig,
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    pcap_size = int(entry.get("pcap_size_bytes") or 0)
    if pcap_size < MIN_PCAP_BYTES:
        reasons.append("pcap_too_small")
        return False, reasons
    report_status = entry.get("report_status")
    if report_status == "skip" or report_status is None:
        reasons.append("pcap_report_missing_or_skip")
        return False, reasons
    if not _features_ok(run_dir):
        reasons.append("pcap_features_missing")
        return False, reasons
    if not _duration_ok(run_dir):
        reasons.append("sampling_duration_below_min")
        return False, reasons
    # Guardrail: if netstats indicates substantial traffic, the PCAP should span
    # more than just a few seconds. This prevents "valid by size" captures from
    # being accepted when they likely missed most of the session traffic.
    net_total = entry.get("netstats_total_bytes")
    pcap_span = entry.get("pcap_capture_duration_s")
    try:
        net_total_int = int(net_total or 0)
    except Exception:
        net_total_int = 0
    try:
        pcap_span_f = float(pcap_span) if pcap_span is not None else None
    except Exception:
        pcap_span_f = None
    if net_total_int >= int(cfg.large_netstats_bytes_threshold):
        if pcap_span_f is None or pcap_span_f < float(cfg.min_pcap_span_seconds_if_large_netstats):
            reasons.append("pcap_span_too_short_for_netstats")
            return False, reasons
    return True, reasons


def _netstats_summary(run_dir: Path) -> dict[str, Any]:
    summary_path = run_dir / "analysis" / "summary.json"
    if not summary_path.exists():
        return {}
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    stats = (payload.get("telemetry") or {}).get("stats") or {}
    total_in = stats.get("netstats_bytes_in_total")
    total_out = stats.get("netstats_bytes_out_total")
    try:
        total = int(total_in or 0) + int(total_out or 0)
    except Exception:
        total = None
    return {
        "netstats_bytes_in_total": total_in,
        "netstats_bytes_out_total": total_out,
        "netstats_total_bytes": total,
    }


def _pcap_capture_stats(run_dir: Path) -> dict[str, Any]:
    report_path = run_dir / "analysis/pcap_report.json"
    if not report_path.exists():
        return {}
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    parsed = (payload.get("capinfos") or {}).get("parsed") or {}
    return {
        "pcap_packet_count": parsed.get("packet_count"),
        "pcap_capture_duration_s": parsed.get("capture_duration_s"),
        "pcap_data_size_bytes": parsed.get("data_size_bytes"),
    }


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


__all__ = [
    "DatasetTrackerConfig",
    "load_dataset_tracker",
    "peek_next_run_protocol",
    "recompute_dataset_tracker",
    "update_dataset_tracker",
]
