"""Dataset run tracker for dynamic collection."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean, pstdev, pvariance
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.core.event_logger import RunEventLogger
from scytaledroid.DynamicAnalysis.core.manifest import RunManifest

MIN_PCAP_BYTES = int(getattr(app_config, "DYNAMIC_MIN_PCAP_BYTES", 100000))


@dataclass(frozen=True)
class DatasetTrackerConfig:
    repeats_per_app: int = field(
        default_factory=lambda: int(getattr(app_config, "DYNAMIC_DATASET_RUNS_PER_APP", 3))
    )
    baseline_required: int = field(
        default_factory=lambda: int(getattr(app_config, "DYNAMIC_DATASET_BASELINE_RUNS", 1))
    )
    interactive_required: int = field(
        default_factory=lambda: int(getattr(app_config, "DYNAMIC_DATASET_INTERACTIVE_RUNS", 2))
    )
    baseline_profile: str = "baseline_idle"
    interactive_profile: str = "interactive_use"


_VALIDITY_ENUM = {
    "INSUFFICIENT_DURATION",
    "PCAP_MISSING",
    "PCAP_TOO_SMALL",
    "PCAP_REPORT_MISSING",
    "PCAP_REPORT_SKIP",
    "MISSING_TOOLS_TSHARK",
    "MISSING_TOOLS_CAPINFOS",
    "PCAP_REPORT_EMPTY_NO_REASON",
    "PCAP_PARSE_ERROR",
    "CAPTURE_INTERRUPTED",
}


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
        "messaging_activity": operator.get("messaging_activity"),
    }
    run_entry.update(_netstats_summary(run_dir))
    run_entry.update(_pcap_capture_stats(run_dir))
    validity = evaluate_dataset_validity(run_dir, manifest, run_entry, cfg)
    run_entry.update(validity)

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
    app_entry["baseline_valid_runs"] = sum(
        1
        for r in app_entry["runs"]
        if r.get("valid_dataset_run") is True and str(r.get("run_profile") or "").startswith(cfg.baseline_profile)
    )
    app_entry["interactive_valid_runs"] = sum(
        1
        for r in app_entry["runs"]
        if r.get("valid_dataset_run") is True and str(r.get("run_profile") or "").startswith(cfg.interactive_profile)
    )
    app_entry["app_complete"] = (
        int(app_entry["baseline_valid_runs"]) >= int(cfg.baseline_required)
        and int(app_entry["interactive_valid_runs"]) >= int(cfg.interactive_required)
    )
    _apply_quota_marking(app_entry, cfg)
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
    payload = _load(tracker_path)
    return _normalize_tracker_payload(payload, DatasetTrackerConfig())


def _normalize_tracker_payload(payload: dict[str, Any], cfg: DatasetTrackerConfig) -> dict[str, Any]:
    """Normalize/repair derived tracker fields in-memory.

    The tracker JSON is a derived index. As the schema evolves, older files may
    be missing computed keys like baseline_valid_runs. Normalization keeps the UI
    and status logic stable without requiring an explicit recompute step.
    """
    if not isinstance(payload, dict):
        return {"apps": {}}
    apps = payload.get("apps")
    if not isinstance(apps, dict):
        payload["apps"] = {}
        return payload

    for _pkg, entry in apps.items():
        if not isinstance(entry, dict):
            continue
        runs = entry.get("runs")
        if not isinstance(runs, list):
            runs = []
            entry["runs"] = runs

        # Recompute key counts if missing or inconsistent.
        entry["run_count"] = len([r for r in runs if isinstance(r, dict)])
        entry["target_runs"] = int(entry.get("target_runs") or cfg.repeats_per_app)
        entry["valid_runs"] = sum(1 for r in runs if isinstance(r, dict) and r.get("valid_dataset_run") is True)
        entry["baseline_valid_runs"] = sum(
            1
            for r in runs
            if isinstance(r, dict)
            and r.get("valid_dataset_run") is True
            and str(r.get("run_profile") or "").startswith(cfg.baseline_profile)
        )
        entry["interactive_valid_runs"] = sum(
            1
            for r in runs
            if isinstance(r, dict)
            and r.get("valid_dataset_run") is True
            and str(r.get("run_profile") or "").startswith(cfg.interactive_profile)
        )
        entry["app_complete"] = (
            int(entry["baseline_valid_runs"]) >= int(cfg.baseline_required)
            and int(entry["interactive_valid_runs"]) >= int(cfg.interactive_required)
        )

        # Ensure quota markings are present for UI labels (extra_run, counts_toward_quota).
        _apply_quota_marking(entry, cfg)
        entry["quota_met"] = bool(entry.get("quota_met") or entry.get("app_complete"))
        entry["extra_valid_runs"] = int(entry.get("extra_valid_runs") or 0)

    return payload


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

    baseline_valid = 0
    interactive_valid = 0
    total_valid = 0
    if isinstance(runs, list):
        for r in runs:
            if not isinstance(r, dict) or r.get("valid_dataset_run") is not True:
                continue
            total_valid += 1
            prof = str(r.get("run_profile") or "")
            if prof.startswith(cfg.baseline_profile) or "baseline" in prof or "idle" in prof:
                baseline_valid += 1
            elif prof.startswith(cfg.interactive_profile) or "interactive" in prof:
                interactive_valid += 1

    # Dataset protocol numbering is by quota slot, not attempt count.
    #
    # If Run #1 fails QA, the next retry should still be "Run #1" until a valid run
    # is recorded. This avoids confusing operators ("baseline Run #2") and matches
    # the paper contract: each app needs >=3 VALID runs; retries fill the same slot.
    needed = max(int(cfg.repeats_per_app), int(cfg.baseline_required) + int(cfg.interactive_required))
    run_sequence = max(min(total_valid + 1, needed), 1)

    if baseline_valid < int(cfg.baseline_required):
        run_profile = cfg.baseline_profile
    elif interactive_valid < int(cfg.interactive_required):
        run_profile = cfg.interactive_profile
    else:
        # Quota is satisfied; continue suggesting interactive unless operator chooses otherwise.
        run_profile = cfg.interactive_profile
    return {
        "run_profile": run_profile,
        "run_sequence": run_sequence,
        "valid_runs_so_far": total_valid,
        "baseline_valid_runs": baseline_valid,
        "interactive_valid_runs": interactive_valid,
        "protocol_note": (
            "Run sequence counts valid runs (quota slots), not raw attempts. "
            f"Need baseline={cfg.baseline_required} and interactive={cfg.interactive_required} valid run(s)."
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

    # Rebuild from evidence packs only. This intentionally drops tracker entries for
    # evidence packs that were deleted locally (e.g., removing invalid runs).
    tracker_path.write_text(
        json.dumps({"apps": {}, "updated_at": datetime.now(UTC).isoformat()}, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    # Iterate all evidence packs and re-run the tracker update.
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


def _parse_dt(value: object) -> datetime | None:
    """Best-effort parse of ISO-ish timestamps used in manifests and tracker runs."""
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    # Allow common ISO 'Z' suffix.
    if text.endswith("Z") and "+" not in text:
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _apply_quota_marking(app_entry: dict[str, Any], cfg: DatasetTrackerConfig) -> None:
    """Mark which runs count toward the first N valid runs (quota) and which are extras.

    This is intentionally deterministic from recorded run history, not from the order in
    which the tracker is updated or recomputed.
    """
    runs = app_entry.get("runs")
    if not isinstance(runs, list):
        return
    baseline_needed = max(0, int(cfg.baseline_required))
    interactive_needed = max(0, int(cfg.interactive_required))
    # Total quota slots is baseline+interactive, unless legacy repeats_per_app is larger.
    # This lets teams temporarily over-collect without changing baseline/interactive minima.
    needed = max(int(cfg.repeats_per_app), baseline_needed + interactive_needed)
    # Reset markers (idempotent).
    for r in runs:
        if isinstance(r, dict):
            r["counts_toward_quota"] = False
            r["extra_run"] = 0
    indexed: list[tuple[int, dict[str, Any]]] = [(i, r) for i, r in enumerate(runs) if isinstance(r, dict)]
    indexed.sort(
        key=lambda item: (
            _parse_dt(item[1].get("ended_at"))
            or _parse_dt(item[1].get("started_at"))
            or datetime.min.replace(tzinfo=UTC),
            item[0],
        )
    )

    baseline_seen = 0
    interactive_seen = 0
    quota_met_at: str | None = None
    quota_met_run_id: str | None = None
    for _, r in indexed:
        is_valid = r.get("valid_dataset_run") is True
        if not is_valid:
            continue
        prof = str(r.get("run_profile") or "")
        is_baseline = prof.startswith(cfg.baseline_profile) or "baseline" in prof or "idle" in prof
        is_interactive = prof.startswith(cfg.interactive_profile) or "interactive" in prof

        counted = False
        if is_baseline and baseline_seen < baseline_needed:
            baseline_seen += 1
            counted = True
        elif is_interactive and interactive_seen < interactive_needed:
            interactive_seen += 1
            counted = True
        elif (baseline_seen + interactive_seen) < needed:
            # If profile tagging is inconsistent, still allow runs to fill total quota slots.
            counted = True

        if counted and (baseline_seen + interactive_seen) <= needed:
            r["counts_toward_quota"] = True
            if (
                quota_met_at is None
                and baseline_seen >= baseline_needed
                and interactive_seen >= interactive_needed
            ):
                quota_met_at = r.get("ended_at") or r.get("started_at")
                quota_met_run_id = r.get("run_id")
        else:
            r["extra_run"] = 1

    app_entry["quota_met"] = bool(
        baseline_seen >= baseline_needed and interactive_seen >= interactive_needed
    )
    app_entry["quota_met_at"] = quota_met_at
    app_entry["quota_met_run_id"] = quota_met_run_id
    app_entry["extra_valid_runs"] = sum(
        1
        for r in runs
        if isinstance(r, dict)
        and r.get("valid_dataset_run") is True
        and not r.get("counts_toward_quota")
    )


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


def _features_ok(run_dir: Path) -> bool:
    return (run_dir / "analysis/pcap_features.json").exists()


def evaluate_dataset_validity(
    run_dir: Path,
    manifest: RunManifest,
    entry: dict[str, Any],
    cfg: DatasetTrackerConfig,
) -> dict[str, Any]:
    """Deterministic dataset validity classifier (Paper #2).

    Contract:
    - valid_dataset_run: bool
    - invalid_reason_code: str | None (exactly one when invalid)
    - flags: short_run, no_traffic_observed (ints 0/1)
    """
    flags: dict[str, int] = {"short_run": 0, "no_traffic_observed": 0}

    # Dataset protocol metadata is part of the Paper #2 dataset contract.
    operator = manifest.operator if isinstance(manifest.operator, dict) else {}
    missing_protocol = []
    if not operator.get("run_profile"):
        missing_protocol.append("run_profile")
    if operator.get("run_sequence") in (None, "", 0):
        missing_protocol.append("run_sequence")
    if not operator.get("interaction_level"):
        missing_protocol.append("interaction_level")
    if missing_protocol:
        return _invalid(
            "PCAP_PARSE_ERROR",
            {**flags, "protocol_missing": 1},
            run_dir,
        )

    # Capture interrupted (observer failure) is always invalid for dataset tier.
    for obs in manifest.observers or []:
        if getattr(obs, "observer_id", None) == "pcapdroid_capture":
            if str(getattr(obs, "status", "")).lower() == "failed":
                return _invalid("CAPTURE_INTERRUPTED", flags, run_dir)

    # Duration policy: sampling window is canonical.
    sampling_seconds = _sampling_duration_seconds(run_dir)
    if sampling_seconds is None:
        return _invalid("INSUFFICIENT_DURATION", flags, run_dir)
    if float(sampling_seconds) < float(app_config.DYNAMIC_MIN_DURATION_S):
        return _invalid("INSUFFICIENT_DURATION", flags, run_dir)
    if float(sampling_seconds) < float(app_config.DYNAMIC_TARGET_DURATION_S):
        flags["short_run"] = 1

    # PCAP size policy.
    min_bytes = int(getattr(app_config, "DYNAMIC_MIN_PCAP_BYTES", 100000))
    pcap_size = entry.get("pcap_size_bytes")
    try:
        pcap_size_int = int(pcap_size or 0)
    except Exception:
        pcap_size_int = 0
    if pcap_size_int <= 0:
        return _invalid("PCAP_MISSING", flags, run_dir)
    if pcap_size_int < min_bytes:
        return _invalid("PCAP_TOO_SMALL", flags, run_dir)

    # PCAP report must exist and not be skipped for dataset tier.
    report = _load_report(run_dir)
    if report is None:
        return _invalid("PCAP_REPORT_MISSING", flags, run_dir)
    report_status = report.get("report_status")
    if report_status is None:
        return _invalid("PCAP_REPORT_MISSING", flags, run_dir)
    if str(report_status).lower() == "skip":
        return _invalid("PCAP_REPORT_SKIP", flags, run_dir)

    # Missing tools are a dataset-tier invalidation (environment not dataset-ready).
    missing = report.get("missing_tools") or []
    missing_set = {str(x).lower() for x in missing if x}
    if "tshark" in missing_set:
        return _invalid("MISSING_TOOLS_TSHARK", flags, run_dir)
    if "capinfos" in missing_set:
        return _invalid("MISSING_TOOLS_CAPINFOS", flags, run_dir)

    # Protocol hierarchy may be empty only with an explicit no_traffic_observed flag.
    proto = report.get("protocol_hierarchy") or []
    no_traffic = report.get("no_traffic_observed")
    try:
        no_traffic_int = int(no_traffic or 0)
    except Exception:
        no_traffic_int = 0
    if not proto:
        if no_traffic_int == 1:
            flags["no_traffic_observed"] = 1
        else:
            return _invalid("PCAP_REPORT_EMPTY_NO_REASON", flags, run_dir)

    # Features must exist for dataset counting.
    if not _features_ok(run_dir):
        # We intentionally map this to a report parse error-like code to avoid
        # expanding the locked enum set for Paper #2.
        return _invalid("PCAP_PARSE_ERROR", flags, run_dir)

    return {
        "valid_dataset_run": True,
        "invalid_reason_code": None,
        "sampling_duration_seconds": sampling_seconds,
        "min_pcap_bytes": min_bytes,
        **flags,
    }


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


def _invalid(code: str, flags: dict[str, int], run_dir: Path) -> dict[str, Any]:
    if code not in _VALIDITY_ENUM:
        code = "PCAP_PARSE_ERROR"
    return {
        "valid_dataset_run": False,
        "invalid_reason_code": code,
        "sampling_duration_seconds": _sampling_duration_seconds(run_dir),
        "min_pcap_bytes": int(getattr(app_config, "DYNAMIC_MIN_PCAP_BYTES", 100000)),
        **flags,
    }


def _sampling_duration_seconds(run_dir: Path) -> float | None:
    summary_path = run_dir / "analysis" / "summary.json"
    if not summary_path.exists():
        return None
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    telemetry = (payload.get("telemetry") or {}).get("stats") or {}
    sampling_duration = telemetry.get("sampling_duration_seconds")
    try:
        return float(sampling_duration)
    except Exception:
        return None


def _load_report(run_dir: Path) -> dict[str, Any] | None:
    report_path = run_dir / "analysis" / "pcap_report.json"
    if not report_path.exists():
        return None
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None
    except (OSError, json.JSONDecodeError):
        return {"report_status": None}


__all__ = [
    "DatasetTrackerConfig",
    "load_dataset_tracker",
    "peek_next_run_protocol",
    "recompute_dataset_tracker",
    "update_dataset_tracker",
]
