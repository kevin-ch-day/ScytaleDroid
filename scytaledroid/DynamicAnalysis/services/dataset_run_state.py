"""State interpretation helpers for guided dataset runs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import MESSAGING_PACKAGES
from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
    DatasetTrackerConfig,
    _is_baseline_profile,
    _is_interactive_profile,
    _normalize_tracker_payload,
)
from scytaledroid.DynamicAnalysis.templates.category_map import category_for_package
from scytaledroid.DynamicAnalysis.utils.run_cleanup import PackageRunCounts, find_dynamic_run_dirs


@dataclass(frozen=True)
class DatasetRunRecentSummary:
    ended_at: str | None
    run_profile: str | None
    interaction_level: str | None
    messaging_activity: str | None
    valid: bool | None
    invalid_reason_code: str | None
    low_signal: bool | None
    run_id: str
    status_label: str


@dataclass(frozen=True)
class DatasetRunState:
    package_name: str
    tracker_status: str
    evidence_status: str
    state_status: str
    counts: PackageRunCounts
    baseline_required: int
    interactive_required: int
    total_required: int
    local_evidence_dir_count: int
    reset_available: bool
    paper_eligible_local: int
    quota_counted_local: int
    exclusion_reason_top: tuple[tuple[str, int], ...]
    suggested_profile_from_tracker: str
    effective_suggested_profile: str
    suggested_slot: int | None
    recent_runs: tuple[DatasetRunRecentSummary, ...]
    baseline_idle_pcap_missing_streak: int
    baseline_idle_low_signal_streak: int
    baseline_connected_insufficient_duration_streak: int


def _is_messaging_package_or_category(package_name: str) -> bool:
    pkg_lc = str(package_name or "").strip().lower()
    if not pkg_lc:
        return False
    category = str(category_for_package(pkg_lc) or "").strip().lower()
    if category == "messaging":
        return True
    return pkg_lc in {p.lower() for p in MESSAGING_PACKAGES}


def _canonical_baseline_profile_for_package(package_name: str) -> str:
    if _is_messaging_package_or_category(package_name):
        return "baseline_connected"
    return "baseline_idle"


def _tracker_path() -> Path:
    return Path(app_config.DATA_DIR) / "archive" / "dataset_plan.json"


def _load_tracker_payload(
    cfg: DatasetTrackerConfig,
) -> tuple[str, dict[str, object], dict[str, object] | None]:
    tracker_path = _tracker_path()
    if not tracker_path.exists():
        return "missing", {"apps": {}}, None
    try:
        raw_payload = json.loads(tracker_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return "invalid", {"apps": {}}, None
    except OSError:
        return "unavailable", {"apps": {}}, None
    if not isinstance(raw_payload, dict):
        return "invalid", {"apps": {}}, None

    apps = raw_payload.get("apps")
    status = "ok" if isinstance(apps, dict) or "apps" not in raw_payload else "invalid"
    normalized = _normalize_tracker_payload(raw_payload, cfg, dirty=[False])
    normalized_apps = normalized.get("apps")
    if not isinstance(normalized_apps, dict):
        return "invalid", {"apps": {}}, None
    return status, normalized, raw_payload


def _counts_from_entry(entry: dict[str, object] | None) -> PackageRunCounts:
    if not isinstance(entry, dict):
        return PackageRunCounts(
            total_runs=0,
            valid_runs=0,
            baseline_valid_runs=0,
            interactive_valid_runs=0,
            quota_met=False,
            extra_valid_runs=0,
        )
    runs = entry.get("runs")
    total = len(runs) if isinstance(runs, list) else 0
    return PackageRunCounts(
        total_runs=total,
        valid_runs=int(entry.get("valid_runs") or 0),
        baseline_valid_runs=int(entry.get("baseline_valid_runs") or 0),
        interactive_valid_runs=int(entry.get("interactive_valid_runs") or 0),
        quota_met=bool(entry.get("quota_met")),
        extra_valid_runs=int(entry.get("extra_valid_runs") or 0),
    )


def _protocol_from_runs(
    *,
    package_name: str,
    runs: list[dict[str, object]],
    cfg: DatasetTrackerConfig,
) -> tuple[str, int | None]:
    baseline_valid = 0
    interactive_valid = 0
    total_valid = 0
    for row in runs:
        if not isinstance(row, dict) or row.get("valid_dataset_run") is not True:
            continue
        if not bool(row.get("counts_toward_quota", True)):
            continue
        total_valid += 1
        profile = row.get("run_profile")
        if _is_baseline_profile(profile, cfg):
            baseline_valid += 1
        elif _is_interactive_profile(profile, cfg):
            interactive_valid += 1

    total_required = int(cfg.baseline_required) + int(cfg.interactive_required)
    suggested_slot = max(min(total_valid + 1, total_required), 1)
    if baseline_valid < int(cfg.baseline_required):
        suggested_profile = cfg.baseline_profile
    elif interactive_valid < int(cfg.interactive_required):
        suggested_profile = cfg.interactive_profile
    else:
        suggested_profile = cfg.interactive_profile
    if str(suggested_profile).strip().lower() == "baseline_idle":
        suggested_profile = _canonical_baseline_profile_for_package(package_name)
    return str(suggested_profile or "interaction_scripted").strip(), suggested_slot


def _status_label(row: DatasetRunRecentSummary) -> str:
    if row.valid is True:
        label = "VALID"
        if str(row.run_profile or "").strip().lower() == "baseline_idle" and row.low_signal is True:
            label += " (LOW_SIGNAL_IDLE)"
        return label
    if row.valid is False:
        label = f"INVALID:{row.invalid_reason_code or 'UNKNOWN'}"
        if (
            str(row.run_profile or "").strip().lower() == "baseline_idle"
            and str(row.invalid_reason_code or "").strip().upper() == "PCAP_MISSING"
            and str(row.messaging_activity or "").strip().lower() in {"none", ""}
        ):
            label += " (LOW_SIGNAL_IDLE)"
        return label
    return "UNKNOWN"


def _recent_run_summaries(
    runs: list[dict[str, object]],
    *,
    limit: int,
) -> tuple[DatasetRunRecentSummary, ...]:
    def _sort_key(row: dict[str, object]) -> str:
        ended = row.get("ended_at") or ""
        started = row.get("started_at") or ""
        return str(ended or started)

    recent = [row for row in runs if isinstance(row, dict)]
    recent.sort(key=_sort_key, reverse=True)
    out: list[DatasetRunRecentSummary] = []
    for row in recent[: max(int(limit), 0)]:
        valid_value = row.get("valid_dataset_run")
        valid_norm = True if valid_value is True else (False if valid_value is False else None)
        summary = DatasetRunRecentSummary(
            ended_at=(str(row.get("ended_at")) if row.get("ended_at") else None),
            run_profile=(str(row.get("run_profile")) if row.get("run_profile") else None),
            interaction_level=(str(row.get("interaction_level")) if row.get("interaction_level") else None),
            messaging_activity=(str(row.get("messaging_activity")) if row.get("messaging_activity") else None),
            valid=valid_norm,
            invalid_reason_code=(
                str(row.get("invalid_reason_code")) if row.get("invalid_reason_code") else None
            ),
            low_signal=(True if row.get("low_signal") is True else (False if row.get("low_signal") is False else None)),
            run_id=str(row.get("run_id") or ""),
            status_label="",
        )
        out.append(summary)
    return tuple(
        DatasetRunRecentSummary(
            ended_at=row.ended_at,
            run_profile=row.run_profile,
            interaction_level=row.interaction_level,
            messaging_activity=row.messaging_activity,
            valid=row.valid,
            invalid_reason_code=row.invalid_reason_code,
            low_signal=row.low_signal,
            run_id=row.run_id,
            status_label=_status_label(row),
        )
        for row in out
    )


def _baseline_idle_pcap_missing_streak(recent_runs: tuple[DatasetRunRecentSummary, ...]) -> int:
    streak = 0
    for row in recent_runs:
        profile = str(row.run_profile or "").strip().lower()
        reason = str(row.invalid_reason_code or "").strip().upper()
        if profile == "baseline_idle" and row.valid is False and reason == "PCAP_MISSING":
            streak += 1
            continue
        break
    return streak


def _baseline_idle_low_signal_streak(recent_runs: tuple[DatasetRunRecentSummary, ...]) -> int:
    streak = 0
    for row in recent_runs:
        profile = str(row.run_profile or "").strip().lower()
        if profile == "baseline_idle" and row.valid is True and row.low_signal is True:
            streak += 1
            continue
        break
    return streak


def _baseline_connected_insufficient_duration_streak(
    recent_runs: tuple[DatasetRunRecentSummary, ...],
    *,
    package_name: str,
) -> int:
    if not _is_messaging_package_or_category(package_name):
        return 0
    streak = 0
    for row in recent_runs:
        profile = str(row.run_profile or "").strip().lower()
        reason = str(row.invalid_reason_code or "").strip().upper()
        if profile == "baseline_connected" and row.valid is False and reason == "INSUFFICIENT_DURATION":
            streak += 1
            continue
        break
    return streak


def _local_rollups(runs: list[dict[str, object]]) -> tuple[int, int, tuple[tuple[str, int], ...]]:
    paper_eligible_local = 0
    quota_counted_local = 0
    reasons: dict[str, int] = {}
    for row in runs:
        if not isinstance(row, dict):
            continue
        if row.get("valid_dataset_run") is not True:
            continue
        if row.get("paper_eligible") is True:
            paper_eligible_local += 1
        if row.get("counts_toward_quota") is True:
            quota_counted_local += 1
        if row.get("paper_eligible") is False:
            reason = str(row.get("paper_exclusion_primary_reason_code") or "EXCLUDED_UNKNOWN").strip()
            reasons[reason] = int(reasons.get(reason, 0)) + 1
    top = tuple(sorted(reasons.items(), key=lambda kv: (-int(kv[1]), kv[0]))[:3])
    return paper_eligible_local, quota_counted_local, top


def _evidence_state(package_name: str) -> tuple[str, int]:
    evidence_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not evidence_root.exists():
        return "missing", 0
    try:
        matches = find_dynamic_run_dirs(package_name)
    except Exception:
        return "unavailable", 0
    return "ok", len(matches)


def _state_status(
    *,
    tracker_status: str,
    evidence_status: str,
    counts: PackageRunCounts,
    local_evidence_dir_count: int,
) -> str:
    if tracker_status == "unavailable" or evidence_status == "unavailable":
        return "unavailable"
    if tracker_status == "invalid":
        return "degraded"
    if counts.total_runs > 0 and evidence_status == "missing":
        return "degraded"
    if local_evidence_dir_count > 0 and tracker_status == "missing":
        return "degraded"
    return "ok"


def load_dataset_run_state(
    package_name: str,
    *,
    config: DatasetTrackerConfig | None = None,
    recent_limit: int = 5,
) -> DatasetRunState:
    cfg = config or DatasetTrackerConfig()
    tracker_status, payload, _raw_payload = _load_tracker_payload(cfg)
    package = (package_name or "_unknown").strip() or "_unknown"
    apps = payload.get("apps") if isinstance(payload, dict) else {}
    entry = apps.get(package) if isinstance(apps, dict) else None
    runs = entry.get("runs") if isinstance(entry, dict) and isinstance(entry.get("runs"), list) else []

    counts = _counts_from_entry(entry)
    suggested_profile_from_tracker, suggested_slot = _protocol_from_runs(
        package_name=package,
        runs=runs if isinstance(runs, list) else [],
        cfg=cfg,
    )
    recent_runs = _recent_run_summaries(runs if isinstance(runs, list) else [], limit=recent_limit)
    baseline_idle_pcap_missing_streak = _baseline_idle_pcap_missing_streak(recent_runs)
    baseline_idle_low_signal_streak = _baseline_idle_low_signal_streak(recent_runs)
    baseline_connected_insufficient_duration_streak = _baseline_connected_insufficient_duration_streak(
        recent_runs,
        package_name=package,
    )
    effective_suggested_profile = suggested_profile_from_tracker
    if baseline_connected_insufficient_duration_streak >= 2:
        effective_suggested_profile = "interaction_scripted"

    paper_eligible_local, quota_counted_local, exclusion_reason_top = _local_rollups(
        runs if isinstance(runs, list) else []
    )
    evidence_status, local_evidence_dir_count = _evidence_state(package)

    return DatasetRunState(
        package_name=package,
        tracker_status=tracker_status,
        evidence_status=evidence_status,
        state_status=_state_status(
            tracker_status=tracker_status,
            evidence_status=evidence_status,
            counts=counts,
            local_evidence_dir_count=local_evidence_dir_count,
        ),
        counts=counts,
        baseline_required=int(cfg.baseline_required),
        interactive_required=int(cfg.interactive_required),
        total_required=int(cfg.baseline_required) + int(cfg.interactive_required),
        local_evidence_dir_count=local_evidence_dir_count,
        reset_available=local_evidence_dir_count > 0,
        paper_eligible_local=paper_eligible_local,
        quota_counted_local=quota_counted_local,
        exclusion_reason_top=exclusion_reason_top,
        suggested_profile_from_tracker=suggested_profile_from_tracker,
        effective_suggested_profile=effective_suggested_profile,
        suggested_slot=suggested_slot,
        recent_runs=recent_runs,
        baseline_idle_pcap_missing_streak=baseline_idle_pcap_missing_streak,
        baseline_idle_low_signal_streak=baseline_idle_low_signal_streak,
        baseline_connected_insufficient_duration_streak=baseline_connected_insufficient_duration_streak,
    )


__all__ = [
    "DatasetRunRecentSummary",
    "DatasetRunState",
    "load_dataset_run_state",
]
