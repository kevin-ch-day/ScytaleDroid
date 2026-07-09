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
from scytaledroid.DynamicAnalysis.research_cohort_archive import resolve_dataset_plan_read_path
from scytaledroid.DynamicAnalysis.services.paper_freeze_readiness import (
    PaperFreezeRecommendation,
    recommend_paper_freeze_for_runs,
)
from scytaledroid.DynamicAnalysis.tracker_scope import (
    build_scoped_dataset_counts,
    default_resolve_tracker_run_identity,
    scope_tracker_runs_to_active_identity,
)
from scytaledroid.DynamicAnalysis.templates.category_map import (
    category_for_package,
    resolved_template_for_package,
)
from scytaledroid.DynamicAnalysis.utils.run_cleanup import PackageRunCounts, find_dynamic_run_dirs


@dataclass(frozen=True)
class DatasetRunRecentSummary:
    ended_at: str | None
    run_profile: str | None
    interaction_level: str | None
    messaging_activity: str | None
    valid: bool | None
    countable: bool | None
    cohort_eligibility: str | None
    invalid_reason_code: str | None
    pcap_failure_detail: str | None
    low_signal: bool | None
    baseline_not_idle: bool | None
    supplemental_reason: str | None
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
    historical_valid_runs: int = 0
    historical_build_count: int = 0
    historical_pcap_count: int = 0
    active_version_code: str = ""
    active_base_sha: str = ""
    paper_freeze: PaperFreezeRecommendation | None = None


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


def _preferred_interactive_profile_for_package(
    package_name: str,
    *,
    config: DatasetTrackerConfig,
) -> str:
    preferred = str(getattr(config, "interactive_profile", "") or "").strip().lower()
    if preferred == "interaction_scripted":
        if resolved_template_for_package(package_name):
            return "interaction_scripted"
        return "interaction_manual"
    return preferred or "interaction_manual"


def _tracker_path() -> Path:
    return resolve_dataset_plan_read_path()


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
    baseline_not_idle = sum(
        1
        for row in runs
        if isinstance(row, dict)
        and row.get("valid_dataset_run") is True
        and row.get("countable") is False
        and str(row.get("run_profile") or "").strip().lower() == "baseline_idle"
        and row.get("baseline_not_idle") is True
    )
    return PackageRunCounts(
        total_runs=total,
        valid_runs=int(entry.get("valid_runs") or 0),
        baseline_valid_runs=int(entry.get("baseline_valid_runs") or 0),
        interactive_valid_runs=int(entry.get("interactive_valid_runs") or 0),
        quota_met=bool(entry.get("quota_met")),
        extra_valid_runs=int(entry.get("extra_valid_runs") or 0),
        baseline_not_idle_valid=baseline_not_idle,
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
        suggested_slot = min(baseline_valid + 1, int(cfg.baseline_required))
    elif interactive_valid < int(cfg.interactive_required):
        suggested_profile = _preferred_interactive_profile_for_package(package_name, config=cfg)
        suggested_slot = int(cfg.baseline_required) + min(interactive_valid + 1, int(cfg.interactive_required))
    else:
        suggested_profile = _preferred_interactive_profile_for_package(package_name, config=cfg)
    if str(suggested_profile).strip().lower() == "baseline_idle":
        suggested_profile = _canonical_baseline_profile_for_package(package_name)
    return str(suggested_profile or "interaction_manual").strip(), suggested_slot


def _status_label(row: DatasetRunRecentSummary) -> str:
    if row.valid is True:
        label = "VALID"
        if str(row.run_profile or "").strip().lower() == "baseline_idle" and row.low_signal is True:
            label += " (LOW_SIGNAL_IDLE)"
        if str(row.run_profile or "").strip().lower() == "baseline_idle" and row.baseline_not_idle is True:
            label += " (BASELINE_NOT_IDLE)"
        return label
    if row.valid is False:
        return f"INVALID:{row.invalid_reason_code or 'UNKNOWN'}"
    return "UNKNOWN"


def _supplemental_reason(
    *,
    run_profile: str | None,
    valid: bool | None,
    countable: bool | None,
    low_signal: bool | None,
    baseline_not_idle: bool | None,
    extra_run: bool,
    cohort_eligibility: str | None,
) -> str | None:
    if valid is not True:
        return None
    if countable is True:
        return None
    profile_lc = str(run_profile or "").strip().lower()
    cohort_lc = str(cohort_eligibility or "").strip().upper()
    if profile_lc == "baseline_idle" and low_signal is True:
        return "LOW_SIGNAL_IDLE"
    if extra_run or cohort_lc == "EXTRA":
        if profile_lc == "interaction_manual":
            return "MANUAL_EXTRA_RUN"
        if profile_lc == "interaction_scripted":
            return "SCRIPTED_EXTRA_RUN"
        return "EXTRA_RUN"
    return None


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
            countable=(True if row.get("countable") is True else (False if row.get("countable") is False else None)),
            cohort_eligibility=(str(row.get("cohort_eligibility")) if row.get("cohort_eligibility") else None),
            invalid_reason_code=(
                str(row.get("invalid_reason_code")) if row.get("invalid_reason_code") else None
            ),
            pcap_failure_detail=(
                str(row.get("pcap_failure_detail")) if row.get("pcap_failure_detail") else None
            ),
            low_signal=(True if row.get("low_signal") is True else (False if row.get("low_signal") is False else None)),
            baseline_not_idle=(
                True
                if row.get("baseline_not_idle") is True
                else (False if row.get("baseline_not_idle") is False else None)
            ),
            supplemental_reason=_supplemental_reason(
                run_profile=(str(row.get("run_profile")) if row.get("run_profile") else None),
                valid=valid_norm,
                countable=(True if row.get("countable") is True else (False if row.get("countable") is False else None)),
                low_signal=(True if row.get("low_signal") is True else (False if row.get("low_signal") is False else None)),
                baseline_not_idle=(
                    True
                    if row.get("baseline_not_idle") is True
                    else (False if row.get("baseline_not_idle") is False else None)
                ),
                extra_run=bool(row.get("extra_run")),
                cohort_eligibility=(str(row.get("cohort_eligibility")) if row.get("cohort_eligibility") else None),
            ),
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
            countable=row.countable,
            cohort_eligibility=row.cohort_eligibility,
            invalid_reason_code=row.invalid_reason_code,
            pcap_failure_detail=row.pcap_failure_detail,
            low_signal=row.low_signal,
            baseline_not_idle=row.baseline_not_idle,
            supplemental_reason=row.supplemental_reason,
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
    scoped_runs = scope_tracker_runs_to_active_identity(
        package,
        runs if isinstance(runs, list) else [],
        resolve_tracker_run_identity_fn=default_resolve_tracker_run_identity,
    )
    active_runs = list(scoped_runs["active_runs"])
    scoped_counts = build_scoped_dataset_counts(
        package,
        runs if isinstance(runs, list) else [],
        cfg=cfg,
        resolve_tracker_run_identity_fn=default_resolve_tracker_run_identity,
    )
    counts = PackageRunCounts(
        total_runs=int(scoped_counts["technical_valid_active"]),
        valid_runs=int(scoped_counts["baseline_countable"]) + int(scoped_counts["interactive_countable"]),
        baseline_valid_runs=int(scoped_counts["baseline_countable"]),
        interactive_valid_runs=int(scoped_counts["interactive_countable"]),
        quota_met=(
            int(scoped_counts["baseline_countable"]) >= int(cfg.baseline_required)
            and int(scoped_counts["interactive_countable"]) >= int(cfg.interactive_required)
        ),
        extra_valid_runs=(
            int(scoped_counts["baseline_extra"])
            + int(scoped_counts.get("baseline_low_signal_supplemental") or 0)
            + int(scoped_counts.get("baseline_not_idle_supplemental") or 0)
            + int(scoped_counts["interactive_extra"])
            + int(scoped_counts.get("interactive_low_signal_supplemental") or 0)
        ),
        baseline_extra_valid=int(scoped_counts["baseline_extra"]),
        baseline_low_signal_valid=int(scoped_counts.get("baseline_low_signal_supplemental") or 0),
        baseline_not_idle_valid=int(scoped_counts.get("baseline_not_idle_supplemental") or 0),
        interactive_extra_valid=int(scoped_counts["interactive_extra"]),
        interactive_low_signal_valid=int(scoped_counts.get("interactive_low_signal_supplemental") or 0),
    )
    suggested_profile_from_tracker, suggested_slot = _protocol_from_runs(
        package_name=package,
        runs=active_runs,
        cfg=cfg,
    )
    recent_runs = _recent_run_summaries(active_runs, limit=recent_limit)
    baseline_idle_pcap_missing_streak = _baseline_idle_pcap_missing_streak(recent_runs)
    baseline_idle_low_signal_streak = _baseline_idle_low_signal_streak(recent_runs)
    baseline_connected_insufficient_duration_streak = _baseline_connected_insufficient_duration_streak(
        recent_runs,
        package_name=package,
    )
    effective_suggested_profile = suggested_profile_from_tracker
    if (
        baseline_connected_insufficient_duration_streak >= 2
        and counts.baseline_valid_runs >= int(cfg.baseline_required)
    ):
        effective_suggested_profile = _preferred_interactive_profile_for_package(package, config=cfg)

    paper_eligible_local, quota_counted_local, exclusion_reason_top = _local_rollups(active_runs)
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
        historical_valid_runs=int(scoped_counts.get("legacy_valid") or scoped_runs.get("legacy_valid") or 0),
        historical_build_count=int(scoped_counts.get("legacy_builds") or scoped_runs.get("legacy_builds") or 0),
        historical_pcap_count=int(scoped_counts.get("legacy_pcap_available") or 0),
        active_version_code=str(scoped_counts.get("active_version_code") or ""),
        active_base_sha=str(scoped_counts.get("active_base_sha") or ""),
        paper_freeze=recommend_paper_freeze_for_runs(
            package,
            runs if isinstance(runs, list) else [],
            cfg=cfg,
            active_identity=(
                str(scoped_counts.get("active_version_code") or "") or None,
                str(scoped_counts.get("active_base_sha") or "") or None,
            ),
        ),
    )


__all__ = [
    "DatasetRunRecentSummary",
    "DatasetRunState",
    "load_dataset_run_state",
]
