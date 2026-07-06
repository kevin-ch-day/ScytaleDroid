from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from scytaledroid.DynamicAnalysis.controllers import guided_run
from scytaledroid.DynamicAnalysis.services.dataset_run_state import (
    DatasetRunRecentSummary,
    DatasetRunState,
)
from scytaledroid.DynamicAnalysis.utils.run_cleanup import PackageRunCounts

DEFAULT_SERIAL = "ZY22JK89DR"
DEFAULT_DEVICE_MODEL = "moto"
DEFAULT_SELECTED_DEVICE = (DEFAULT_SERIAL, DEFAULT_DEVICE_MODEL)
DEFAULT_ACTIVE_DEVICE = {"serial": DEFAULT_SERIAL, "model": DEFAULT_DEVICE_MODEL}
DEFAULT_COHORT_LABEL = "Research Dataset Beta"
UNSET = object()


def make_recent_summary(
    *,
    ended_at: str,
    run_profile: str,
    interaction_level: str,
    valid: bool,
    run_id: str,
    status_label: str,
    invalid_reason_code: str | None = None,
    pcap_failure_detail: str | None = None,
    messaging_activity: str | None = None,
    low_signal: str | None = None,
    baseline_not_idle: bool | None = None,
    countable: bool | None = None,
    cohort_eligibility: str | None = None,
    supplemental_reason: str | None = None,
) -> DatasetRunRecentSummary:
    return DatasetRunRecentSummary(
        ended_at=ended_at,
        run_profile=run_profile,
        interaction_level=interaction_level,
        messaging_activity=messaging_activity,
        valid=valid,
        countable=countable,
        cohort_eligibility=cohort_eligibility,
        invalid_reason_code=invalid_reason_code,
        pcap_failure_detail=pcap_failure_detail,
        low_signal=low_signal,
        baseline_not_idle=baseline_not_idle,
        supplemental_reason=supplemental_reason,
        run_id=run_id,
        status_label=status_label,
    )


def make_dataset_state(
    package_name: str,
    *,
    total_runs: int | None = None,
    valid_runs: int = 0,
    baseline_valid_runs: int = 0,
    interactive_valid_runs: int = 0,
    quota_met: bool | None = None,
    extra_valid_runs: int = 0,
    baseline_extra_valid: int = 0,
    baseline_low_signal_valid: int = 0,
    baseline_not_idle_valid: int = 0,
    interactive_extra_valid: int = 0,
    interactive_low_signal_valid: int = 0,
    baseline_required: int = 3,
    interactive_required: int = 4,
    local_evidence_dir_count: int = 0,
    reset_available: bool = False,
    paper_eligible_local: int = 0,
    quota_counted_local: int | None = None,
    exclusion_reason_top: tuple[tuple[str, int], ...] = (),
    suggested_profile_from_tracker: str = "baseline_idle",
    effective_suggested_profile: str | None = None,
    suggested_slot: int | None = 1,
    recent_runs: tuple[DatasetRunRecentSummary, ...] = (),
    baseline_idle_pcap_missing_streak: int = 0,
    baseline_idle_low_signal_streak: int = 0,
    baseline_connected_insufficient_duration_streak: int = 0,
    tracker_status: str = "ok",
    evidence_status: str = "ok",
    state_status: str = "ok",
    **extra: Any,
) -> DatasetRunState:
    if total_runs is None:
        total_runs = max(
            valid_runs, baseline_valid_runs + interactive_valid_runs + extra_valid_runs
        )
    if quota_met is None:
        quota_met = (
            baseline_valid_runs >= baseline_required
            and interactive_valid_runs >= interactive_required
        )
    if quota_counted_local is None:
        quota_counted_local = max(0, valid_runs - extra_valid_runs)
    effective_profile = effective_suggested_profile or suggested_profile_from_tracker

    payload: dict[str, Any] = {
        "package_name": package_name,
        "tracker_status": tracker_status,
        "evidence_status": evidence_status,
        "state_status": state_status,
        "counts": PackageRunCounts(
            total_runs=total_runs,
            valid_runs=valid_runs,
            baseline_valid_runs=baseline_valid_runs,
            interactive_valid_runs=interactive_valid_runs,
            quota_met=quota_met,
            extra_valid_runs=extra_valid_runs,
            baseline_extra_valid=baseline_extra_valid,
            baseline_low_signal_valid=baseline_low_signal_valid,
            baseline_not_idle_valid=baseline_not_idle_valid,
            interactive_extra_valid=interactive_extra_valid,
            interactive_low_signal_valid=interactive_low_signal_valid,
        ),
        "baseline_required": baseline_required,
        "interactive_required": interactive_required,
        "total_required": baseline_required + interactive_required,
        "local_evidence_dir_count": local_evidence_dir_count,
        "reset_available": reset_available,
        "paper_eligible_local": paper_eligible_local,
        "quota_counted_local": quota_counted_local,
        "exclusion_reason_top": exclusion_reason_top,
        "suggested_profile_from_tracker": suggested_profile_from_tracker,
        "effective_suggested_profile": effective_profile,
        "suggested_slot": suggested_slot,
        "recent_runs": recent_runs,
        "baseline_idle_pcap_missing_streak": baseline_idle_pcap_missing_streak,
        "baseline_idle_low_signal_streak": baseline_idle_low_signal_streak,
        "baseline_connected_insufficient_duration_streak": baseline_connected_insufficient_duration_streak,
    }
    payload.update(extra)
    return DatasetRunState(**payload)


def make_protocol_options_app(
    *,
    package_name: str = "bbc.mobile.news.ww",
    baseline_valid_runs: int,
    interactive_valid_runs: int,
    baseline_required: int = 3,
    interactive_required: int = 4,
    scripted_template_ready: bool = True,
) -> guided_run._SelectedAppContext:
    return guided_run._SelectedAppContext(
        package_name=package_name,
        display_label=package_name,
        meta_family_note=False,
        has_identity_mismatch=False,
        state=SimpleNamespace(suggested_slot=1, reset_available=False),
        cfg=SimpleNamespace(
            baseline_required=baseline_required,
            interactive_required=interactive_required,
        ),
        counts=PackageRunCounts(
            total_runs=baseline_valid_runs + interactive_valid_runs,
            valid_runs=baseline_valid_runs + interactive_valid_runs,
            baseline_valid_runs=baseline_valid_runs,
            interactive_valid_runs=interactive_valid_runs,
            quota_met=(
                baseline_valid_runs >= baseline_required
                and interactive_valid_runs >= interactive_required
            ),
            extra_valid_runs=0,
        ),
        latest_recent=None,
        latest_valid=None,
        queue_action="baseline",
        queue_reason=None,
        live_build_drift=False,
        db_active_sessions=0,
        db_historical_sessions=0,
        historical_valid_local=0,
        historical_build_count=0,
        historical_pcap_count=0,
        extra_valid_local=0,
        suggested_default_key="1",
        suggested_is_interactive=False,
        scripted_template_ready=scripted_template_ready,
        can_reset=False,
    )


def patch_guided_run_context(
    monkeypatch,
    *,
    package_name: str,
    display_name: str | None,
    lineage_context: dict[str, Any] | None = None,
    active_device: dict[str, Any] | None | object = UNSET,
    selected_device: tuple[str, str] = DEFAULT_SELECTED_DEVICE,
    preflight_result: bool = True,
    patch_static_drift_detector: bool = True,
) -> None:
    if patch_static_drift_detector:
        monkeypatch.setattr(guided_run, "_detect_static_plan_build_drift", lambda **_k: None)
    monkeypatch.setattr(
        guided_run,
        "_load_db_dynamic_lineage_context",
        lambda _pkg: {} if lineage_context is None else dict(lineage_context),
    )
    monkeypatch.setattr(guided_run, "active_research_cohort_label", lambda: DEFAULT_COHORT_LABEL)
    monkeypatch.setattr(guided_run, "_print_paper_mode_constants", lambda: None)
    monkeypatch.setattr(
        guided_run,
        "group_artifacts",
        lambda: [SimpleNamespace(package_name=package_name, display_name=display_name)],
    )
    monkeypatch.setattr(guided_run, "active_research_cohort_packages", lambda: (package_name,))
    monkeypatch.setattr(guided_run, "select_device", lambda: selected_device)
    monkeypatch.setattr(guided_run, "_device_preflight_checks", lambda _serial: preflight_result)
    monkeypatch.setattr(guided_run.menu_utils, "render_menu", lambda _spec: None)
    if active_device is not UNSET:
        monkeypatch.setattr(guided_run.device_manager, "get_active_device", lambda: active_device)


def one_shot_package_selector(package_name: str):
    calls = {"count": 0}

    def _select_package(_groups, title, subtitle=None):
        del title, subtitle
        calls["count"] += 1
        if calls["count"] == 1:
            return package_name
        return None

    return calls, _select_package
