"""Guided cohort run controller."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.adb import shell as adb_shell
from scytaledroid.DeviceAnalysis import device_manager
from scytaledroid.DynamicAnalysis.controllers.device_select import (
    get_device_selection_details,
    select_device,
)
from scytaledroid.DynamicAnalysis.controllers import guided_run_capture as _guided_run_capture
from scytaledroid.DynamicAnalysis.controllers import guided_run_messaging as _guided_run_messaging
from scytaledroid.DynamicAnalysis.controllers import selected_app_actions as _selected_app_actions
from scytaledroid.DynamicAnalysis.controllers import selected_app_review as _selected_app_review
from scytaledroid.DynamicAnalysis.controllers import selected_app_state as _selected_app_state
from scytaledroid.DynamicAnalysis.controllers.guided_run_checks import (
    device_preflight_checks as _device_preflight_checks_impl,
    extract_version_code_details_from_dump as _extract_version_code_details_from_dump_impl,
    post_run_integrity_check as _post_run_integrity_check_impl,
    pre_run_scientific_checks as _pre_run_scientific_checks_impl,
    read_observed_signer_set_hash as _read_observed_signer_set_hash_impl,
    read_observed_version_code_details as _read_observed_version_code_details_impl,
)
from scytaledroid.DynamicAnalysis.core.run_specs import build_dynamic_run_spec
from scytaledroid.DynamicAnalysis.core.target_manager import extract_version_code_from_dump
from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import (
    MESSAGING_PACKAGES,
)
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.pcap.tools import collect_host_tools, missing_required_tools
from scytaledroid.DynamicAnalysis.plan_selection import (
    ensure_plan_or_error,
    print_plan_selection_banner,
)
from scytaledroid.DynamicAnalysis.research_cohort_runtime import (
    active_research_cohort_label,
    active_research_cohort_packages,
)
from scytaledroid.DynamicAnalysis.run_dynamic_analysis import execute_dynamic_run_spec
from scytaledroid.DynamicAnalysis.run_summary import print_run_summary
from scytaledroid.DynamicAnalysis.scenarios.manual import preview_script_template_for_package
from scytaledroid.DynamicAnalysis.services.dataset_run_state import load_dataset_run_state
from scytaledroid.DynamicAnalysis.templates.category_map import (
    category_for_package,
    resolved_template_for_package,
)
from scytaledroid.DynamicAnalysis.utils.path_utils import resolve_evidence_path
from scytaledroid.DynamicAnalysis.utils.run_cleanup import (
    delete_dynamic_evidence_packs,
    find_dynamic_run_dirs,
    recent_tracker_runs,
    reset_package_dataset_tracker,
)
from scytaledroid.StaticAnalysis.core.repository import group_artifacts, load_display_name_map
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

_BATTERY_WARN_PCT = 30
_BATTERY_BLOCK_PCT = 20
_STORAGE_BLOCK_GB = 1.5
_CLOCK_WARN_S = 5
_CLOCK_BLOCK_S = 30
_STABILIZATION_WAIT_S = 15
_META_FAMILY_PACKAGES = {
    "com.facebook.katana",
    "com.facebook.orca",
    "com.instagram.android",
    "com.whatsapp",
}

_QUEUE_ACTION_NONE = "none"
_QUEUE_ACTION_REVIEW_QA = "review_qa"
_QUEUE_ACTION_RESTORE_LOCAL = "restore_local_evidence"
_QUEUE_ACTION_REFRESH = "refresh"
_QUEUE_ACTION_BASELINE = "baseline"
_QUEUE_ACTION_SCRIPTED = "scripted_interaction"
_QUEUE_ACTION_MANUAL = "manual_interaction"


def _normalize_dynamic_app_display_label(display_label: str | None, package_name: str) -> str:
    text = str(display_label or "").strip() or str(package_name or "").strip()
    pkg_lc = str(package_name or "").strip().lower()
    if pkg_lc == "com.twitter.android" and text.strip().lower() == "x":
        return "X (Twitter)"
    return text


@dataclass(frozen=True)
class _SelectedAppContext:
    package_name: str
    display_label: str
    meta_family_note: bool
    has_identity_mismatch: bool
    state: Any
    cfg: Any
    counts: Any
    latest_recent: Any
    latest_valid: bool | None
    queue_action: str
    queue_reason: str | None
    db_active_sessions: int
    db_historical_sessions: int
    historical_valid_local: int
    historical_build_count: int
    extra_valid_local: int
    suggested_default_key: str
    suggested_is_interactive: bool
    scripted_template_ready: bool
    can_reset: bool


@dataclass(frozen=True)
class _SelectedAppAction:
    app: _SelectedAppContext
    selected_protocol: str


@dataclass(frozen=True)
class _SelectedAppStateSnapshot:
    build: str
    evidence: str
    qa: str
    need: str
    action: str
    quota: str


def _queue_action_key(action: str | None) -> str:
    text = str(action or "").strip().lower()
    if not text or text == "—":
        return _QUEUE_ACTION_NONE
    if text == "review qa":
        return _QUEUE_ACTION_REVIEW_QA
    if text == "restore local evidence":
        return _QUEUE_ACTION_RESTORE_LOCAL
    if text == "refresh":
        return _QUEUE_ACTION_REFRESH
    if text == "baseline":
        return _QUEUE_ACTION_BASELINE
    if text == "scripted interaction":
        return _QUEUE_ACTION_SCRIPTED
    if text == "manual interaction":
        return _QUEUE_ACTION_MANUAL
    return text.replace(" ", "_")


def _with_selected_app_display(app: _SelectedAppContext, *, package_name: str, display_label: str) -> _SelectedAppContext:
    return replace(
        app,
        display_label=display_label,
        meta_family_note=bool(str(package_name or "").strip().lower() in _META_FAMILY_PACKAGES),
    )


def _selected_app_active_valid_runs(app: _SelectedAppContext) -> int:
    return int(app.counts.baseline_valid_runs) + int(app.counts.interactive_valid_runs)


def _initial_device_context() -> dict[str, str | None]:
    try:
        active = device_manager.get_active_device()
    except Exception:
        active = None
    if not isinstance(active, dict):
        return {"serial": None, "label": None}
    serial = str(active.get("serial") or "").strip()
    if not serial:
        return {"serial": None, "label": None}
    try:
        label = device_manager.describe_device(active)
    except Exception:
        label = serial
    return {"serial": serial, "label": label}


def _load_db_dynamic_lineage_context(package_name: str) -> dict[str, int]:
    pkg_lc = str(package_name or "").strip().lower()
    if not pkg_lc:
        return {}
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_scripts import package_lineage_read_model as lineage
        from scytaledroid.DynamicAnalysis.tracker_scope import resolve_active_package_identity
    except Exception:
        return {}

    base_rows = [
        row
        for row in (lineage.fetch_base_rows(core_q, package_name=pkg_lc) or [])
        if str(row.get("package_name") or "").strip().lower() == pkg_lc
    ]
    dynamic_by_hash = lineage.fetch_dynamic_coverage(core_q)
    active_vc, active_sha = resolve_active_package_identity(pkg_lc)
    active_vc = str(active_vc or "").strip()
    active_sha = str(active_sha or "").strip().lower()

    out = {
        "db_active_sessions": 0,
        "db_historical_sessions": 0,
        "db_total_sessions": 0,
    }
    for row in base_rows:
        sha = str(row.get("base_apk_sha256") or "").strip().lower()
        if not sha:
            continue
        dynamic_sessions = int((dynamic_by_hash.get(sha) or {}).get("dynamic_sessions") or 0)
        if dynamic_sessions <= 0:
            continue
        version_code = str(row.get("version_code") or "").strip()
        is_active = sha == active_sha if active_sha else (version_code == active_vc if active_vc else False)
        out["db_total_sessions"] += dynamic_sessions
        if is_active:
            out["db_active_sessions"] += dynamic_sessions
        else:
            out["db_historical_sessions"] += dynamic_sessions
    return out


def _selected_app_lineage_state(
    *,
    active_valid_runs: int,
    legacy_valid_runs: int,
    db_active_sessions: int,
    db_historical_sessions: int,
) -> str:
    if int(active_valid_runs) > 0:
        return "current_build_observed"
    if int(db_active_sessions) > 0:
        return "current_build_db_only"
    if int(legacy_valid_runs) > 0:
        return "historical_local_only"
    if int(db_historical_sessions) > 0:
        return "historical_db_only"
    return "no_evidence_anywhere"


def _print_selected_app_evidence_context(
    *,
    package_name: str,
    active_valid_runs: int,
    legacy_valid_runs: int,
    historical_build_count: int,
    db_active_sessions: int,
    db_historical_sessions: int,
    include_why: bool = True,
) -> None:
    state = _selected_app_lineage_state(
        active_valid_runs=active_valid_runs,
        legacy_valid_runs=legacy_valid_runs,
        db_active_sessions=db_active_sessions,
        db_historical_sessions=db_historical_sessions,
    )
    if int(legacy_valid_runs) > 0:
        build_text = (
            f" across {historical_build_count} older build(s)"
            if historical_build_count > 0
            else ""
        )
        print(
            status_messages.status(
                f"Historical evidence: {legacy_valid_runs} legacy valid run(s){build_text} retained for comparison; not counted toward current quota.",
                level="info",
            )
        )
    if not include_why:
        return
    if state == "current_build_db_only":
        print()
        print("Why:")
        print("Current-build evidence exists in the DB, but the local evidence pack is missing in this workspace.")
        print("Restore the local evidence pack if available, or recollect the current build.")
        return
    if state == "historical_local_only":
        print()
        print("Why:")
        print("Historical evidence exists locally, but current-build evidence is still missing for this app.")
        print("Baseline collection should target the installed build.")
        return
    if state == "historical_db_only":
        print()
        print("Why:")
        print("Historical DB-only evidence exists, but no current-build evidence pack is present in this workspace.")
        print("Collect baseline evidence for the installed build.")
        return
    if state == "no_evidence_anywhere":
        print()
        print("Why:")
        print(f"No dynamic evidence exists yet for {package_name}.")
        print("This run will establish the first current-build baseline.")


def _selected_app_queue_action(
    *,
    baseline_valid_runs: int,
    interactive_valid_runs: int,
    baseline_required: int,
    interactive_required: int,
    scripted_template_ready: bool,
    latest_valid: bool | None,
    latest_invalid_reason: str | None,
    db_active_sessions: int,
    active_valid_runs: int,
) -> tuple[str, str | None]:
    return _selected_app_state.selected_app_queue_action(
        baseline_valid_runs=baseline_valid_runs,
        interactive_valid_runs=interactive_valid_runs,
        baseline_required=baseline_required,
        interactive_required=interactive_required,
        scripted_template_ready=scripted_template_ready,
        latest_valid=latest_valid,
        latest_invalid_reason=latest_invalid_reason,
        db_active_sessions=db_active_sessions,
        active_valid_runs=active_valid_runs,
    )

def _render_selected_app_review(
    *,
    display_label: str,
    latest_recent: Any,
    print_tier1_qa_result: Callable[[str], None] | None = None,
) -> None:
    _selected_app_review.render_selected_app_review(
        display_label=display_label,
        latest_recent=latest_recent,
        print_tier1_qa_result=print_tier1_qa_result,
        menu_utils=menu_utils,
        status_messages=status_messages,
        run_profile_label_fn=_run_profile_label,
    )


def _render_selected_app_recent_runs(state: Any) -> None:
    _selected_app_review.render_selected_app_recent_runs(
        state,
        menu_utils=menu_utils,
        status_messages=status_messages,
        run_profile_label_fn=_run_profile_label,
    )


def _render_selected_app_diagnostics(
    *,
    package_name: str,
    display_label: str,
    state: Any,
    queue_action: str,
    db_active_sessions: int,
    db_historical_sessions: int,
) -> None:
    _selected_app_review.render_selected_app_diagnostics(
        package_name=package_name,
        display_label=display_label,
        state=state,
        queue_action=queue_action,
        db_active_sessions=db_active_sessions,
        db_historical_sessions=db_historical_sessions,
        menu_utils=menu_utils,
    )


def _selected_app_build_label(
    *,
    active_valid_runs: int,
    legacy_valid_runs: int,
    db_active_sessions: int,
    db_historical_sessions: int,
) -> str:
    return _selected_app_state.selected_app_build_label(
        active_valid_runs=active_valid_runs,
        legacy_valid_runs=legacy_valid_runs,
        db_active_sessions=db_active_sessions,
        db_historical_sessions=db_historical_sessions,
    )


def _selected_app_evidence_label(lineage_state: str) -> str:
    return _selected_app_state.selected_app_evidence_label(lineage_state)


def _selected_app_qa_badge(latest_valid: bool | None) -> str:
    return _selected_app_state.selected_app_qa_badge(latest_valid)


def _selected_app_need_label(
    *,
    queue_action: str,
    baseline_valid_runs: int,
    interactive_valid_runs: int,
    baseline_required: int,
    interactive_required: int,
) -> str:
    return _selected_app_state.selected_app_need_label(
        queue_action=queue_action,
        baseline_valid_runs=baseline_valid_runs,
        interactive_valid_runs=interactive_valid_runs,
        baseline_required=baseline_required,
        interactive_required=interactive_required,
        queue_action_key_fn=_queue_action_key,
        queue_action_review_qa=_QUEUE_ACTION_REVIEW_QA,
        queue_action_restore_local=_QUEUE_ACTION_RESTORE_LOCAL,
        queue_action_refresh=_QUEUE_ACTION_REFRESH,
        queue_action_baseline=_QUEUE_ACTION_BASELINE,
        queue_action_manual=_QUEUE_ACTION_MANUAL,
        queue_action_scripted=_QUEUE_ACTION_SCRIPTED,
    )


def _selected_app_action_label(queue_action: str) -> str:
    return _selected_app_state.selected_app_action_label(
        queue_action,
        queue_action_key_fn=_queue_action_key,
        queue_action_review_qa=_QUEUE_ACTION_REVIEW_QA,
        queue_action_restore_local=_QUEUE_ACTION_RESTORE_LOCAL,
        queue_action_refresh=_QUEUE_ACTION_REFRESH,
        queue_action_baseline=_QUEUE_ACTION_BASELINE,
        queue_action_manual=_QUEUE_ACTION_MANUAL,
        queue_action_scripted=_QUEUE_ACTION_SCRIPTED,
    )


def _selected_app_quota_label(
    *,
    baseline_valid_runs: int,
    interactive_valid_runs: int,
    baseline_required: int,
    interactive_required: int,
    extra_valid_runs: int,
) -> str:
    return _selected_app_state.selected_app_quota_label(
        baseline_valid_runs=baseline_valid_runs,
        interactive_valid_runs=interactive_valid_runs,
        baseline_required=baseline_required,
        interactive_required=interactive_required,
        extra_valid_runs=extra_valid_runs,
    )


def _selected_app_state_snapshot(
    *,
    lineage_state: str,
    active_valid_runs: int,
    legacy_valid_runs: int,
    db_active_sessions: int,
    db_historical_sessions: int,
    latest_valid: bool | None,
    queue_action: str,
    baseline_valid_runs: int,
    interactive_valid_runs: int,
    baseline_required: int,
    interactive_required: int,
    extra_valid_runs: int,
) -> _SelectedAppStateSnapshot:
    snapshot = _selected_app_state.selected_app_state_snapshot(
        lineage_state=lineage_state,
        active_valid_runs=active_valid_runs,
        legacy_valid_runs=legacy_valid_runs,
        db_active_sessions=db_active_sessions,
        db_historical_sessions=db_historical_sessions,
        latest_valid=latest_valid,
        queue_action=queue_action,
        baseline_valid_runs=baseline_valid_runs,
        interactive_valid_runs=interactive_valid_runs,
        baseline_required=baseline_required,
        interactive_required=interactive_required,
        extra_valid_runs=extra_valid_runs,
        queue_action_key_fn=_queue_action_key,
        queue_action_review_qa=_QUEUE_ACTION_REVIEW_QA,
        queue_action_restore_local=_QUEUE_ACTION_RESTORE_LOCAL,
        queue_action_refresh=_QUEUE_ACTION_REFRESH,
        queue_action_baseline=_QUEUE_ACTION_BASELINE,
        queue_action_manual=_QUEUE_ACTION_MANUAL,
        queue_action_scripted=_QUEUE_ACTION_SCRIPTED,
    )
    return _SelectedAppStateSnapshot(**snapshot.__dict__)

def _select_guided_dataset_package(
    *,
    scoped_groups: tuple[Any, ...],
    groups: list[Any],
    cohort_label: str,
    device_ctx: dict[str, str | None],
    select_package_from_groups: Callable[[object, str], str | None],
) -> tuple[str, str] | None:
    queue_device_serial = str(device_ctx.get("serial") or "").strip() or None
    queue_device_label = str(device_ctx.get("label") or "").strip() or "not selected"
    try:
        package_name = select_package_from_groups(
            scoped_groups,
            title=f"App Queue — {cohort_label}",
            subtitle=f"Device: {queue_device_label}",
            device_serial=queue_device_serial,
        )
    except TypeError:
        package_name = select_package_from_groups(
            scoped_groups,
            title=f"App Queue — {cohort_label}",
            subtitle=f"Device: {queue_device_label}",
        )
    if not package_name:
        return None
    display_label = _resolve_package_display_label(groups, package_name)
    return str(package_name), str(display_label)


def _resolve_package_display_label(groups: list[Any], package_name: str) -> str:
    pkg_lc = str(package_name or "").strip().lower()
    if not pkg_lc:
        return str(package_name or "").strip() or package_name
    try:
        display_map = {
            str(g.package_name or "").strip().lower(): str(g.display_name or "").strip()
            for g in groups
            if getattr(g, "package_name", None)
        }
        display_label = display_map.get(pkg_lc) or ""
        if display_label:
            return _normalize_dynamic_app_display_label(display_label, package_name)
    except Exception:
        pass
    try:
        db_map = load_display_name_map(groups)
    except Exception:
        db_map = {}
    display_label = str(db_map.get(pkg_lc) or "").strip()
    if display_label:
        return _normalize_dynamic_app_display_label(display_label, package_name)
    return _normalize_dynamic_app_display_label(str(package_name or "").strip() or package_name, package_name)


def _plan_drift_rows(plan_drift: dict[str, Any], *, detailed_installed_build: bool) -> list[list[str]]:
    return _guided_run_capture.plan_drift_rows(
        plan_drift,
        detailed_installed_build=detailed_installed_build,
    )


def _print_plan_drift_warning(plan_drift: dict[str, Any]) -> None:
    _guided_run_capture.print_plan_drift_warning(
        plan_drift,
        status_messages=status_messages,
    )


def _print_plan_drift_blocked_message(plan_drift: dict[str, Any]) -> None:
    _guided_run_capture.print_plan_drift_blocked_message(
        plan_drift,
        status_messages=status_messages,
    )


def _render_static_plan_build_drift_block(*, display_label: str, plan_drift: dict[str, Any]) -> None:
    _guided_run_capture.render_static_plan_build_drift_block(
        display_label=display_label,
        plan_drift=plan_drift,
        menu_utils=menu_utils,
        status_messages=status_messages,
    )


def _render_selected_app_drift_workbench(
    *,
    app: _SelectedAppContext,
    plan_drift: dict[str, Any],
) -> None:
    _guided_run_capture.render_selected_app_drift_workbench(
        app=app,
        plan_drift=plan_drift,
        menu_utils=menu_utils,
        prompt_utils=prompt_utils,
        status_messages=status_messages,
        selected_app_active_valid_runs_fn=_selected_app_active_valid_runs,
        print_selected_app_evidence_context_fn=_print_selected_app_evidence_context,
        selected_app_lineage_state_fn=_selected_app_lineage_state,
        selected_app_state_snapshot_fn=_selected_app_state_snapshot,
        render_selected_app_recent_runs_fn=_render_selected_app_recent_runs,
        render_selected_app_diagnostics_fn=_render_selected_app_diagnostics,
    )


def _load_selected_app_context(
    *,
    package_name: str,
) -> _SelectedAppContext:
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig

    cfg = DatasetTrackerConfig()
    state = load_dataset_run_state(package_name, config=cfg)
    counts = state.counts
    scripted_template_ready = _scripted_template_available(package_name)
    suggested_profile = (
        state.effective_suggested_profile
        or str(getattr(cfg, "interactive_profile", "") or "interaction_manual")
    ).strip()
    suggested_slot = state.suggested_slot
    extra_valid_local = int(counts.extra_valid_runs)
    historical_valid_local = int(state.historical_valid_runs)
    historical_build_count = int(state.historical_build_count)
    db_lineage_context = _load_db_dynamic_lineage_context(package_name)
    db_active_sessions = int(db_lineage_context.get("db_active_sessions") or 0)
    db_historical_sessions = int(db_lineage_context.get("db_historical_sessions") or 0)
    if int(counts.baseline_valid_runs) < int(cfg.baseline_required):
        suggested_profile = _canonical_baseline_profile_for_package(package_name)
        suggested_slot = max(1, min(int(counts.baseline_valid_runs) + 1, int(cfg.baseline_required)))
    if counts.quota_met:
        suggested_slot = None

    suggested_is_interactive = _is_interactive_profile(suggested_profile)
    suggested_default_key = _suggested_menu_key(suggested_profile)
    latest_recent = _selected_app_latest_recent_summary(package_name=package_name, state=state)
    latest_valid = getattr(latest_recent, "valid", None)
    queue_action, queue_reason = _selected_app_queue_action(
        baseline_valid_runs=int(counts.baseline_valid_runs),
        interactive_valid_runs=int(counts.interactive_valid_runs),
        baseline_required=int(cfg.baseline_required),
        interactive_required=int(cfg.interactive_required),
        scripted_template_ready=scripted_template_ready,
        latest_valid=latest_valid,
        latest_invalid_reason=getattr(latest_recent, "invalid_reason_code", None),
        db_active_sessions=db_active_sessions,
        active_valid_runs=int(counts.baseline_valid_runs) + int(counts.interactive_valid_runs),
    )
    return _SelectedAppContext(
        package_name=package_name,
        display_label=package_name,
        meta_family_note=bool(str(package_name or "").strip().lower() in _META_FAMILY_PACKAGES),
        has_identity_mismatch=_selected_app_has_identity_mismatch(
            package_name=package_name,
            latest_recent=latest_recent,
            cfg=cfg,
        ),
        state=state,
        cfg=cfg,
        counts=counts,
        latest_recent=latest_recent,
        latest_valid=latest_valid,
        queue_action=queue_action,
        queue_reason=queue_reason,
        db_active_sessions=db_active_sessions,
        db_historical_sessions=db_historical_sessions,
        historical_valid_local=historical_valid_local,
        historical_build_count=historical_build_count,
        extra_valid_local=extra_valid_local,
        suggested_default_key=suggested_default_key,
        suggested_is_interactive=suggested_is_interactive,
        scripted_template_ready=scripted_template_ready,
        can_reset=bool(state.reset_available),
    )


def _selected_app_latest_recent_summary(*, package_name: str, state: Any) -> Any:
    fallback = state.recent_runs[0] if getattr(state, "recent_runs", ()) else None
    recent = recent_tracker_runs(package_name, limit=1)
    if recent:
        row = recent[0]
        valid = getattr(row, "valid", None)
        invalid_reason = str(getattr(row, "invalid_reason_code", "") or "").strip() or None
        if valid is True:
            status_label = "VALID"
        elif valid is False:
            status_label = f"INVALID:{invalid_reason or 'UNKNOWN'}"
        else:
            status_label = "UNKNOWN"
        tracker_summary = SimpleNamespace(
            ended_at=getattr(row, "ended_at", None),
            run_profile=getattr(row, "run_profile", None),
            interaction_level=getattr(row, "interaction_level", None),
            messaging_activity=getattr(row, "messaging_activity", None),
            valid=valid,
            invalid_reason_code=invalid_reason,
            low_signal=getattr(row, "low_signal", None),
            run_id=str(getattr(row, "run_id", "") or ""),
            status_label=status_label,
        )
        if fallback is None:
            return tracker_summary
        tracker_run_id = str(getattr(tracker_summary, "run_id", "") or "").strip()
        fallback_run_id = str(getattr(fallback, "run_id", "") or "").strip()
        tracker_ended = str(getattr(tracker_summary, "ended_at", "") or "").strip()
        fallback_ended = str(getattr(fallback, "ended_at", "") or "").strip()
        if tracker_run_id and fallback_run_id and tracker_run_id == fallback_run_id:
            return tracker_summary
        if tracker_ended and fallback_ended and tracker_ended > fallback_ended:
            return tracker_summary
    return fallback


def _selected_app_has_identity_mismatch(
    *,
    package_name: str,
    latest_recent: Any,
    cfg: Any,
) -> bool:
    if getattr(latest_recent, "valid", None) is not True:
        return False
    try:
        from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker

        tracker = load_dataset_tracker()
        apps = tracker.get("apps") if isinstance(tracker, dict) else {}
        entry = apps.get(str(package_name or "").strip().lower()) if isinstance(apps, dict) else None
        runs = entry.get("runs") if isinstance(entry, dict) else None
        if not isinstance(runs, list):
            return False
        recent_row = next(
            (
                row
                for row in runs
                if isinstance(row, dict)
                and str(row.get("run_id") or "").strip() == str(getattr(latest_recent, "run_id", "") or "").strip()
            ),
            None,
        )
        if not isinstance(recent_row, dict):
            return False
        scoped = _build_scoped_dataset_counts_shared(
            package_name,
            runs,
            cfg=cfg,
            resolve_tracker_run_identity_fn=_resolve_tracker_run_identity_shared,
        )
        active_ident = (
            str(scoped.get("active_version_code") or "").strip() or None,
            str(scoped.get("active_base_sha") or "").strip().lower() or None,
        )
        if not (active_ident[0] or active_ident[1]):
            return False
        recent_ident = _resolve_tracker_run_identity_shared(package_name, recent_row)
        return recent_ident != active_ident
    except Exception:
        return False


def _is_messaging_package_or_category(package_name: str) -> bool:
    return _guided_run_messaging.is_messaging_package_or_category(
        package_name,
        category_lookup=category_for_package,
        messaging_packages=MESSAGING_PACKAGES,
    )


def _canonical_baseline_profile_for_package(package_name: str) -> str:
    return _guided_run_messaging.canonical_baseline_profile_for_package(
        package_name,
        is_messaging_package_or_category_fn=_is_messaging_package_or_category,
    )


def _is_messaging_connected_baseline(
    *,
    package_name: str,
    run_profile: str,
    messaging_activity: str | None,
) -> bool:
    return _guided_run_messaging.is_messaging_connected_baseline(
        package_name=package_name,
        run_profile=run_profile,
        messaging_activity=messaging_activity,
        is_messaging_package_or_category_fn=_is_messaging_package_or_category,
    )


def _messaging_baseline_connected_insufficient_duration_streak(
    recent_runs: list[Any],
    *,
    package_name: str,
) -> int:
    return _guided_run_messaging.messaging_baseline_connected_insufficient_duration_streak(
        recent_runs,
        package_name=package_name,
        is_messaging_package_or_category_fn=_is_messaging_package_or_category,
    )


def _intent_counts_toward_quota(
    *,
    run_profile: str,
    baseline_valid_runs: int,
    interactive_valid_runs: int,
    cfg: Any,
) -> bool:
    profile = str(run_profile or "").strip().lower()
    if profile.startswith("baseline"):
        return int(baseline_valid_runs) < int(cfg.baseline_required)
    if profile.startswith("interaction_") or "interactive" in profile:
        return (
            int(baseline_valid_runs) >= int(cfg.baseline_required)
            and int(interactive_valid_runs) < int(cfg.interactive_required)
        )
    return False


def _is_interactive_profile(profile: str) -> bool:
    p = str(profile or "").strip().lower()
    return ("interaction" in p) or ("interactive" in p) or ("script" in p)


def _apply_messaging_baseline_countability_policy(
    *,
    package_name: str,
    run_profile: str,
    messaging_activity: str | None,
    counts_toward_completion: bool,
) -> tuple[bool, str | None]:
    """Messaging baseline policy: baseline is baseline_connected by default."""
    return _guided_run_messaging.apply_messaging_baseline_countability_policy(
        package_name=package_name,
        run_profile=run_profile,
        messaging_activity=messaging_activity,
        counts_toward_completion=counts_toward_completion,
        is_messaging_package_or_category_fn=_is_messaging_package_or_category,
    )


def _prompt_messaging_baseline_setup() -> str:
    return _guided_run_messaging.prompt_messaging_baseline_setup(
        menu_utils=menu_utils,
        prompt_utils=prompt_utils,
    )


def _print_paper_mode_constants() -> None:
    try:
        import numpy as _np

        numpy_version = str(getattr(_np, "__version__", "unknown"))
    except Exception:
        numpy_version = "unknown"
    try:
        import sklearn as _sk

        sklearn_version = str(getattr(_sk, "__version__", "unknown"))
    except Exception:
        sklearn_version = "unknown"

    # Default operator UX: keep this compact. Full parameter tables are available
    # on demand to avoid drowning operators in static boilerplate.
    menu_utils.print_section("ML Parameters (Locked)")
    rows = [
        ("Window size", f"{int(profile_config.WINDOW_SIZE_S)}s"),
        ("Stride", f"{int(profile_config.WINDOW_STRIDE_S)}s"),
        ("Min sampling time", f"{int(getattr(profile_config, 'MIN_SAMPLING_SECONDS', 180))}s"),
        ("Recommended time", f"{int(getattr(profile_config, 'RECOMMENDED_SAMPLING_SECONDS', 240))}s"),
        ("Percentile threshold", f"{int(profile_config.THRESHOLD_PERCENTILE)}"),
        ("Percentile method", str(getattr(profile_config, "NP_PERCENTILE_METHOD", "linear"))),
        ("Min PCAP bytes", f"{int(profile_config.MIN_PCAP_BYTES)}"),
        ("Models", "Isolation Forest + OC-SVM"),
        ("Baseline-only training", "YES"),
        ("NumPy version", numpy_version),
        ("scikit-learn version", sklearn_version),
    ]
    compact = (
        str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower() not in {"debug", "details"}
    )
    if compact:
        line = (
            f"Window={int(profile_config.WINDOW_SIZE_S)}s/{int(profile_config.WINDOW_STRIDE_S)}s | "
            f"Min={int(getattr(profile_config, 'MIN_SAMPLING_SECONDS', 180))}s | "
            f"Rec={int(getattr(profile_config, 'RECOMMENDED_SAMPLING_SECONDS', 240))}s | "
            f"MinPCAP={int(profile_config.MIN_PCAP_BYTES)} | "
            f"Models=IF+OCSVM | Baseline-only=YES"
        )
        print(status_messages.status(line, level="info"))
        # Keep guided collection fast: no extra prompt here. Operators can switch to
        # SCYTALEDROID_UI_LEVEL=details/debug for full tables.
        return
    menu_utils.print_table(["Parameter", "Value"], rows)


def _build_selected_app_protocol_options(app: _SelectedAppContext) -> list[menu_utils.MenuOption]:
    return _selected_app_actions.build_selected_app_protocol_options(
        app,
        menu_utils=menu_utils,
        queue_action_key_fn=_queue_action_key,
        is_messaging_package_or_category_fn=_is_messaging_package_or_category,
        queue_action_review_qa=_QUEUE_ACTION_REVIEW_QA,
        queue_action_restore_local=_QUEUE_ACTION_RESTORE_LOCAL,
    )


def _print_selected_app_workbench_summary(app: _SelectedAppContext) -> None:
    _selected_app_actions.print_selected_app_workbench_summary(
        app,
        status_messages=status_messages,
        selected_app_active_valid_runs_fn=_selected_app_active_valid_runs,
        print_selected_app_evidence_context_fn=_print_selected_app_evidence_context,
        is_messaging_package_or_category_fn=_is_messaging_package_or_category,
    )


def _handle_selected_app_aux_action(
    *,
    selected_protocol: str,
    app: _SelectedAppContext,
    print_tier1_qa_result: Callable[[str], None] | None,
) -> str | None:
    return _selected_app_actions.handle_selected_app_aux_action(
        selected_protocol=selected_protocol,
        app=app,
        print_tier1_qa_result=print_tier1_qa_result,
        prompt_utils=prompt_utils,
        status_messages=status_messages,
        menu_utils=menu_utils,
        render_selected_app_review_fn=_render_selected_app_review,
        render_selected_app_recent_runs_fn=_render_selected_app_recent_runs,
        render_selected_app_diagnostics_fn=_render_selected_app_diagnostics,
    )


def _render_selected_app_workbench(
    *,
    app: _SelectedAppContext,
    print_tier1_qa_result: Callable[[str], None] | None,
) -> str:
    return _selected_app_actions.render_selected_app_workbench(
        app=app,
        print_tier1_qa_result=print_tier1_qa_result,
        menu_utils=menu_utils,
        prompt_utils=prompt_utils,
        queue_action_key_fn=_queue_action_key,
        queue_action_review_qa=_QUEUE_ACTION_REVIEW_QA,
        build_selected_app_protocol_options_fn=_build_selected_app_protocol_options,
        print_selected_app_workbench_summary_fn=_print_selected_app_workbench_summary,
        handle_selected_app_aux_action_fn=_handle_selected_app_aux_action,
    )


def _select_guided_dataset_action(
    *,
    cohort_label: str,
    device_ctx: dict[str, str | None],
    groups: list[Any],
    scoped_groups: tuple[Any, ...],
    select_package_from_groups: Callable[[object, str], str | None],
    print_tier1_qa_result: Callable[[str], None] | None = None,
) -> _SelectedAppAction | None:
    selected = _select_guided_dataset_package(
        scoped_groups=scoped_groups,
        groups=groups,
        cohort_label=cohort_label,
        device_ctx=device_ctx,
        select_package_from_groups=select_package_from_groups,
    )
    if selected is None:
        return None
    package_name, display_label = selected
    print(status_messages.status(f"Selected app: {display_label}", level="info"))
    if display_label != package_name:
        print(status_messages.status(f"Package: {package_name}", level="info"))

    queue_device_serial = str(device_ctx.get("serial") or "").strip() or None
    plan_drift = (
        _detect_static_plan_build_drift(
            device_serial=queue_device_serial,
            package_name=package_name,
        )
        if queue_device_serial
        else None
    )
    if plan_drift is not None:
        selected_app = _with_selected_app_display(
            _load_selected_app_context(package_name=package_name),
            package_name=package_name,
            display_label=display_label,
        )
        print()
        _render_selected_app_drift_workbench(app=selected_app, plan_drift=plan_drift)
        return _SelectedAppAction(
            app=selected_app,
            selected_protocol="0",
        )

    app = _with_selected_app_display(
        _load_selected_app_context(package_name=package_name),
        package_name=package_name,
        display_label=display_label,
    )
    selected_protocol = _render_selected_app_workbench(
        app=app,
        print_tier1_qa_result=print_tier1_qa_result,
    )
    return _SelectedAppAction(app=app, selected_protocol=selected_protocol)


def _load_plan_identity(plan_path: str) -> dict[str, str]:
    payload = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    run_identity = (
        payload.get("run_identity")
        if isinstance(payload, dict) and isinstance(payload.get("run_identity"), dict)
        else {}
    )
    return {
        "package_name_lc": str(
            run_identity.get("package_name_lc") or payload.get("package_name") or ""
        ).strip().lower(),
        "version_code": str(
            run_identity.get("version_code") or payload.get("version_code") or ""
        ).strip(),
        "base_apk_sha256": str(run_identity.get("base_apk_sha256") or "").strip().lower(),
        "artifact_set_hash": str(run_identity.get("artifact_set_hash") or "").strip().lower(),
        "signer_set_hash": str(
            run_identity.get("signer_set_hash") or run_identity.get("signer_digest") or ""
        ).strip().lower(),
    }


def _detect_static_plan_build_drift(
    *,
    device_serial: str,
    package_name: str,
) -> dict[str, str] | None:
    """Return static-plan/device build drift details when dataset mode is already blocked.

    This is a fast-fail UX probe for cohort/freeze workflows. It intentionally
    reuses the same version-code identity rules as the later scientific checks,
    but runs before the operator spends time choosing intent/observers.
    """

    plan_selection = ensure_plan_or_error(
        package_name,
        prompt_run_static=False,
        deterministic=True,
        run_static_callback=None,
    )
    if not plan_selection:
        return None
    try:
        plan_identity = _load_plan_identity(str(plan_selection.get("plan_path") or ""))
    except Exception:
        return None
    expected_vc = str(plan_identity.get("version_code") or plan_selection.get("version_code") or "").strip()
    if not expected_vc:
        return None
    observed_details = _read_observed_version_code_details(device_serial, package_name)
    observed_vc = str(observed_details.get("version_code") or "").strip()
    if not observed_vc or observed_vc == expected_vc:
        return None
    return {
        "plan_path": str(plan_selection.get("plan_path") or ""),
        "static_run_id": str(plan_selection.get("static_run_id") or ""),
        "expected_version_code": expected_vc,
        "expected_version_name": str(plan_selection.get("version_name") or "").strip(),
        "observed_version_code": observed_vc,
        "observed_command": str(observed_details.get("command") or "").strip(),
        "observed_pattern": str(observed_details.get("pattern") or "").strip(),
        "observed_line": str(observed_details.get("matched_line") or "").strip(),
    }


def _known_signer_hash(value: object) -> str:
    text = str(value or "").strip().lower()
    if text in {"", "unknown", "none", "null"}:
        return ""
    return text


def _progress_label(count: int, required: int, *, noun: str = "needed") -> str:
    count_i = max(0, int(count))
    required_i = max(0, int(required))
    missing = max(0, required_i - count_i)
    if missing == 0:
        return f"{count_i}/{required_i} complete"
    return f"{count_i}/{required_i} need {missing}"


def _run_profile_label(run_profile: str | None) -> str:
    profile = str(run_profile or "").strip().lower()
    if profile == "baseline_idle" or "baseline" in profile or "idle" in profile:
        return "baseline"
    if profile == "interaction_scripted":
        return "scripted interaction"
    if profile == "interaction_manual":
        return "manual interaction"
    return str(run_profile or "interaction").strip() or "interaction"


def _interactive_phase_label(cfg: Any) -> str:
    profile = str(getattr(cfg, "interactive_profile", "") or "").strip().lower()
    if profile == "interaction_manual":
        return "Manual runs"
    return "Interactive runs"


def _scripted_template_available(package_name: str) -> bool:
    return bool(resolved_template_for_package(package_name))


def _suggested_menu_key(run_profile: str | None) -> str:
    profile = str(run_profile or "").strip().lower()
    if profile.startswith("baseline"):
        return "1"
    if profile == "interaction_scripted":
        return "2"
    if profile == "interaction_manual":
        return "3"
    return "1"


def _read_battery_level(device_serial: str) -> int | None:
    out = adb_shell.run_shell(device_serial, ["dumpsys", "battery"])
    m = re.search(r"level:\s*(\d+)", out)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def _read_storage_free_gb(device_serial: str) -> float | None:
    out = adb_shell.run_shell(device_serial, ["df", "-k", "/data"])
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if len(lines) < 2:
        return None
    parts = lines[-1].split()
    if len(parts) < 4:
        return None
    try:
        avail_kb = int(parts[3])
        return round(avail_kb / (1024 * 1024), 2)
    except Exception:
        return None


def _read_clock_drift_seconds(device_serial: str) -> float | None:
    out = adb_shell.run_shell(device_serial, ["date", "+%s"]).strip()
    try:
        device_epoch = int(out)
    except Exception:
        return None
    host_epoch = int(datetime.now(UTC).timestamp())
    return float(abs(host_epoch - device_epoch))


def _read_vpn_state(device_serial: str) -> str:
    out = adb_shell.run_shell(device_serial, ["dumpsys", "connectivity"]).lower()
    if "not_vpn" in out or "not vpn" in out:
        return "not_vpn"
    if "vpn" in out:
        return "vpn"
    return "unknown"


def _extract_route_interface(route_output: str) -> str | None:
    for line in route_output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Common forms:
        # - default via 192.168.1.1 dev wlan0
        # - 10.0.0.0/8 dev rmnet_data0 scope link
        if " dev " not in line:
            continue
        m = re.search(r"\bdev\s+(\S+)", line)
        if not m:
            continue
        iface = m.group(1).strip()
        if iface and iface not in {"lo"}:
            return iface
    return None


def _read_capture_interface(device_serial: str) -> str | None:
    # 1) Route-based detection (preferred).
    for cmd in (
        ["ip", "route"],
        ["ip", "-o", "route", "show"],
        ["ip", "route", "show", "table", "all"],
        ["/system/bin/ip", "route"],
    ):
        try:
            out = adb_shell.run_shell(device_serial, cmd)
        except Exception:
            out = ""
        iface = _extract_route_interface(out or "")
        if iface:
            return iface

    # 2) Connectivity service fallback.
    try:
        conn = adb_shell.run_shell(device_serial, ["dumpsys", "connectivity"])
    except Exception:
        conn = ""
    for pattern in (
        r"\binterfaceName[:=]\s*([a-zA-Z0-9_.:-]+)",
        r"\bIface[:=]\s*([a-zA-Z0-9_.:-]+)",
    ):
        m = re.search(pattern, conn or "", flags=re.IGNORECASE)
        if m:
            iface = m.group(1).strip()
            if iface and iface != "lo":
                return iface

    # 3) Property fallback for OEM/network stacks.
    for prop in ("wifi.interface", "vendor.wifi.interface", "persist.vendor.wifi.interface"):
        try:
            val = adb_shell.run_shell(device_serial, ["getprop", prop]).strip()
        except Exception:
            val = ""
        if val and val != "[]":
            return val
    return None


def _read_observed_version_code(device_serial: str, package_name: str) -> str | None:
    details = _read_observed_version_code_details(device_serial, package_name)
    return details.get("version_code")


def _read_observed_version_code_details(device_serial: str, package_name: str) -> dict[str, str]:
    return _read_observed_version_code_details_impl(
        device_serial,
        package_name,
        run_shell_fn=adb_shell.run_shell,
        extract_details_fn=_extract_version_code_details_from_dump,
    )


def _extract_version_code_from_dump(dump: str, package_name: str) -> str | None:
    return extract_version_code_from_dump(dump, package_name)


def _extract_version_code_details_from_dump(dump: str, package_name: str) -> dict[str, str]:
    return _extract_version_code_details_from_dump_impl(dump, package_name)


def _read_observed_signer_set_hash(device_serial: str, package_name: str) -> str | None:
    return _read_observed_signer_set_hash_impl(
        device_serial,
        package_name,
        run_shell_fn=adb_shell.run_shell,
    )


def _pre_run_scientific_checks(
    *,
    device_serial: str,
    package_name: str,
    plan_path: str,
    observer_ids: list[str],
) -> bool:
    return _pre_run_scientific_checks_impl(
        device_serial=device_serial,
        package_name=package_name,
        plan_path=plan_path,
        observer_ids=observer_ids,
        data_dir=app_config.DATA_DIR,
        battery_block_pct=_BATTERY_BLOCK_PCT,
        battery_warn_pct=_BATTERY_WARN_PCT,
        storage_block_gb=_STORAGE_BLOCK_GB,
        clock_block_s=_CLOCK_BLOCK_S,
        clock_warn_s=_CLOCK_WARN_S,
        missing_required_tools_fn=missing_required_tools,
        read_capture_interface_fn=_read_capture_interface,
        read_vpn_state_fn=_read_vpn_state,
        read_battery_level_fn=_read_battery_level,
        read_storage_free_gb_fn=_read_storage_free_gb,
        read_clock_drift_seconds_fn=_read_clock_drift_seconds,
        load_plan_identity_fn=_load_plan_identity,
        read_observed_version_code_details_fn=_read_observed_version_code_details,
        known_signer_hash_fn=_known_signer_hash,
        read_observed_signer_set_hash_fn=_read_observed_signer_set_hash,
    )


def _device_preflight_checks(device_serial: str) -> bool:
    return _device_preflight_checks_impl(
        device_serial,
        data_dir=app_config.DATA_DIR,
        battery_block_pct=_BATTERY_BLOCK_PCT,
        battery_warn_pct=_BATTERY_WARN_PCT,
        storage_block_gb=_STORAGE_BLOCK_GB,
        clock_block_s=_CLOCK_BLOCK_S,
        clock_warn_s=_CLOCK_WARN_S,
        ui_level=str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower(),
        missing_required_tools_fn=missing_required_tools,
        read_capture_interface_fn=_read_capture_interface,
        read_vpn_state_fn=_read_vpn_state,
        read_battery_level_fn=_read_battery_level,
        read_storage_free_gb_fn=_read_storage_free_gb,
        read_clock_drift_seconds_fn=_read_clock_drift_seconds,
    )


def _post_run_integrity_check(result) -> None:
    _post_run_integrity_check_impl(
        result,
        min_pcap_bytes=int(profile_config.MIN_PCAP_BYTES),
        min_windows=int(getattr(profile_config, "MIN_WINDOWS_PER_RUN", 20)),
        ui_level=str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower(),
    )


def _prepare_selected_app_capture(
    *,
    app: _SelectedAppContext,
    device_ctx: dict[str, str | None],
    print_device_badge: Callable[[str, str], None],
) -> tuple[str, str] | None:
    return _guided_run_capture.prepare_selected_app_capture(
        app=app,
        device_ctx=device_ctx,
        print_device_badge=print_device_badge,
        menu_utils=menu_utils,
        prompt_utils=prompt_utils,
        status_messages=status_messages,
        print_paper_mode_constants_fn=_print_paper_mode_constants,
        choose_capture_device_fn=_choose_capture_device,
        device_preflight_checks_fn=_device_preflight_checks,
        detect_static_plan_build_drift_fn=_detect_static_plan_build_drift,
        render_selected_app_drift_workbench_fn=_render_selected_app_drift_workbench,
    )


def _print_capture_device_choice(
    *,
    details: dict[str, str],
    detected: bool,
) -> None:
    _guided_run_capture.print_capture_device_choice(
        details=details,
        detected=detected,
        menu_utils=menu_utils,
        status_messages=status_messages,
    )


def _choose_capture_device(device_ctx: dict[str, str | None]) -> tuple[str, str] | None:
    return _guided_run_capture.choose_capture_device(
        device_ctx,
        get_device_selection_details_fn=get_device_selection_details,
        select_device_fn=select_device,
        menu_utils=menu_utils,
        prompt_utils=prompt_utils,
        status_messages=status_messages,
    )


def _auto_run_static_for_package(package_name: str) -> bool:
    """Dataset-mode helper: run static analysis quietly to produce a dynamic plan.

    This is non-interactive and intended only to unblock dataset collection.
    """

    from scytaledroid.DeviceAnalysis.services import artifact_store
    from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
    from scytaledroid.StaticAnalysis.cli.core.run_specs import build_static_run_spec
    from scytaledroid.StaticAnalysis.cli.flows.run_dispatch import execute_run_spec
    from scytaledroid.StaticAnalysis.session import make_session_stamp, normalize_session_stamp

    groups = group_artifacts()
    group = next((g for g in groups if (g.package_name or "").lower() == package_name.lower()), None)
    if not group:
        print(status_messages.status("No APK artifacts found locally for this package.", level="error"))
        return False

    session_stamp = normalize_session_stamp(f"{make_session_stamp()}-{group.package_name}")
    selection = ScopeSelection(scope="app", label=group.package_name, groups=(group,))
    params = RunParameters(
        profile="full",
        scope=selection.scope,
        scope_label=selection.label,
        session_stamp=session_stamp,
        show_split_summaries=False,
        # Noninteractive run: never prompt on collisions.
        canonical_action="append",
    )
    buffer_out = io.StringIO()
    buffer_err = io.StringIO()
    with contextlib.redirect_stdout(buffer_out), contextlib.redirect_stderr(buffer_err):
        spec = build_static_run_spec(
            selection=selection,
            params=params,
            base_dir=artifact_store.analysis_apk_root(),
            run_mode="batch",
            quiet=True,
            noninteractive=True,
        )
        execute_run_spec(spec)
    return True


def run_guided_dataset_run(
    *,
    select_package_from_groups: Callable[[object, str], str | None],
    select_observers: Callable[[str, str], list[str]],
    print_device_badge: Callable[[str, str], None],
    print_tier1_qa_result: Callable[[str], None] | None = None,
    observer_prompts_enabled: bool = False,
    pcapdroid_api_key: str | None = None,
) -> None:
    cohort_label = active_research_cohort_label()
    device_ctx: dict[str, str | None] = _initial_device_context()

    while True:
        keep_running = _run_guided_dataset_iteration(
            cohort_label=cohort_label,
            device_ctx=device_ctx,
            select_package_from_groups=select_package_from_groups,
            select_observers=select_observers,
            print_device_badge=print_device_badge,
            print_tier1_qa_result=print_tier1_qa_result,
            observer_prompts_enabled=observer_prompts_enabled,
            pcapdroid_api_key=pcapdroid_api_key,
        )
        if not keep_running:
            return


def _run_guided_dataset_iteration(
    *,
    cohort_label: str,
    device_ctx: dict[str, str | None],
    select_package_from_groups: Callable[[object, str], str | None],
    select_observers: Callable[[str, str], list[str]],
    print_device_badge: Callable[[str, str], None],
    print_tier1_qa_result: Callable[[str], None] | None = None,
    observer_prompts_enabled: bool = False,
    pcapdroid_api_key: str | None = None,
) -> bool:
    scenario_id = "basic_usage"
    duration_seconds = 0
    label = "Cohort"

    groups = group_artifacts()
    dataset_pkgs = {pkg.lower() for pkg in active_research_cohort_packages()}
    if not dataset_pkgs:
        print(status_messages.status(f"{cohort_label} has no apps.", level="warn"))
        return False

    available = {group.package_name.lower() for group in groups if group.package_name}
    scoped_groups = tuple(
        group
        for group in groups
        if group.package_name
        and group.package_name.lower() in available.intersection(dataset_pkgs)
    )
    if not scoped_groups:
        print(
            status_messages.status(
                f"No APK artifacts available for {cohort_label}. Execute Harvest or use Custom package name.",
                level="warn",
            )
        )
        return False

    selection = _select_guided_dataset_action(
        cohort_label=cohort_label,
        device_ctx=device_ctx,
        groups=groups,
        scoped_groups=scoped_groups,
        select_package_from_groups=select_package_from_groups,
        print_tier1_qa_result=print_tier1_qa_result,
    )
    if selection is None:
        return False
    app = selection.app
    selected_protocol = selection.selected_protocol
    package_name = app.package_name
    display_label = app.display_label
    state = app.state
    cfg = app.cfg
    counts = app.counts
    if selected_protocol == "0":
        return True
    if selected_protocol == "X":
        local = find_dynamic_run_dirs(package_name)
        print(
            status_messages.status(
                f"Local dynamic runs for {package_name}: {len(local)} evidence pack(s).",
                level="warn",
            )
        )
        if not local:
            print(
                status_messages.status(
                    "Delete is blocked: local evidence packs are missing in this workspace. Resetting tracker-only state is unsafe in freeze/profile mode.",
                    level="error",
                )
            )
            prompt_utils.press_enter_to_continue()
            return True
        confirmed = prompt_utils.prompt_yes_no(
            f"Delete local evidence packs AND reset dataset tracker entry for {package_name}?",
            default=False,
        )
        if not confirmed:
            return True
        deleted = delete_dynamic_evidence_packs(package_name)
        reset_package_dataset_tracker(package_name)
        remaining = len(find_dynamic_run_dirs(package_name))
        print(
            status_messages.status(
                f"Deleted {deleted} evidence pack(s). Remaining={remaining}. Tracker entry reset.",
                level="info",
            )
        )
        prompt_utils.press_enter_to_continue()
        return True
    if selected_protocol == "4":
        # Preflight-only test: do not capture or write evidence packs.
        missing = missing_required_tools(tier="dataset")
        tools = collect_host_tools()
        if missing:
            print(
                status_messages.status(
                    f"Preflight FAIL: missing host tools: {', '.join(missing)}",
                    level="error",
                )
            )
        else:
            print(status_messages.status("Preflight OK: host tools present.", level="success"))
        print(status_messages.status(f"Host tools: {tools}", level="info"))
        # Also ensure a plan exists (offer to run static once, as normal).
        plan_selection = ensure_plan_or_error(
            package_name,
            prompt_run_static=True,
            deterministic=True,
            run_static_callback=_auto_run_static_for_package,
        )
        if plan_selection:
            print(status_messages.status(f"Plan OK: {plan_selection['plan_path']}", level="success"))
        mapped = resolved_template_for_package(package_name)
        if mapped:
            try:
                template_id, steps = preview_script_template_for_package(package_name=package_name)
                print()
                menu_utils.print_section("Dry Run Script Preview")
                print(status_messages.status(f"Template: {template_id}", level="info"))
                rows = [[str(i), sid, str(sexp)] for i, (sid, _sdesc, sexp) in enumerate(steps, start=1)]
                menu_utils.print_table(["#", "Step ID", "Expected (s)"], rows)
                print(status_messages.status("Dry run validates plan/tools only; no capture or saving is performed.", level="info"))
            except Exception as exc:
                print(status_messages.status(f"Template preview unavailable: {exc}", level="warn"))
        prompt_utils.press_enter_to_continue()
        return True

    if selected_protocol in {"1", "2", "3"}:
        prepared = _prepare_selected_app_capture(
            app=app,
            device_ctx=device_ctx,
            print_device_badge=print_device_badge,
        )
        if not prepared:
            return True
        device_serial, _device_label = prepared

    # Capture modes.
    tier = "dataset"
    if selected_protocol == "1":
        run_profile = _canonical_baseline_profile_for_package(package_name)
        interaction_level = "minimal"
    elif selected_protocol == "2":
        run_profile = "interaction_scripted"
        interaction_level = "scripted"
    else:
        run_profile = "interaction_manual"
        interaction_level = "manual"
    if (
        selected_protocol in {"2", "3"}
        and int(counts.baseline_valid_runs) < int(cfg.baseline_required)
    ):
        print(
            status_messages.status(
                "Baseline requirement is not complete: "
                f"{counts.baseline_valid_runs}/{cfg.baseline_required} valid baseline runs.",
                level="warn",
            )
        )
        print(status_messages.status("Recommended next run is baseline.", level="warn"))
        if not prompt_utils.prompt_yes_no("Proceed with interaction anyway?", default=False):
            return True
    counts_toward_completion = _intent_counts_toward_quota(
        run_profile=run_profile,
        baseline_valid_runs=int(counts.baseline_valid_runs),
        interactive_valid_runs=int(counts.interactive_valid_runs),
        cfg=cfg,
    )
    suggested_key = app.suggested_default_key if app.suggested_is_interactive else "1"
    if selected_protocol in {"1", "2", "3"} and selected_protocol != suggested_key and not counts_toward_completion:
        print(
            status_messages.status(
                "Selected intent is not quota-suggested and will be saved as supplemental evidence (not quota-counted).",
                level="warn",
            )
        )
        proceed = prompt_utils.prompt_yes_no("Proceed with supplemental run anyway?", default=False)
        if not proceed:
            print(status_messages.status("Run canceled. Choose the suggested intent to fill quota.", level="info"))
            return True

    # Manual runs can be quota-counted (by policy), so do not gate behind an
    # "EXPLORATORY" confirmation.
    messaging_activity: str | None = None
    if _is_messaging_package_or_category(package_name):
        # PM lock: messaging activity is a tag describing what happened. In manual mode, it
        # must never affect countability. In scripted mode, it selects a deterministic
        # template (template policy then determines cohort eligibility).
        if str(run_profile or "").strip().lower().startswith("baseline"):
            # Keep baseline deterministic: messaging baselines are baseline_connected and the
            # activity is "connected_idle" by definition. Do not offer a menu that can
            # accidentally select known-low-signal "home idle" baselines.
            messaging_activity = "connected_idle"
        else:
            print()
            menu_utils.print_header("Messaging Activity (Tag)")
            messaging_options = [
                menu_utils.MenuOption("1", "Idle", description="browse thread/list surfaces; no sending/calls/media"),
                menu_utils.MenuOption(
                    "2",
                    "Text",
                    description="send 2 fixed text messages (no media). Use Meta AI/Saved/Note-to-self if needed.",
                ),
                menu_utils.MenuOption("3", "Voice Call", description="start call; if connected hold ~90s; end call"),
                menu_utils.MenuOption("4", "Video Call", description="start video call; if connected hold ~90s; end call"),
                menu_utils.MenuOption("5", "Mixed", description="text + call (exploratory-only; non-cohort)"),
            ]
            menu_utils.render_menu(
                menu_utils.MenuSpec(
                    items=messaging_options,
                    default="2" if str(run_profile or "").strip().lower() == "interaction_scripted" else "1",
                    exit_label=None,
                    show_exit=False,
                    show_descriptions=True,
                    compact=True,
                )
            )
            valid_choices = menu_utils.selectable_keys(messaging_options, include_exit=False)
            choice = prompt_utils.get_choice(
                valid_choices,
                default="2" if str(run_profile or "").strip().lower() == "interaction_scripted" else "1",
                invalid_message=f"Choose {valid_choices[0]}-{valid_choices[-1]}.",
                disabled=[option.key for option in messaging_options if option.disabled],
            )
            messaging_activity = {
                "1": "idle",
                "2": "text_only",
                "3": "voice_call",
                "4": "video_call",
                "5": "mixed",
            }[choice]
    else:
        # Non-messaging apps: leave unset so downstream can distinguish "not applicable" vs "none".
        messaging_activity = None

    counts_toward_completion, policy_reason = _apply_messaging_baseline_countability_policy(
        package_name=package_name,
        run_profile=run_profile,
        messaging_activity=messaging_activity,
        counts_toward_completion=counts_toward_completion,
    )
    if policy_reason == "MESSAGING_BASELINE_NONE_EXPLORATORY" or _is_messaging_connected_baseline(
        package_name=package_name,
        run_profile=run_profile,
        messaging_activity=messaging_activity,
    ):
        baseline_setup = _prompt_messaging_baseline_setup()
        if baseline_setup == "1":
            messaging_activity = "connected_idle"
            run_profile = "baseline_connected"
            counts_toward_completion = _intent_counts_toward_quota(
                run_profile=run_profile,
                baseline_valid_runs=int(counts.baseline_valid_runs),
                interactive_valid_runs=int(counts.interactive_valid_runs),
                cfg=cfg,
            )
            print(status_messages.status("Using messaging connected-idle baseline behavior.", level="info"))
        elif baseline_setup == "2":
            run_profile = "interaction_manual"
            interaction_level = "manual"
            messaging_activity = "none"
            counts_toward_completion = _intent_counts_toward_quota(
                run_profile=run_profile,
                baseline_valid_runs=int(counts.baseline_valid_runs),
                interactive_valid_runs=int(counts.interactive_valid_runs),
                cfg=cfg,
            )
            print(status_messages.status("Switched to manual interaction.", level="info"))
        else:
            print(
                status_messages.status(
                    "Run canceled. Start again when the app is ready for a connected-idle baseline or choose manual interaction.",
                    level="info",
                )
            )
            return True

    # Template policy determines scripted countability (messaging activity is only a tag).
    if _is_messaging_package_or_category(package_name) and str(run_profile or "").strip().lower() == "interaction_scripted":
        try:
            tmpl_id, _steps = preview_script_template_for_package(
                package_name=str(package_name or "").strip().lower(),
                messaging_activity=str(messaging_activity or "").strip().lower(),
            )
            print(status_messages.status(f"Script template selected: {tmpl_id}", level="info"))
            if str(tmpl_id) == "messaging_call_basic_v1":
                print(
                    status_messages.status(
                        "Template policy: Mixed/call template is exploratory-only (will NOT count toward paper quota).",
                        level="warn",
                    )
                )
                counts_toward_completion = False
        except Exception:
            # If preview fails, keep behavior unchanged; capture can still proceed and will
            # be evaluated evidence-first post-run.
            pass

    # Operator-facing paper quota impact label (avoid generic "countable" wording).
    prof_lc = str(run_profile or "").strip().lower()
    if counts_toward_completion:
        paper_impact_label = "Cohort quota impact: YES (if VALID)"
    else:
        paper_impact_label = "Cohort quota impact: NO (supplemental evidence / policy)"

    print(
        paper_impact_label
    )

    print()
    menu_utils.print_header("Dynamic Run Observers")
    observer_ids = select_observers(device_serial, mode="guided")

    if not observer_ids:
        print(status_messages.status("Select at least one observer.", level="error"))
        return True

    # Dataset mode is deterministic about plan choice, but interactive about gating:
    # if no plan exists yet, offer a single prompt to run static now.
    plan_selection = ensure_plan_or_error(
        package_name,
        prompt_run_static=True,
        deterministic=True,
        run_static_callback=_auto_run_static_for_package,
    )
    if not plan_selection:
        return True
    plan_path = plan_selection["plan_path"]
    static_run_id = plan_selection["static_run_id"]
    print_plan_selection_banner(plan_selection)
    if not _pre_run_scientific_checks(
        device_serial=device_serial,
        package_name=package_name,
        plan_path=plan_path,
        observer_ids=observer_ids,
    ):
        prompt_utils.press_enter_to_continue()
        return True
    print(status_messages.status(f"Stabilizing environment ({_STABILIZATION_WAIT_S}s)...", level="info"))
    time.sleep(_STABILIZATION_WAIT_S)
    clear_logcat = prompt_utils.prompt_yes_no("Clear logcat at run start?", default=True)
    if run_profile == "interaction_scripted":
        mapped = resolved_template_for_package(package_name)
        if not mapped:
            print(
                status_messages.status(
                    f"BLOCKED_UNKNOWN_CATEGORY: no scripted template mapping for {package_name} in freeze/profile mode.",
                    level="error",
                )
            )
            prompt_utils.press_enter_to_continue()
            return True

    spec = build_dynamic_run_spec(
        package_name=package_name,
        device_serial=device_serial,
        observer_ids=tuple(observer_ids),
        scenario_id=scenario_id,
        tier=tier,
        duration_seconds=duration_seconds,
        plan_path=plan_path,
        static_run_id=static_run_id,
        clear_logcat=clear_logcat,
        interactive=True,
        # Dataset tier is strict; exploratory runs are allowed to proceed with best-effort
        # schema/persistence while still producing an evidence pack.
        require_dynamic_schema=(tier == "dataset"),
        observer_prompts_enabled=bool(observer_prompts_enabled),
        pcapdroid_api_key=pcapdroid_api_key,
        run_profile=run_profile,
        interaction_level=interaction_level,
        messaging_activity=messaging_activity,
        counts_toward_completion=counts_toward_completion,
    )
    result = execute_dynamic_run_spec(spec)
    print_run_summary(result, label)
    _post_run_integrity_check(result)
    if result.dynamic_run_id and print_tier1_qa_result:
        print_tier1_qa_result(result.dynamic_run_id)
    _capture_protocol_fit_feedback(result=result, run_profile=run_profile, package_name=package_name)
    return True


def _capture_protocol_fit_feedback(*, result, run_profile: str, package_name: str | None) -> None:
    if run_profile != "interaction_scripted":
        return
    if not result or str(getattr(result, "status", "")).lower() != "success":
        return
    run_id = str(getattr(result, "dynamic_run_id", "") or "").strip()
    if not run_id:
        return
    print()
    menu_utils.print_header("Protocol Fit (Optional)")
    fit_options = [
        menu_utils.MenuOption("1", "Great", description="Steps matched app flow well."),
        menu_utils.MenuOption("2", "Okay", description="Mostly good; minor mismatch."),
        menu_utils.MenuOption("3", "Poor", description="Steps did not fit app well."),
    ]
    menu_utils.render_menu(
        menu_utils.MenuSpec(
            items=fit_options,
            default="2",
            show_exit=False,
            show_descriptions=True,
            compact=True,
        )
    )
    fit_choice = prompt_utils.get_choice(["1", "2", "3"], default="2", invalid_message="Choose 1-3.")
    fit_label = {"1": "great", "2": "okay", "3": "poor"}.get(fit_choice, "okay")

    step_ref = ""
    replacement_note = ""
    if fit_label == "poor":
        step_ref = prompt_utils.prompt_text(
            "Which step number felt wrong? (optional, e.g., 2)",
            required=False,
        ).strip()
        replacement_note = prompt_utils.prompt_text(
            "Suggested replacement step (optional one-line note)",
            required=False,
        ).strip()
        print(
            status_messages.status(
                "Rerun recommended with the correct template/protocol before counting this app for paper cohort.",
                level="warn",
            )
        )

    # Messaging templates may legitimately send messages (text-mode templates). Only flag
    # "send" as a protocol violation when it was not expected by the selected template.
    send_detected = False

    event = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "event": "protocol_fit_feedback",
        "run_id": run_id,
        "run_profile": run_profile,
        "fit": fit_label,
        "step_ref": step_ref or None,
        "replacement_note": replacement_note or None,
        "script_protocol_send": bool(send_detected),
    }
    run_dir = resolve_evidence_path(getattr(result, "evidence_path", None)) if getattr(result, "evidence_path", None) else None
    if not run_dir:
        return
    manifest_path = Path(run_dir) / "run_manifest.json"
    events_path = Path(run_dir) / "notes" / "run_events.jsonl"
    try:
        events_path.parent.mkdir(parents=True, exist_ok=True)
        with events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    except Exception:
        return
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            operator_existing = payload.get("operator") if isinstance(payload.get("operator"), dict) else {}
            observed_template = str(operator_existing.get("template_id_actual") or operator_existing.get("template_id") or "").strip()
            is_text_template = observed_template.endswith("_text_v1") or observed_template in {"messaging_text_v1", "whatsapp_text_v1"}
            if _is_messaging_package_or_category(str(package_name or "").strip().lower()) and not is_text_template:
                send_detected = prompt_utils.prompt_yes_no(
                    "Did this scripted run send messages outside of the template steps? (protocol violation)",
                    default=False,
                )
            operator = payload.get("operator") if isinstance(payload.get("operator"), dict) else {}
            operator["protocol_fit"] = fit_label
            operator["protocol_fit_step_ref"] = step_ref or None
            operator["protocol_fit_replacement_note"] = replacement_note or None
            operator["script_protocol_send"] = bool(send_detected)
            payload["operator"] = operator
            manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    except Exception:
        pass
    print(status_messages.status("Protocol fit feedback saved.", level="info"))


__all__ = ["run_guided_dataset_run"]
