"""Dynamic analysis menu scaffolding."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Config import app_config  # noqa: F401 - re-exported for tests
from scytaledroid.DynamicAnalysis import plan_selection as _plan_selection
from scytaledroid.DynamicAnalysis.controllers.guided_run import run_guided_dataset_run
from scytaledroid.DynamicAnalysis.controllers.sandbox_run import run_sandbox_dynamic_run
from scytaledroid.DynamicAnalysis.freeze_eligibility import derive_freeze_eligibility
from scytaledroid.DynamicAnalysis.menus import maintenance_adapter as _maintenance_adapter
from scytaledroid.DynamicAnalysis.menus import (
    package_selection_adapter as _package_selection_adapter,
)
from scytaledroid.DynamicAnalysis.menus import run_target_adapter as _run_target_adapter
from scytaledroid.DynamicAnalysis.menus.archived_structural_menu import (
    print_profile_v3_capture_runbook as _print_profile_v3_capture_runbook_impl,
)
from scytaledroid.DynamicAnalysis.menus.archived_structural_menu import (
    run_profile_v3_capture_status_dashboard as _run_profile_v3_capture_status_dashboard_impl,
)
from scytaledroid.DynamicAnalysis.menus.archived_structural_menu import (
    run_profile_v3_guided_phase2_capture as _run_profile_v3_guided_phase2_capture_impl,
)
from scytaledroid.DynamicAnalysis.menus.archived_structural_menu import (
    run_profile_v3_manifest_build as _run_profile_v3_manifest_build_impl,
)
from scytaledroid.DynamicAnalysis.menus.archived_structural_menu import (
    run_profile_v3_recapture_plan_view as _run_profile_v3_recapture_plan_view_impl,
)
from scytaledroid.DynamicAnalysis.menus.capture_runtime_support import (
    print_device_badge as _print_device_badge_impl,
)
from scytaledroid.DynamicAnalysis.menus.capture_runtime_support import (
    print_network_status as _print_network_status_impl,
)
from scytaledroid.DynamicAnalysis.menus.capture_runtime_support import (
    print_root_status as _print_root_status_impl,
)
from scytaledroid.DynamicAnalysis.menus.capture_runtime_support import (
    print_tier1_qa_result as _print_tier1_qa_result_impl,
)
from scytaledroid.DynamicAnalysis.menus.capture_runtime_support import (
    select_observers as _select_observers_impl,
)
from scytaledroid.DynamicAnalysis.menus.export_actions import (
    run_cohort_security_audit_export as _run_cohort_security_audit_export_impl,
)
from scytaledroid.DynamicAnalysis.menus.maintenance_actions import (
    choose_active_research_cohort_action as _choose_active_research_cohort_action,
)
from scytaledroid.DynamicAnalysis.menus.menu_hub import (
    DynamicAnalysisMenuCallbacks,
)
from scytaledroid.DynamicAnalysis.menus.menu_hub import (
    run_dynamic_analysis_menu as _run_dynamic_analysis_menu_hub,
)
from scytaledroid.DynamicAnalysis.menus.process_guard import (
    build_dynamic_menu_code_signature as _build_dynamic_menu_code_signature_impl,
)
from scytaledroid.DynamicAnalysis.menus.process_guard import (
    warn_if_dynamic_menu_code_changed as _warn_if_dynamic_menu_code_changed_impl,
)
from scytaledroid.DynamicAnalysis.menus.queue_metrics import (
    summarize_evidence_quota as _summarize_evidence_quota_impl,
)
from scytaledroid.DynamicAnalysis.menus.queue_selection import (
    PreparedPackageSelectionRow as _PreparedPackageSelectionRow,
)
from scytaledroid.DynamicAnalysis.menus.queue_selection import (
    PreparedPackageSelectionView as _PreparedPackageSelectionView,
)
from scytaledroid.DynamicAnalysis.menus.queue_selection import (
    build_package_selection_row as _build_package_selection_row_impl,
)
from scytaledroid.DynamicAnalysis.menus.queue_selection import (
    build_scoped_dataset_counts as _build_scoped_dataset_counts_impl,
)
from scytaledroid.DynamicAnalysis.menus.queue_selection import (
    prepare_package_selection_view as _prepare_package_selection_view_impl,
)
from scytaledroid.DynamicAnalysis.menus.queue_selection import (
    resolve_tracker_run_identity as _resolve_tracker_run_identity_impl,
)
from scytaledroid.DynamicAnalysis.menus.queue_selection import (
    run_package_selection_menu as _run_package_selection_menu_impl,
)
from scytaledroid.DynamicAnalysis.menus.run_target_selection import (
    choose_index as _choose_index_impl,
)
from scytaledroid.DynamicAnalysis.menus.run_target_selection import (
    prompt_custom_package as _prompt_custom_package_impl,
)
from scytaledroid.DynamicAnalysis.menus.run_target_selection import (
    resolve_custom_tier as _resolve_custom_tier_impl,
)
from scytaledroid.DynamicAnalysis.menus.run_target_selection import (
    resolve_plan_selection as _resolve_plan_selection_impl,
)
from scytaledroid.DynamicAnalysis.menus.run_target_selection import (
    select_dynamic_target as _select_dynamic_target_impl,
)
from scytaledroid.DynamicAnalysis.menus.run_target_selection import (
    select_package_from_groups as _select_package_from_groups_impl,
)
from scytaledroid.DynamicAnalysis.menus.run_target_selection import (
    select_profile_package as _select_profile_package_impl,
)
from scytaledroid.DynamicAnalysis.menus.summary_support import (
    min_windows_per_run as _min_windows_per_run_impl,
)
from scytaledroid.DynamicAnalysis.menus.summary_support import (
    next_action_from_need as _next_action_from_need_impl,
)
from scytaledroid.DynamicAnalysis.menus.summary_support import (
    run_profile_bucket as _run_profile_bucket_impl,
)
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.profile_loader import (
    load_operational_profiles,
    load_profile_packages,
)
from scytaledroid.DynamicAnalysis.research_cohort_runtime import (
    active_research_cohort_key,
    active_research_cohort_label,
    active_research_cohort_packages,
    chooseable_active_research_cohorts,
    persist_active_research_cohort_key,  # re-exported for test monkeypatch compatibility
)
from scytaledroid.DynamicAnalysis.run_qualification import (
    format_bucket_queue_label,
    format_quota_progress_label,
)
from scytaledroid.StaticAnalysis.core.repository import (
    group_artifacts,
    list_categories,
    list_packages,
)
from scytaledroid.Utils.DisplayUtils import (  # noqa: F401
    prompt_utils,
    status_messages,
    table_utils,
    text_blocks,
)

_DEVICE_STATUS_CACHE: dict[str, dict[str, str]] = {}
_RUN_IDENTITY_CACHE: dict[str, tuple[str | None, str | None]] = {}
_MENU_CODE_SIGNATURE_AT_START = _build_dynamic_menu_code_signature_impl(Path(__file__).resolve())


def _warn_if_code_changed() -> None:
    _warn_if_dynamic_menu_code_changed_impl(
        menu_file=Path(__file__).resolve(),
        start_signature=_MENU_CODE_SIGNATURE_AT_START,
    )


def _min_windows_per_run() -> int:
    return _min_windows_per_run_impl()


def _run_profile_bucket(run_profile: str) -> str:
    return _run_profile_bucket_impl(run_profile)


def _summarize_evidence_quota(dataset_pkgs: set[str], cfg) -> dict[str, int | bool]:
    return _summarize_evidence_quota_impl(
        dataset_pkgs,
        cfg,
        output_dir=app_config.OUTPUT_DIR,
        derive_freeze_eligibility_fn=derive_freeze_eligibility,
        min_windows=_min_windows_per_run(),
        required_capture_policy_version=int(profile_config.PAPER_CONTRACT_VERSION),
        run_profile_bucket_fn=_run_profile_bucket,
    )


@dataclass(frozen=True)
class _DynamicUiDefaults:
    observer_prompts_enabled: bool
    pcapdroid_api_key: str | None


def _load_dynamic_ui_defaults() -> _DynamicUiDefaults:
    # UI-layer defaults only. Execution semantics must rely on the frozen config
    # carried in DynamicSessionConfig/RunContext and recorded in run_manifest.json.
    return _DynamicUiDefaults(
        observer_prompts_enabled=(os.environ.get("SCYTALEDROID_OBSERVER_PROMPTS") == "1"),
        pcapdroid_api_key=os.environ.get("SCYTALEDROID_PCAPDROID_API_KEY"),
    )


def _print_profile_v3_capture_runbook() -> None:
    _print_profile_v3_capture_runbook_impl()


def _run_profile_v3_guided_phase2_capture() -> None:
    _run_profile_v3_guided_phase2_capture_impl(
        load_dynamic_ui_defaults_fn=_load_dynamic_ui_defaults
    )


def _run_profile_v3_manifest_build() -> None:
    _run_profile_v3_manifest_build_impl()


def _run_profile_v3_capture_status_dashboard() -> None:
    _run_profile_v3_capture_status_dashboard_impl()


def _run_profile_v3_recapture_plan_view() -> None:
    _run_profile_v3_recapture_plan_view_impl()


def _legacy_structural_archive_menu(*, pause_if_verbose) -> None:
    def _show_integrity_gates() -> None:
        try:
            from scytaledroid.Reporting.menu_actions import handle_profile_v3_integrity_gates

            handle_profile_v3_integrity_gates()
        except Exception:
            print(
                status_messages.status(
                    "Failed to open structural archive integrity gates (Reporting).", level="error"
                )
            )
            prompt_utils.press_enter_to_continue()

    _maintenance_adapter.legacy_structural_archive_menu(
        run_guided_capture=_run_profile_v3_guided_phase2_capture,
        show_runbook=_print_profile_v3_capture_runbook,
        show_recapture_plan=_run_profile_v3_recapture_plan_view,
        show_status_dashboard=_run_profile_v3_capture_status_dashboard,
        show_integrity_gates=_show_integrity_gates,
        build_manifest=_run_profile_v3_manifest_build,
        pause_if_verbose=pause_if_verbose,
    )


def dynamic_analysis_menu() -> None:
    _run_dynamic_analysis_menu_hub(
        DynamicAnalysisMenuCallbacks(
            warn_if_code_changed=_warn_if_code_changed,
            load_ui_defaults=_load_dynamic_ui_defaults,
            resolve_active_cohort_for_run=_resolve_active_cohort_for_run,
            run_guided_dataset_run=_run_guided_dataset_run,
            run_focused_app_run=_run_focused_app_run,
            run_paper_freeze_readiness=_run_paper_freeze_readiness,
            run_state_summary=_run_state_summary,
            run_freeze_readiness_audit=_run_freeze_readiness_audit,
            verify_host_pcap_tools=_verify_host_pcap_tools,
            choose_active_research_cohort=_choose_active_research_cohort,
            repair_reindex_tracker=_repair_reindex_tracker,
            prune_incomplete_dynamic_evidence_dirs=_prune_incomplete_dynamic_evidence_dirs,
            open_legacy_structural_archive=_legacy_structural_archive_menu,
            run_cohort_security_audit_export=_run_cohort_security_audit_export,
        )
    )


def _prune_incomplete_dynamic_evidence_dirs() -> None:
    _maintenance_adapter.prune_incomplete_dynamic_evidence_dirs(
        run_state_summary=_run_state_summary
    )


def _repair_reindex_tracker() -> None:
    _maintenance_adapter.repair_reindex_tracker(
        run_state_summary=_run_state_summary,
        min_windows_per_run=_min_windows_per_run,
        summarize_evidence_quota=_summarize_evidence_quota,
        read_json_fn=_maintenance_adapter.read_json,
    )


def _run_freeze_readiness_audit() -> None:
    _maintenance_adapter.run_freeze_readiness_audit()


def _run_paper_freeze_readiness() -> None:
    _maintenance_adapter.run_paper_freeze_readiness()


def _run_state_summary() -> None:
    _maintenance_adapter.run_state_summary()


def _next_action_from_need(need_baseline: int, need_interactive: int) -> str:
    return _next_action_from_need_impl(need_baseline, need_interactive)


def _quota_progress_label(
    count: int,
    required: int,
    *,
    extra_count: int = 0,
    low_signal: int = 0,
    non_idle: int = 0,
) -> str:
    return format_quota_progress_label(
        countable=int(count),
        required=int(required),
        extra=int(extra_count),
        low_signal=int(low_signal),
        non_idle=int(non_idle),
    )


def _bucket_progress_label(
    count: int,
    required: int,
    *,
    extra_count: int = 0,
    low_signal: int = 0,
    non_idle: int = 0,
    need: int = 0,
) -> str:
    return format_bucket_queue_label(
        countable=int(count),
        extra=int(extra_count),
        low_signal=int(low_signal),
        non_idle=int(non_idle),
        required=int(required),
        need=int(need),
    )


def _static_build_label(active_runs: int, legacy_valid: int) -> str:
    if active_runs > 0 and legacy_valid > 0:
        return "mixed"
    if active_runs > 0:
        return "current"
    if legacy_valid > 0:
        return "legacy"
    return "ready"


def _run_cohort_security_audit_export() -> None:
    _maintenance_adapter.run_cohort_security_audit_export(
        run_export_impl=_run_cohort_security_audit_export_impl,
    )


def _verify_host_pcap_tools() -> None:
    """Verify host toolchain required for dataset-tier PCAP post-analysis."""
    _maintenance_adapter.verify_host_pcap_tools()


def _select_dynamic_target() -> tuple[str, str] | None:
    return _run_target_adapter.select_dynamic_target(
        select_dynamic_target_fn=_select_dynamic_target_impl,
        group_artifacts_fn=group_artifacts,
        active_research_cohort_packages_fn=active_research_cohort_packages,
        active_research_cohort_label_fn=active_research_cohort_label,
        select_package_from_groups_fn=_select_package_from_groups,
        prompt_custom_package_fn=_prompt_custom_package,
        resolve_custom_tier_fn=_resolve_custom_tier,
        select_profile_package_fn=_select_profile_package,
    )


def _resolve_plan_selection(package_name: str) -> dict[str, object] | None:
    return _run_target_adapter.resolve_plan_selection(
        package_name,
        resolve_plan_selection_fn=_resolve_plan_selection_impl,
        load_plan_candidates_fn=_plan_selection._load_plan_candidates,
        prompt_missing_baseline_fn=_prompt_missing_baseline,
        pick_newest_candidate_fn=_plan_selection._pick_newest_candidate,
        build_selection_fn=_plan_selection._build_selection,
        prompt_baseline_selection_fn=_prompt_baseline_selection,
    )


def _run_guided_dataset_run(ui_defaults: _DynamicUiDefaults) -> None:
    _run_target_adapter.run_guided_dataset_run(
        ui_defaults,
        run_guided_dataset_run_fn=run_guided_dataset_run,
        select_package_from_groups_fn=_select_package_from_groups,
        select_observers_fn=lambda device_serial, mode: _select_observers_impl(
            device_serial, mode=mode
        ),
        print_device_badge_fn=_print_device_badge,
        print_tier1_qa_result_fn=_print_tier1_qa_result,
    )


def _resolve_active_cohort_for_run() -> dict[str, object] | None:
    return _run_target_adapter.resolve_active_cohort_for_run(
        active_research_cohort_key_fn=active_research_cohort_key,
        chooseable_active_research_cohorts_fn=chooseable_active_research_cohorts,
        choose_active_research_cohort_fn=_choose_active_research_cohort,
        status_messages_mod=status_messages,
    )


def _run_focused_app_run(ui_defaults: _DynamicUiDefaults) -> None:
    _run_target_adapter.run_focused_app_run(
        ui_defaults,
        run_sandbox_dynamic_run_fn=run_sandbox_dynamic_run,
        select_dynamic_target_fn=_select_dynamic_target,
        select_observers_fn=lambda device_serial, mode: _select_observers_impl(
            device_serial, mode=mode
        ),
        print_root_status_fn=_print_root_status,
        print_network_status_fn=_print_network_status,
    )


def _choose_active_research_cohort() -> None:
    return _choose_active_research_cohort_action(
        chooseable_active_research_cohorts_fn=chooseable_active_research_cohorts,
        active_research_cohort_key_fn=active_research_cohort_key,
        persist_active_research_cohort_key_fn=persist_active_research_cohort_key,
    )


def _print_tier1_qa_result(dynamic_run_id: str) -> None:
    _run_target_adapter.print_tier1_qa_result(
        dynamic_run_id,
        print_tier1_qa_result_fn=_print_tier1_qa_result_impl,
    )


def _resolve_custom_tier(package_name: str, dataset_pkgs: set[str]) -> tuple[str, str] | None:
    return _run_target_adapter.resolve_custom_tier(
        package_name,
        dataset_pkgs,
        resolve_custom_tier_fn=_resolve_custom_tier_impl,
        active_research_cohort_label_fn=active_research_cohort_label,
    )


def _select_profile_package(groups) -> tuple[str, str | None] | None:
    return _run_target_adapter.select_profile_package(
        groups,
        select_profile_package_fn=_select_profile_package_impl,
        list_categories_fn=list_categories,
        load_operational_profiles_fn=load_operational_profiles,
        load_profile_packages_fn=load_profile_packages,
        choose_index_fn=_choose_index,
        select_package_from_groups_fn=_select_package_from_groups,
    )


def _select_package_from_groups(
    groups,
    *,
    title: str,
    subtitle: str | None = None,
    device_serial: str | None = None,
) -> str | None:
    return _package_selection_adapter.select_package_from_groups(
        groups,
        select_package_from_groups_fn=_select_package_from_groups_impl,
        prepare_package_selection_view_fn=_prepare_package_selection_view,
        run_package_selection_menu_fn=_run_package_selection_menu,
        title=title,
        subtitle=subtitle,
        device_serial=device_serial,
    )


def _prepare_package_selection_view(
    groups, device_serial: str | None = None
) -> _PreparedPackageSelectionView | None:
    return _package_selection_adapter.prepare_package_selection_view(
        groups,
        prepare_package_selection_view_fn=_prepare_package_selection_view_impl,
        load_dataset_packages=active_research_cohort_packages,
        list_packages_fn=list_packages,
        summarize_evidence_quota_fn=_summarize_evidence_quota,
        build_package_selection_row_fn=_build_package_selection_row,
        device_serial=device_serial,
    )


def _build_package_selection_row(
    *,
    idx: int,
    package: str,
    app_label: str | None,
    collisions: set[str],
    dataset_pkgs: set[str],
    tracker_apps,
    cfg,
    recent_tracker_runs,
    live_build_drift=None,
    db_lineage_context=None,
) -> _PreparedPackageSelectionRow:
    return _package_selection_adapter.build_package_selection_row(
        build_package_selection_row_fn=_build_package_selection_row_impl,
        idx=idx,
        package=package,
        app_label=app_label,
        collisions=collisions,
        dataset_pkgs=dataset_pkgs,
        tracker_apps=tracker_apps,
        cfg=cfg,
        recent_tracker_runs=recent_tracker_runs,
        live_build_drift=live_build_drift,
        db_lineage_context=db_lineage_context,
        truncate_visible_fn=text_blocks.truncate_visible,
        bucket_progress_label_fn=_bucket_progress_label,
        quota_progress_label_fn=_quota_progress_label,
        static_build_label_fn=_static_build_label,
        next_action_from_need_fn=_next_action_from_need,
        build_scoped_dataset_counts_fn=_build_scoped_dataset_counts,
        resolve_tracker_run_identity_fn=_resolve_tracker_run_identity,
    )


def _run_package_selection_menu(prepared: _PreparedPackageSelectionView) -> str | None:
    return _package_selection_adapter.run_package_selection_menu(
        prepared,
        run_package_selection_menu_fn=_run_package_selection_menu_impl,
        summarize_evidence_quota_fn=_summarize_evidence_quota,
    )


def _build_scoped_dataset_counts(
    package_name: str, runs: list[dict], *, cfg: object | None = None
) -> dict[str, int | str]:
    return _package_selection_adapter.build_scoped_dataset_counts(
        package_name,
        runs,
        build_scoped_dataset_counts_fn=_build_scoped_dataset_counts_impl,
        cfg=cfg,
        resolve_tracker_run_identity_fn=_resolve_tracker_run_identity,
    )


def _resolve_tracker_run_identity(package_name: str, run: dict) -> tuple[str | None, str | None]:
    return _package_selection_adapter.resolve_tracker_run_identity(
        package_name,
        run,
        resolve_tracker_run_identity_fn=_resolve_tracker_run_identity_impl,
        run_identity_cache=_RUN_IDENTITY_CACHE,
        output_dir=app_config.OUTPUT_DIR,
    )


def _choose_index(prompt: str, total: int) -> int | None:
    return _choose_index_impl(prompt, total, get_choice_fn=prompt_utils.get_choice)


def _prompt_custom_package() -> str:
    return _prompt_custom_package_impl()


def _prompt_baseline_selection(
    package_name: str,
    candidates: list[dict[str, object]],
) -> dict[str, object] | None:
    return _plan_selection._prompt_baseline_selection(package_name, candidates)


def _prompt_missing_baseline(package_name: str, note: str | None) -> dict[str, object] | None:
    return _plan_selection._prompt_missing_baseline(package_name, note)


def _select_observers(device_serial: str, *, mode: str) -> list[str]:
    return _run_target_adapter.select_observers(
        device_serial,
        mode=mode,
        select_observers_fn=_select_observers_impl,
    )


def _print_device_badge(device_serial: str, device_label: str) -> None:
    _run_target_adapter.print_device_badge(
        device_serial,
        device_label,
        print_device_badge_fn=_print_device_badge_impl,
        device_status_cache=_DEVICE_STATUS_CACHE,
    )


def _print_root_status(device_serial: str, *, force: bool = False) -> bool:
    return _run_target_adapter.print_root_status(
        device_serial,
        print_root_status_fn=_print_root_status_impl,
        force=force,
        device_status_cache=_DEVICE_STATUS_CACHE,
    )


def _print_network_status(device_serial: str, *, force: bool = False) -> None:
    _run_target_adapter.print_network_status(
        device_serial,
        print_network_status_fn=_print_network_status_impl,
        force=force,
        device_status_cache=_DEVICE_STATUS_CACHE,
    )
