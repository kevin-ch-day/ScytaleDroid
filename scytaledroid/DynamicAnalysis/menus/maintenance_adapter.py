"""Maintenance action adapters for Dynamic Analysis menu wiring."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from scytaledroid.DynamicAnalysis.menus.maintenance_actions import (
    DynamicMaintenanceCallbacks,
    LegacyStructuralCallbacks,
    legacy_structural_archive_menu as _legacy_structural_archive_menu_impl,
    prune_incomplete_dynamic_evidence_dirs as _prune_incomplete_dynamic_evidence_dirs_impl,
    repair_reindex_tracker as _repair_reindex_tracker_impl,
    run_freeze_readiness_audit_action as _run_freeze_readiness_audit_action,
    run_state_summary_action as _run_state_summary_action,
    verify_host_pcap_tools_action as _verify_host_pcap_tools_action,
)
from scytaledroid.Utils.DisplayUtils import prompt_utils


def read_json(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def legacy_structural_archive_menu(
    *,
    run_guided_capture: Callable[[], None],
    show_runbook: Callable[[], None],
    show_recapture_plan: Callable[[], None],
    show_status_dashboard: Callable[[], None],
    show_integrity_gates: Callable[[], None],
    build_manifest: Callable[[], None],
    pause_if_verbose: Callable[[], None],
) -> None:
    _legacy_structural_archive_menu_impl(
        callbacks=LegacyStructuralCallbacks(
            run_guided_capture=run_guided_capture,
            show_runbook=show_runbook,
            show_recapture_plan=show_recapture_plan,
            show_status_dashboard=show_status_dashboard,
            show_integrity_gates=show_integrity_gates,
            build_manifest=build_manifest,
        ),
        pause_if_verbose=pause_if_verbose,
    )


def prune_incomplete_dynamic_evidence_dirs(*, run_state_summary: Callable[[], None]) -> None:
    _prune_incomplete_dynamic_evidence_dirs_impl(run_state_summary=run_state_summary)


def repair_reindex_tracker(
    *,
    run_state_summary: Callable[[], None],
    min_windows_per_run: Callable[[], int],
    summarize_evidence_quota: Callable[[set[str], object], dict[str, int | bool]],
    read_json_fn: Callable[[Path], dict | None] = read_json,
) -> None:
    _repair_reindex_tracker_impl(
        callbacks=DynamicMaintenanceCallbacks(
            run_state_summary=run_state_summary,
            read_json=read_json_fn,
            min_windows_per_run=min_windows_per_run,
            summarize_evidence_quota=summarize_evidence_quota,
        )
    )


def run_freeze_readiness_audit() -> None:
    _run_freeze_readiness_audit_action()


def run_state_summary() -> None:
    _run_state_summary_action()


def verify_host_pcap_tools() -> None:
    _verify_host_pcap_tools_action()


def run_cohort_security_audit_export(*, run_export_impl: Callable[..., None]) -> None:
    include_hidden = prompt_utils.prompt_yes_no(
        "Also export hidden-pattern bridge candidates?",
        default=False,
    )
    run_export_impl(include_hidden_patterns=include_hidden)
