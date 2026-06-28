"""Rendering helpers for dynamic menu reports."""

from __future__ import annotations

import os
import shutil
import textwrap
from pathlib import Path

from scytaledroid.DynamicAnalysis.research_cohort_archive import (
    resolve_dataset_freeze_read_path,
    resolve_dataset_plan_read_path,
)
from scytaledroid.DynamicAnalysis.menus.environment_reports import (
    capture_environment_summary as _capture_environment_summary_impl,
    render_host_pcap_tools as _render_host_pcap_tools_impl,
)
from scytaledroid.DynamicAnalysis.menus.dataset_status_report import (
    count_tracker_runs as _count_tracker_runs_impl,
    render_dataset_status as _render_dataset_status_impl,
)
from scytaledroid.DynamicAnalysis.menus.state_summary_views import (
    render_compact_state_summary as _render_compact_state_summary_impl,
)
from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_label
from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import (
    run_freeze_readiness_audit,
)
from scytaledroid.DynamicAnalysis.tools.evidence.state_summary import build_state_summary
from scytaledroid.StaticAnalysis.core.repository import group_artifacts, load_display_name_map
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils


def _bool_text(value: object) -> str:
    return "yes" if bool(value) else "no"


def _count_tracker_runs(apps: object) -> int:
    return _count_tracker_runs_impl(apps)


def _tracker_path() -> Path:
    return resolve_dataset_plan_read_path()


def _freeze_path() -> Path:
    return resolve_dataset_freeze_read_path()


def _capture_environment_summary() -> dict[str, object]:
    return _capture_environment_summary_impl()


def run_freeze_readiness_audit_report() -> None:
    summary = run_freeze_readiness_audit()
    cohort_label = active_research_cohort_label()
    print()
    menu_utils.print_header("Freeze Readiness Audit")
    menu_utils.print_hint(
        "Check whether local dynamic evidence is technically valid and eligible for a frozen cohort export."
    )
    ui_level = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower()
    verbose = ui_level in {"details", "debug"}
    if not verbose:
        verdict = "GO" if summary.result == "GO" else "NO-GO"
        freeze_capability = "enabled" if summary.can_freeze else "blocked"
        msg = (
            f"Freeze audit={verdict} | capability={freeze_capability} | "
            f"technically_valid={summary.valid_runs} | eligible={summary.paper_eligible_runs} | "
            f"missing_window_count={summary.missing_window_count} | identity_mismatch={summary.identity_mismatch}"
        )
        level = "success" if summary.result == "GO" else "blocked"
        print(status_messages.status(msg, level=level))
        if summary.first_failing_reason:
            print(status_messages.status(f"Primary failing reason: {summary.first_failing_reason}", level="warn"))
        if "NO_EVIDENCE_PACKS_FOUND" in summary.reasons:
            print(
                status_messages.status(
                    "No dynamic evidence packs are present. This is expected after workspace cleanup; "
                    f"run cohort ({cohort_label}) first, then rerun State summary and Archive readiness.",
                    level="info",
                )
            )
        if summary.report_path:
            print(status_messages.status(f"Report: {summary.report_path}", level="info"))
        return
    rows = [
        ("Total runs", str(summary.total_runs)),
        ("Technically valid runs", str(summary.valid_runs)),
        ("Cohort-eligible runs", str(summary.paper_eligible_runs)),
        ("Freeze capability", "enabled" if summary.can_freeze else "blocked"),
        ("Primary failing reason", str(summary.first_failing_reason or "—")),
        ("Incomplete dirs (no manifest)", str(summary.missing_run_manifest_dirs)),
        ("Expected valid runs", str(summary.expected_valid_runs)),
        ("Expected total runs", str(summary.expected_total_runs)),
        ("Missing capture_policy_version", str(summary.missing_capture_policy_version)),
        ("capture_policy_version mismatch", str(summary.capture_policy_version_mismatch)),
        ("Missing signer_set_hash", str(summary.missing_signer_set_hash)),
        ("Identity mismatch", str(summary.identity_mismatch)),
        ("Missing window_count", str(summary.missing_window_count)),
        ("window_count < min", str(summary.window_count_below_min)),
        ("Canonical freeze role", str(summary.canonical_freeze_role)),
        ("Canonical freeze hash present", str(summary.canonical_freeze_contract_hash_present).lower()),
        ("Canonical freeze run IDs present", f"{summary.freeze_run_ids_present}/{summary.freeze_run_ids_total}"),
        ("Tracker runs (hint)", str(summary.tracker_runs_hint)),
        ("Static runs (hint)", str(summary.static_runs_hint)),
    ]
    table_utils.render_table(["Metric", "Count"], rows, compact=False)
    if summary.result != "GO":
        print(status_messages.status("Freeze audit result: NO-GO (freeze readiness checks failed).", level="blocked"))
    else:
        print(status_messages.status("Freeze audit result: GO (freeze readiness checks passed).", level="success"))
    if summary.reasons:
        reason_text = ", ".join(summary.reasons)
        print(status_messages.status(f"Reasons: {reason_text}", level="warn"))
    if "NO_EVIDENCE_PACKS_FOUND" in summary.reasons and summary.tracker_runs_hint > 0:
        print(
            status_messages.status(
                "Tracker contains historical runs but local evidence packs are missing. Recollect runs or repoint evidence root before freeze.",
                level="warn",
            )
        )
    if "NO_EVIDENCE_PACKS_FOUND" in summary.reasons and summary.tracker_runs_hint <= 0:
        print(
                status_messages.status(
                    "No dynamic evidence packs are present. This is expected after workspace cleanup; "
                    f"run cohort ({cohort_label}) first, then rerun State summary and Archive readiness.",
                    level="info",
                )
            )
    if summary.missing_run_manifest_dirs > 0:
        print(
            status_messages.status(
                "Incomplete dynamic evidence directories detected (missing run_manifest.json). "
                "Clean up orphan run folders before freeze.",
                level="warn",
            )
        )
    if "NO_EVIDENCE_PACKS_FOUND" in summary.reasons and summary.static_runs_hint > 0:
        print(
            status_messages.status(
                "Static evidence packs were found in this workspace, but dynamic evidence packs were not. Run dynamic collection on this host or copy dynamic evidence packs before freeze.",
                level="warn",
            )
        )
    if summary.canonical_freeze_demoted_to_legacy:
        print(
            status_messages.status(
                f"Renamed stale dataset_freeze.json -> {summary.canonical_freeze_demoted_to_legacy} (blocked from export).",
                level="warn",
            )
        )
    print(status_messages.status(f"Evidence root: {summary.evidence_root}", level="info"))
    print(status_messages.status(f"Evidence root exists: {str(summary.evidence_root_exists).lower()}", level="info"))
    print(status_messages.status(f"Runs discovered from: {summary.runs_discovered_from}", level="info"))
    print(status_messages.status(f"Report: {summary.report_path}", level="info"))


def render_dataset_status() -> None:
    _render_dataset_status_impl(
        active_research_cohort_label_fn=active_research_cohort_label,
        run_freeze_readiness_audit_fn=run_freeze_readiness_audit,
        build_state_summary_fn=build_state_summary,
        group_artifacts_fn=group_artifacts,
        load_display_name_map_fn=load_display_name_map,
        tracker_path_fn=_tracker_path,
        freeze_path_fn=_freeze_path,
    )


def build_freeze_state_payload() -> dict[str, object]:
    """Compatibility wrapper for state summary construction."""

    return build_state_summary()


def run_state_summary_report(
    *,
    summary: object,
    payload: dict[str, object],
    state_payload: dict[str, object],
    delta_rows: list[dict[str, object]],
    priorities: list[dict[str, object]],
) -> None:
    print()
    menu_utils.print_header("State Summary")
    menu_utils.print_hint(
        "Compare tracker state, evidence-pack state, exclusion reasons, and next collection priorities."
    )
    ui_level = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower()
    verbose = ui_level in {"details", "debug"}
    if not verbose:
        _render_compact_state_summary_impl(
            summary=summary,
            state_payload=state_payload,
            capture_environment_summary_fn=_capture_environment_summary,
            active_research_cohort_label_fn=active_research_cohort_label,
            tracker_path_fn=_tracker_path,
            bool_text_fn=_bool_text,
        )
        return
    rows = [
        ("CAN_FREEZE", "YES" if summary.can_freeze else "NO"),
        ("First failing reason", str(summary.first_failing_reason or "—")),
        ("Canonical freeze role", str(summary.canonical_freeze_role)),
        ("Canonical freeze hash present", str(summary.canonical_freeze_contract_hash_present).lower()),
        ("Freeze run IDs present", f"{summary.freeze_run_ids_present}/{summary.freeze_run_ids_total}"),
        ("Evidence root", str(summary.evidence_root)),
        ("Total runs", str(summary.total_runs)),
        ("Cohort-eligible runs", str(summary.paper_eligible_runs)),
    ]
    table_utils.render_table(["Metric", "Value"], rows, compact=False)

    canonical = payload.get("canonical_freeze") if isinstance(payload.get("canonical_freeze"), dict) else {}
    presence = (
        canonical.get("run_id_presence_classification")
        if isinstance(canonical.get("run_id_presence_classification"), dict)
        else {}
    )
    if presence:
        print()
        menu_utils.print_header("Freeze Run-ID Presence")
        prow = [
            ("Total IDs", str(int(presence.get("total_run_ids") or 0))),
            ("Present run dirs", str(int(presence.get("present_run_dirs") or 0))),
            ("Missing run dirs", str(int(presence.get("missing_run_dirs") or 0))),
            ("Found but incomplete", str(int(presence.get("found_but_incomplete") or 0))),
            ("Missing required files", str(int(presence.get("found_but_missing_required_files") or 0))),
            ("Found but identity mismatch", str(int(presence.get("found_but_identity_mismatch") or 0))),
        ]
        table_utils.render_table(["Category", "Count"], prow, compact=False)

    exclusion_counts = payload.get("exclusion_reason_counts") if isinstance(payload.get("exclusion_reason_counts"), dict) else {}
    if exclusion_counts:
        print()
        menu_utils.print_header("Exclusion Reasons")
        erows = [[k, str(int(v))] for k, v in sorted(exclusion_counts.items(), key=lambda kv: (-int(kv[1]), str(kv[0])))]
        table_utils.render_table(["Reason", "Count"], erows, compact=False)

    baseline_signal = (
        state_payload.get("baseline_signal_summary")
        if isinstance(state_payload.get("baseline_signal_summary"), dict)
        else {}
    )
    if baseline_signal:
        print()
        menu_utils.print_header("Baseline Signal")
        by_cat = (
            baseline_signal.get("baseline_idle_failures_by_category")
            if isinstance(baseline_signal.get("baseline_idle_failures_by_category"), dict)
            else {}
        )
        brows = [[f"baseline_idle failures ({k})", str(int(v))] for k, v in sorted(by_cat.items())]
        brows.append(
            [
                "baseline_connected successes",
                str(int(baseline_signal.get("baseline_connected_successes") or 0)),
            ]
        )
        table_utils.render_table(["Metric", "Count"], brows, compact=False)

    handoff = (
        state_payload.get("static_handoff_plan_summary")
        if isinstance(state_payload.get("static_handoff_plan_summary"), dict)
        else {}
    )
    if handoff:
        print()
        menu_utils.print_header("Static Prep")
        hrows = [
            ("Plan dir exists", str(bool(handoff.get("plan_dir_exists"))).lower()),
            ("Dynamic plan files", str(int(handoff.get("dynamic_plan_files") or 0))),
            ("Valid plan files", str(int(handoff.get("valid_plan_files") or 0))),
            ("Invalid plan files", str(int(handoff.get("invalid_plan_files") or 0))),
            (
                "Dataset apps with plan",
                f"{int(handoff.get('dataset_packages_with_plan') or 0)}/"
                f"{int(handoff.get('dataset_packages_total') or 0)}",
            ),
            ("Dataset apps missing plan", str(int(handoff.get("dataset_packages_missing_plan") or 0))),
            ("Ready for run", str(bool(handoff.get("ready_for_guided_dataset_run"))).lower()),
        ]
        table_utils.render_table(["Metric", "Value"], hrows, compact=False)
        missing_pkgs = handoff.get("missing_packages") if isinstance(handoff.get("missing_packages"), list) else []
        if missing_pkgs:
            print(status_messages.status("Missing dataset plans: " + ", ".join(str(pkg) for pkg in missing_pkgs), level="warn"))

    repeatability = (
        state_payload.get("repeatability_summary")
        if isinstance(state_payload.get("repeatability_summary"), dict)
        else {}
    )
    if repeatability:
        print()
        menu_utils.print_header("Repeatability")
        rrows = [
            ("Runs total", str(int(repeatability.get("runs_total") or 0))),
            ("Identity complete", str(int(repeatability.get("runs_identity_complete") or 0))),
            ("Static link ready", str(int(repeatability.get("runs_static_link_ready") or 0))),
            ("PCAP present", str(int(repeatability.get("runs_pcap_present") or 0))),
            ("Features present", str(int(repeatability.get("runs_features_present") or 0))),
            ("Windowing recorded", str(int(repeatability.get("runs_windowing_recorded") or 0))),
            ("Threshold present", str(int(repeatability.get("runs_threshold_present") or 0))),
            ("RDI ready", str(int(repeatability.get("runs_rdi_ready") or 0))),
            ("Freeze stamped", str(int(repeatability.get("runs_freeze_stamped") or 0))),
            ("Fully repeatable", str(int(repeatability.get("runs_repeatability_ready") or 0))),
            ("Publication manifests", _bool_text(repeatability.get("publication_manifests_present"))),
        ]
        table_utils.render_table(["Metric", "Value"], rrows, compact=False)
        blockers = repeatability.get("top_blockers") if isinstance(repeatability.get("top_blockers"), list) else []
        if blockers:
            brows = [
                [
                    str(item.get("code") or "unknown"),
                    str(int(item.get("count") or 0)),
                    ", ".join(str(x) for x in (item.get("sample_run_ids") or [])[:3]) or "—",
                ]
                for item in blockers
                if isinstance(item, dict)
            ]
            if brows:
                table_utils.render_table(["Blocker", "Count", "Sample runs"], brows, compact=False)

    if delta_rows:
        print()
        menu_utils.print_header("Tracker vs Evidence (Per App)")
        table_utils.print_table(
            delta_rows,
            headers=[
                "Package",
                "Tracker countable",
                "Evidence eligible countable",
                "Extras",
                "Excluded",
            ],
        )
        if priorities:
            print()
            menu_utils.print_header("Next Collection Priorities")
            table_utils.print_table(
                priorities,
                headers=[
                    "Package",
                    "Need baseline",
                    "Need interactive",
                    "Total needed",
                    "Suggested next",
                ],
            )
    print(status_messages.status(f"Audit report: {summary.report_path}", level="info"))


def render_host_pcap_tools() -> None:
    _render_host_pcap_tools_impl()


__all__ = [
    "build_freeze_state_payload",
    "render_dataset_status",
    "run_state_summary_report",
    "run_freeze_readiness_audit_report",
]


def render_cohort_status_details(
    *,
    dataset_apps_total: int,
    dataset_apps_complete: int,
    dataset_valid_runs_total: int,
    current_build_ready_count: int,
    current_build_in_progress_count: int,
    current_build_review_count: int,
    stale_app_count: int,
    current_build_db_only_count: int,
    historical_valid_runs_total: int,
    historical_build_count_total: int,
    mixed_identity_app_count: int,
    legacy_only_app_count: int,
    historical_local_only_app_count: int,
    historical_db_only_app_count: int,
    no_evidence_anywhere_count: int,
    expected_runs: int,
    evidence_summary: dict[str, object] | None,
    row_models: list[object],
    baseline_required: int,
    interactive_required: int,
) -> None:
    print()
    menu_utils.print_header("Summary", "Operator-facing cohort status")
    if dataset_apps_total <= 0:
        prompt_utils.press_enter_to_continue()
        return
    evidence_summary = evidence_summary or {}
    quota_counted = int(evidence_summary.get("quota_runs_counted", 0))
    quota_remaining = max(0, int(expected_runs) - quota_counted)
    baseline_remaining = sum(max(0, int(getattr(row, "need_baseline", 0))) for row in row_models)
    manual_remaining = sum(max(0, int(getattr(row, "need_interactive", 0))) for row in row_models)
    static_refresh_needed = sum(1 for row in row_models if bool(getattr(row, "live_build_drift", False)))
    print("Progress")
    print(f"  Apps complete         : {int(evidence_summary.get('apps_satisfied', 0))} / {dataset_apps_total}")
    print(f"  Quota-valid remaining : {quota_remaining}")
    print(f"  Static refresh needed : {static_refresh_needed}")
    print(f"  Baseline runs needed  : {baseline_remaining}")
    print(f"  Manual runs needed    : {manual_remaining}")
    print(
        "  Archive readiness    : "
        + ("ready" if int(evidence_summary.get("apps_satisfied", 0)) >= int(dataset_apps_total) and quota_counted >= int(expected_runs) else "blocked")
    )
    print()
    print("Evidence-authoritative quota")
    print(f"  Quota-valid runs      : {quota_counted} / {expected_runs}")
    print(f"  Paper-eligible found  : {int(evidence_summary.get('paper_eligible_runs', 0))}")
    print(f"  Supplemental extras   : {int(evidence_summary.get('extra_eligible_runs', 0))}")
    print(f"  Excluded              : {int(evidence_summary.get('excluded_runs', 0))}")
    print()
    print("Tracker-scoped latest-run state")
    print(f"  Apps satisfied        : {dataset_apps_complete} / {dataset_apps_total}")
    print(f"  Current-build complete: {current_build_ready_count} / {dataset_apps_total}")
    if current_build_in_progress_count > 0:
        print(f"  Current-build active  : {current_build_in_progress_count}")
    if current_build_review_count > 0:
        print(f"  Current-build review  : {current_build_review_count}")
    print(f"  Current-build stale   : {stale_app_count}")
    if current_build_db_only_count > 0:
        print(f"  Current-build DB-only : {current_build_db_only_count}")
    print(f"  Active-build counted  : {dataset_valid_runs_total} / {expected_runs}")
    print(f"  Baseline target       : {baseline_required} per app")
    print(f"  Manual target         : {interactive_required} per app")
    if (
        historical_valid_runs_total > 0
        or historical_build_count_total > 0
        or historical_local_only_app_count > 0
        or historical_db_only_app_count > 0
        or no_evidence_anywhere_count > 0
    ):
        print()
        print("Historical context")
        print(f"  Mixed apps            : {mixed_identity_app_count}")
        print(f"  Legacy-only apps      : {legacy_only_app_count}")
        if historical_local_only_app_count > 0:
            print(f"  Historical local-only : {historical_local_only_app_count}")
        if historical_db_only_app_count > 0:
            print(f"  Historical DB-only    : {historical_db_only_app_count}")
        if no_evidence_anywhere_count > 0:
            print(f"  No evidence anywhere  : {no_evidence_anywhere_count}")
        print(f"  Legacy valid runs     : {historical_valid_runs_total}")
        print(f"  Older builds          : {historical_build_count_total}")
    if int(evidence_summary.get("protocol_fit_poor_runs", 0)) > 0:
        print(f"  Protocol fit poor     : {int(evidence_summary.get('protocol_fit_poor_runs', 0))} (flagged)")
    if int(evidence_summary.get("low_signal_exploratory_runs", 0)) > 0:
        print(f"  Low-signal exploratory: {int(evidence_summary.get('low_signal_exploratory_runs', 0))}")
    print()
    print("Meaning")
    print("  Evidence-authoritative quota drives archive/freeze readiness.")
    print("  Tracker-scoped latest-run state describes active-build queue posture.")
    print("  Current-build stale means older evidence exists, but the installed app version needs fresh harvest/static.")
    print("  Current-build DB-only means the DB knows current-build sessions, but the local evidence pack is not present.")
    print("  Historical DB-only means older dynamic lineage exists in the DB, but the local evidence pack is not present.")
    prompt_utils.press_enter_to_continue()


def render_cohort_build_history(row_models: list[object], build_rows: list[list[str]]) -> None:
    print()
    menu_utils.print_header("History", "Build lineage and why an app looks current, mixed, or legacy")
    summary_rows = []
    for row in row_models:
        reason, notes = _history_reason_and_notes(row)
        if int(getattr(row, "baseline_extra", 0)) > 0:
            notes.append("extra baseline outside quota")
        if int(getattr(row, "interactive_extra", 0)) > 0:
            notes.append("extra manual outside quota")
        if int(getattr(row, "historical_valid_runs_count", 0)) > 0:
            notes.append("legacy evidence present")
        if str(getattr(row, "lineage_state", "")) == "historical_db_only":
            notes.append("historical DB-only evidence")
        if str(getattr(row, "lineage_state", "")) == "current_build_db_only":
            notes.append("current-build DB-only evidence")
        if bool(getattr(row, "live_build_drift", False)):
            notes.append("installed build needs static refresh")
        if str(getattr(row, "qa_label", "")).startswith("invalid"):
            notes.append("latest QA invalid")
        if "id_mismatch" in str(getattr(row, "qa_label", "")):
            notes.append("identity mismatch")
        note_text = reason
        extras = [item for item in notes if item and item != reason]
        if extras:
            note_text = f"{reason}; " + "; ".join(extras)
        summary_rows.append(
            {
                "app": getattr(row, "display_name", "—"),
                "baseline": _history_progress_label(
                    getattr(row, "baseline_countable", 0),
                    getattr(row, "baseline_extra", 0),
                    required=3,
                    missing=getattr(row, "need_baseline", 0),
                ),
                "manual": (
                    "locked"
                    if int(getattr(row, "need_baseline", 0)) > 0
                    else _history_progress_label(
                        getattr(row, "interactive_countable", 0),
                        getattr(row, "interactive_extra", 0),
                        required=2,
                        missing=getattr(row, "need_interactive", 0),
                    )
                ),
                "prep": getattr(row, "prep_label", "—"),
                "qa": getattr(row, "qa_label", "—"),
                "notes": note_text or "—",
            }
        )
    _render_history_summary_table(summary_rows)
    if build_rows:
        print()
        print("Build identity detail")
        table_utils.render_table(
            ["App", "Identity (vc/base)", "Active Runs", "Legacy Runs", "Legacy Builds"],
            build_rows,
            compact=True,
        )
    prompt_utils.press_enter_to_continue()


def _history_reason_and_notes(row: object) -> tuple[str, list[str]]:
    lineage_state = str(getattr(row, "lineage_state", "") or "").strip()
    qa_label = str(getattr(row, "qa_label", "") or "").strip().lower()
    need_baseline = int(getattr(row, "need_baseline", 0) or 0)
    need_interactive = int(getattr(row, "need_interactive", 0) or 0)
    if bool(getattr(row, "live_build_drift", False)):
        return "installed build drifted from newest static plan", []
    if lineage_state == "current_build_db_only":
        return "current-build evidence missing locally", []
    if lineage_state == "historical_db_only":
        return "only historical DB lineage exists", []
    if lineage_state == "historical_local_only":
        return "only legacy local evidence exists", []
    if qa_label.startswith("invalid") and need_baseline <= 0 and need_interactive <= 0:
        return "latest current-build QA invalid", []
    if need_baseline > 0:
        return "baseline quota not met", []
    if need_interactive > 0:
        return "interactive quota not met", []
    return "current-build quota complete", []


def render_cohort_status_help() -> None:
    print()
    menu_utils.print_header("Help", "Queue legend")
    print("Status   = workflow state only: complete, review, manual, baseline, restore, refresh, legacy, or blocked.")
    print("Need     = current blocker or gap: review, base 0/3, manual 0/2, current, local+curr, refresh, or local pack.")
    print("Baseline Runs    = baseline-side valid runs shown as a raw count against the total run target; + extra rolls into the displayed count.")
    print("Interactive Runs = scripted/manual runs combined for planning; detailed run type remains in history/diagnostics.")
    print("Build    = build posture for this app in the queue: current, legacy, drift, or unknown.")
    print("QA       = latest QA badge: ✓, inv, +id, +L, +id+L, or —.")
    print("Action   = recommended operator move: baseline, interactive, review, refresh, or restore.")
    print("locked   = manual phase unavailable until baseline minimum is met.")
    print("mixed    = current-build and legacy-build evidence both exist.")
    print("refresh  = installed app build differs from the newest static plan. Refresh harvest/static before continuing dataset-mode dynamic capture for this app.")
    print("drift    = build posture for a refresh-blocked app; harvest/static refresh is required before dynamic continuation.")
    print("identity mismatch = latest valid run does not match the active build identity; review historical vs current evidence carefully.")
    print("baseline gap = baseline minimum is not met yet for quota/publication use.")
    print("manual gap   = baseline is complete, but interactive quota is still missing.")
    print("refresh steps: harvest current APK(s), rerun static for that build, regenerate the newest plan, then return to the queue.")
    print("Detailed local/db/history evidence lineage moved to diagnostics and run history.")
    print("db-only  = evidence exists in stored history/DB context but no local pack is present in this workspace.")
    print("Build=legacy + Evidence=db-only = historical-only context; recollect on the installed build.")
    print("Build=current + Evidence=db-only = current-build run context is stored, but the local evidence pack is not present here.")
    print("+L       = latest QA valid, legacy evidence also exists.")
    print("Status is workflow state only; Build and QA are separate displayed dimensions.")
    print("Need explains why the app is not done; Action is the recommended next operation.")
    print("Evidence-authoritative quota = archive/freeze truth.")
    print("Tracker-scoped latest-run state = queue-operating view of the active build.")
    prompt_utils.press_enter_to_continue()


def render_cohort_status_debug(rows: list[list[str]], row_models: list[object]) -> None:
    print()
    menu_utils.print_header("Diagnostics", "Dense raw/debug view; lower-level tracker and queue fields")
    print("This view preserves lower-level queue fields for debugging and the tracker-scoped latest-run state.")
    table_utils.render_table(
        ["#", "App", "Baseline", "Manual", "Need", "Next Action", "Build", "Quota", "Legacy", "Last QA"],
        rows,
        compact=False,
    )
    if row_models:
        drift_rows = [row for row in row_models if bool(getattr(row, "live_build_drift", False))]
        if drift_rows:
            print()
            print("Build refresh required")
            print("----------------------")
            print(f"{len(drift_rows)} apps have installed builds that differ from the newest static plan.")
            print("Refresh harvest/static before continuing dataset-mode dynamic capture.")
            for row in drift_rows:
                expected_vc = str(getattr(row, "live_expected_version_code", "") or "").strip() or "unknown"
                expected_vn = str(getattr(row, "live_expected_version_name", "") or "").strip()
                static_plan = f"{expected_vn} ({expected_vc})" if expected_vn else expected_vc
                observed_vc = str(getattr(row, "live_observed_version_code", "") or "").strip() or "unknown"
                static_run_id = str(getattr(row, "live_static_run_id", "") or "").strip() or "unknown"
                print()
                print(str(getattr(row, "display_name", "—") or "—"))
                print(f"  Package     : {str(getattr(row, 'package_name', '—') or '—')}")
                print(f"  Installed   : {observed_vc}")
                print(f"  Static plan : {static_plan}")
                print(f"  Static run  : {static_run_id}")
                print("  Action      : refresh harvest/static, then return to dynamic queue")
        print()
        print("Operator summary")
        summary_rows = [
            [
                getattr(row, "display_name", "—"),
                _diagnostic_status_label(row),
                _history_reason_and_notes(row)[0],
                _diagnostic_db_lineage_label(row),
                str(getattr(row, "qa_label", "—") or "—"),
            ]
            for row in row_models
        ]
        table_utils.render_table(
            ["App", "Status", "Reason", "DB lineage", "Latest QA"],
            summary_rows,
            compact=False,
        )
        print()
        print("Raw state extract")
        raw_rows = [
            [
                getattr(row, "display_name", "—"),
                str(getattr(row, "baseline_countable", 0)),
                str(getattr(row, "baseline_extra", 0)),
                str(getattr(row, "interactive_countable", 0)),
                str(getattr(row, "interactive_extra", 0)),
                str(getattr(row, "historical_valid_runs_count", 0)),
                str(getattr(row, "historical_build_count", 0)),
                str(getattr(row, "need_baseline", 0)),
                str(getattr(row, "need_interactive", 0)),
                str(getattr(row, "lineage_state", "")),
                str(getattr(row, "db_active_sessions", 0)),
                str(getattr(row, "db_historical_sessions", 0)),
            ]
            for row in row_models
        ]
        table_utils.render_table(
            ["App", "Base ct", "Base ex", "Manual ct", "Manual ex", "Legacy", "L builds", "Need B", "Need M", "Lineage", "DB active", "DB hist"],
            raw_rows,
            compact=True,
        )
    prompt_utils.press_enter_to_continue()


def _diagnostic_status_label(row: object) -> str:
    if bool(getattr(row, "live_build_drift", False)):
        return "refresh"
    lineage_state = str(getattr(row, "lineage_state", "") or "").strip()
    if lineage_state == "current_build_db_only":
        return "restore"
    if lineage_state in {"historical_db_only", "historical_local_only"}:
        return "legacy"
    need_baseline = int(getattr(row, "need_baseline", 0) or 0)
    need_interactive = int(getattr(row, "need_interactive", 0) or 0)
    qa_label = str(getattr(row, "qa_label", "") or "").strip().lower()
    if qa_label.startswith("invalid") and need_baseline <= 0 and need_interactive <= 0:
        return "review"
    if need_baseline > 0:
        return "baseline"
    if need_interactive > 0:
        return "manual"
    return "complete"


def _diagnostic_db_lineage_label(row: object) -> str:
    active = int(getattr(row, "db_active_sessions", 0) or 0)
    historical = int(getattr(row, "db_historical_sessions", 0) or 0)
    if active > 0 and historical > 0:
        return f"active={active} hist={historical}"
    if active > 0:
        return f"active={active}"
    if historical > 0:
        return f"hist={historical}"
    return "—"


def _history_progress_label(countable: object, extra: object, *, required: int, missing: object) -> str:
    count_i = max(0, int(countable or 0))
    extra_i = max(0, int(extra or 0))
    required_i = max(0, int(required))
    missing_i = max(0, int(missing or 0))
    if missing_i == 0:
        if extra_i > 0:
            return f"{count_i}/{required_i} +{extra_i} extra"
        return f"{count_i}/{required_i} complete"
    return f"{count_i}/{required_i} need {missing_i}"


def _render_history_summary_table(rows: list[dict[str, str]]) -> None:
    terminal_width = max(80, shutil.get_terminal_size(fallback=(120, 40)).columns)
    col_widths = {
        "app": 18,
        "baseline": 17,
        "manual": 15,
        "prep": 8,
        "qa": 11,
    }
    note_width = max(
        24,
        terminal_width
        - (
            col_widths["app"]
            + col_widths["baseline"]
            + col_widths["manual"]
            + col_widths["prep"]
            + col_widths["qa"]
            + 5
        ),
    )
    print(
        f"{'App':<{col_widths['app']}} "
        f"{'Baseline':<{col_widths['baseline']}} "
        f"{'Manual':<{col_widths['manual']}} "
        f"{'Prep':<{col_widths['prep']}} "
        f"{'QA':<{col_widths['qa']}} "
        f"{'Notes'}"
    )
    print(
        f"{'-' * col_widths['app']} "
        f"{'-' * col_widths['baseline']} "
        f"{'-' * col_widths['manual']} "
        f"{'-' * col_widths['prep']} "
        f"{'-' * col_widths['qa']} "
        f"{'-' * min(note_width, 32)}"
    )
    for row in rows:
        wrapped_notes = textwrap.wrap(
            str(row.get("notes") or "—"),
            width=note_width,
            break_long_words=False,
            break_on_hyphens=False,
        ) or ["—"]
        first_line = wrapped_notes[0]
        print(
            f"{_truncate_cell(row.get('app'), col_widths['app']):<{col_widths['app']}} "
            f"{_truncate_cell(row.get('baseline'), col_widths['baseline']):<{col_widths['baseline']}} "
            f"{_truncate_cell(row.get('manual'), col_widths['manual']):<{col_widths['manual']}} "
            f"{_truncate_cell(row.get('prep'), col_widths['prep']):<{col_widths['prep']}} "
            f"{_truncate_cell(row.get('qa'), col_widths['qa']):<{col_widths['qa']}} "
            f"{first_line}"
        )
        for continuation in wrapped_notes[1:]:
            print(
                f"{'':<{col_widths['app']}} "
                f"{'':<{col_widths['baseline']}} "
                f"{'':<{col_widths['manual']}} "
                f"{'':<{col_widths['prep']}} "
                f"{'':<{col_widths['qa']}} "
                f"{continuation}"
            )


def _truncate_cell(value: object, width: int) -> str:
    text = str(value or "—")
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "…"


__all__.extend(
    [
        "render_host_pcap_tools",
        "render_cohort_build_history",
        "render_cohort_status_debug",
        "render_cohort_status_details",
        "render_cohort_status_help",
    ]
)
