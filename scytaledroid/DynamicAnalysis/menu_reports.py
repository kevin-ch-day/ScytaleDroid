"""Rendering helpers for dynamic menu reports."""

from __future__ import annotations

import os

from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import (
    run_freeze_readiness_audit,
)
from scytaledroid.DynamicAnalysis.tools.evidence.state_summary import build_state_summary
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils


def run_freeze_readiness_audit_report() -> None:
    summary = run_freeze_readiness_audit()
    print()
    menu_utils.print_header("Freeze Readiness Audit")
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
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker

    print()
    menu_utils.print_header("Dataset Run Status")
    payload = load_dataset_tracker()
    apps = payload.get("apps", {})
    rows = []
    for package, entry in sorted(apps.items()):
        runs = int(entry.get("run_count") or 0)
        valid = int(entry.get("valid_runs") or 0)
        target = int(entry.get("target_runs") or 0)
        base = int(entry.get("baseline_valid_runs") or 0)
        inter = int(entry.get("interactive_valid_runs") or 0)
        extra = int(entry.get("extra_valid_runs") or 0)
        quota_met_at = entry.get("quota_met_at") or ""
        status = "DONE" if entry.get("app_complete") else "IN_PROGRESS"
        rows.append(
            {
                "Package": package,
                "Valid": valid,
                "Base": base,
                "Inter": inter,
                "Runs": runs,
                "Target": target,
                "Extra": extra,
                "Quota met at": str(quota_met_at),
                "Status": status,
            }
        )
    if not rows:
        print(status_messages.status("No dataset runs recorded yet.", level="info"))
        return
    table_utils.print_table(
        rows,
        headers=["Package", "Valid", "Base", "Inter", "Runs", "Target", "Extra", "Quota met at", "Status"],
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
    ui_level = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower()
    verbose = ui_level in {"details", "debug"}
    if not verbose:
        line = (
            f"CAN_FREEZE={'YES' if summary.can_freeze else 'NO'}"
            f" | total_runs={summary.total_runs}"
            f" | eligible_runs={summary.paper_eligible_runs}"
        )
        if summary.first_failing_reason:
            line += f" | first_fail={summary.first_failing_reason}"
        print(status_messages.status(line, level="success" if summary.can_freeze else "warn"))
        print(status_messages.status(f"Audit report: {summary.report_path}", level="info"))
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
    """Render host toolchain status required for dataset-tier PCAP post-analysis."""
    from pathlib import Path

    from scytaledroid.DynamicAnalysis.pcap.tools import collect_host_tools, missing_required_tools

    print()
    menu_utils.print_header("Host PCAP Tools")
    tools = collect_host_tools()
    missing = missing_required_tools(tier="dataset")
    ui_level = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower()
    verbose = ui_level in {"details", "debug"}
    if not verbose and not missing:
        tshark_path = ((tools.get("tshark") or {}) if isinstance(tools, dict) else {}).get("path")
        capinfos_path = ((tools.get("capinfos") or {}) if isinstance(tools, dict) else {}).get("path")
        tshark_ok = "present" if tshark_path else "missing"
        capinfos_ok = "present" if capinfos_path else "missing"
        print(status_messages.status(f"tshark={tshark_ok} | capinfos={capinfos_ok}", level="success"))
        print(status_messages.status("Host toolchain is dataset-ready.", level="success"))
        return
    for name in ("tshark", "capinfos"):
        meta = tools.get(name) if isinstance(tools, dict) else None
        path = meta.get("path") if isinstance(meta, dict) else None
        version = meta.get("version") if isinstance(meta, dict) else None
        if path:
            print(status_messages.status(f"{name}: present ({path})", level="success"))
            if verbose and version:
                print(status_messages.status(f"{name}: {version}", level="info"))
        else:
            print(status_messages.status(f"{name}: missing", level="warn"))

    script = Path("scripts/install_wireshark_cli.sh")
    if missing:
        if script.exists():
            print(
                status_messages.status(
                    "Fix: install required tools with: sudo scripts/install_wireshark_cli.sh",
                    level="warn",
                )
            )
        else:
            print(
                status_messages.status(
                    "Fix: install wireshark-cli (tshark + capinfos) using your OS package manager.",
                    level="warn",
                )
            )
    else:
        print(status_messages.status("Host toolchain is dataset-ready.", level="success"))


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
    expected_runs: int,
    evidence_summary: dict[str, object] | None,
) -> None:
    print()
    menu_utils.print_header("Details", "Tracker vs evidence (compact)")
    if dataset_apps_total <= 0:
        prompt_utils.press_enter_to_continue()
        return
    evidence_summary = evidence_summary or {}
    print("Tracker (informational)")
    print(f"  Apps satisfied  : {dataset_apps_complete} / {dataset_apps_total}")
    print(f"  Valid runs      : {dataset_valid_runs_total} / {expected_runs}")
    print("Evidence (authoritative)")
    print(f"  Apps satisfied  : {int(evidence_summary.get('apps_satisfied', 0))} / {dataset_apps_total}")
    print(f"  Eligible counted: {int(evidence_summary.get('quota_runs_counted', 0))} / {expected_runs}")
    print(f"  Eligible found  : {int(evidence_summary.get('paper_eligible_runs', 0))}")
    print(f"  Extras          : {int(evidence_summary.get('extra_eligible_runs', 0))}")
    print(f"  Excluded        : {int(evidence_summary.get('excluded_runs', 0))}")
    if int(evidence_summary.get("protocol_fit_poor_runs", 0)) > 0:
        print(f"  Protocol fit poor: {int(evidence_summary.get('protocol_fit_poor_runs', 0))} (flagged)")
    if int(evidence_summary.get("low_signal_exploratory_runs", 0)) > 0:
        print(f"  Low-signal (exploratory): {int(evidence_summary.get('low_signal_exploratory_runs', 0))}")
    prompt_utils.press_enter_to_continue()


def render_cohort_build_history(build_rows: list[list[str]]) -> None:
    print()
    menu_utils.print_header("Build History Details")
    table_utils.render_table(
        ["App", "Identity (vc/base)", "Active Runs", "Legacy Runs", "Legacy Builds"],
        build_rows,
        compact=True,
    )
    prompt_utils.press_enter_to_continue()


def render_cohort_status_help() -> None:
    print()
    menu_utils.print_header("Help", "Legend (short)")
    print("Baseline / Interactive = countable valid runs for active build")
    print("Scripted / Manual      = interactive run breakdown (countable(+extra))")
    print("(+N)                   = extra valid runs (not quota-counted)")
    print("Need                   = remaining quota slots for this package")
    print("Next                   = deterministic suggestion from Need")
    print("Build                  = CUR(current build) | OLD(legacy only) | MIX(both)")
    print("Total                  = technically valid evidence packs found (includes excluded/exploratory)")
    print("QA                     = latest tracker QA status (may include identity mismatch note)")
    prompt_utils.press_enter_to_continue()


def render_cohort_status_debug(rows: list[list[str]]) -> None:
    print()
    menu_utils.print_header("Debug", "Full table + legacy/QA fields")
    table_utils.render_table(
        ["#", "App", "Baseline", "Interactive", "Need", "Next Action", "Build", "Total", "Legacy", "Last QA"],
        rows,
        compact=False,
    )
    prompt_utils.press_enter_to_continue()


__all__.extend(
    [
        "render_host_pcap_tools",
        "render_cohort_build_history",
        "render_cohort_status_debug",
        "render_cohort_status_details",
        "render_cohort_status_help",
    ]
)
