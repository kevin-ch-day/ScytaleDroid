"""Rendering helpers for dynamic menu reports."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import (
    run_freeze_readiness_audit,
)
from scytaledroid.DynamicAnalysis.tools.evidence.state_summary import build_state_summary
from scytaledroid.StaticAnalysis.core.repository import group_artifacts, load_display_name_map
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils


def _bool_text(value: object) -> str:
    return "yes" if bool(value) else "no"


def _count_tracker_runs(apps: object) -> int:
    if not isinstance(apps, dict):
        return 0
    return sum(
        len(entry.get("runs", []))
        for entry in apps.values()
        if isinstance(entry, dict) and isinstance(entry.get("runs"), list)
    )


def _tracker_path() -> Path:
    return Path(app_config.DATA_DIR) / "archive" / "dataset_plan.json"


def _freeze_path() -> Path:
    return Path(app_config.DATA_DIR) / "archive" / "dataset_freeze.json"


def _capture_environment_summary() -> dict[str, object]:
    required_tools = ("adb", "tshark", "capinfos")
    optional_tools = ("tcpdump", "dumpcap", "editcap", "mergecap", "frida", "mitmproxy", "mitmdump")
    tools: dict[str, dict[str, object]] = {}
    for name in (*required_tools, *optional_tools):
        path = shutil.which(name)
        tools[name] = {"path": path, "present": bool(path)}

    adb_devices: list[str] = []
    adb_path = tools.get("adb", {}).get("path")
    if adb_path:
        try:
            completed = subprocess.run(
                [str(adb_path), "devices"],
                check=False,
                capture_output=True,
                text=True,
                timeout=8,
            )
            for line in (completed.stdout or "").splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "device":
                    adb_devices.append(parts[0])
        except Exception:
            adb_devices = []

    evidence_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    nearest_existing = evidence_root
    while not nearest_existing.exists() and nearest_existing != nearest_existing.parent:
        nearest_existing = nearest_existing.parent
    evidence_root_ready = (
        (evidence_root.exists() and os.access(evidence_root, os.R_OK | os.W_OK))
        or (not evidence_root.exists() and nearest_existing.exists() and os.access(nearest_existing, os.W_OK))
    )
    blocking = []
    for name in required_tools:
        if not tools.get(name, {}).get("present"):
            blocking.append(f"missing {name}")
    if not adb_devices:
        blocking.append("no adb device visible")
    if not evidence_root_ready:
        blocking.append("dynamic evidence root is not writable")

    return {
        "required_tools": required_tools,
        "optional_tools": optional_tools,
        "tools": tools,
        "adb_devices": adb_devices,
        "evidence_root": str(evidence_root),
        "evidence_root_exists": bool(evidence_root.exists()),
        "evidence_root_ready": bool(evidence_root_ready),
        "blocking_issues": blocking,
    }


def run_freeze_readiness_audit_report() -> None:
    summary = run_freeze_readiness_audit()
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
                    "run Guided cohort run first, then rerun State summary and Freeze readiness audit.",
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
                "run Guided cohort run first, then rerun State summary and Freeze readiness audit.",
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
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker

    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig

    print()
    menu_utils.print_header("Cohort Status Overview")
    menu_utils.print_hint(
        "Review cohort progress from local evidence packs and tracker state without starting collection."
    )
    summary = run_freeze_readiness_audit()
    state_payload = build_state_summary()
    handoff = (
        state_payload.get("static_handoff_plan_summary")
        if isinstance(state_payload.get("static_handoff_plan_summary"), dict)
        else {}
    )
    try:
        display_names = load_display_name_map(group_artifacts())
    except Exception:
        display_names = {}
    payload = load_dataset_tracker()
    apps = payload.get("apps", {})
    tracker_exists = _tracker_path().exists()
    tracker_rows = _count_tracker_runs(apps)
    if not tracker_rows:
        rows = [
            ("Cohort runs", "none recorded"),
            ("Evidence packs", str(int(summary.total_runs))),
            ("Tracker", "present" if tracker_exists else "missing"),
            ("Freeze file", "present" if _freeze_path().exists() else "missing"),
            (
                "Static handoff",
                f"ready {int(handoff.get('dataset_packages_with_plan') or 0)}/"
                f"{int(handoff.get('dataset_packages_total') or 0)}",
            ),
            ("Next", "run Guided cohort"),
        ]
        table_utils.render_table(["Signal", "Status"], rows, compact=False)
        if int(summary.total_runs) == 0:
            print(
                status_messages.status(
                    "No dynamic evidence packs are present. This is expected after cleanup or before the first run.",
                    level="info",
                )
            )
        return

    cfg = DatasetTrackerConfig()
    target = int(cfg.baseline_required) + int(cfg.interactive_required)
    rows = []
    for package, entry in sorted(apps.items()):
        runs = int(entry.get("run_count") or 0)
        valid = int(entry.get("valid_runs") or 0)
        app_target = int(entry.get("target_runs") or 0) or target
        base = int(entry.get("baseline_valid_runs") or 0)
        inter = int(entry.get("interactive_valid_runs") or 0)
        latest_run = ""
        run_entries = entry.get("runs") if isinstance(entry.get("runs"), list) else []
        if run_entries:
            latest = run_entries[-1] if isinstance(run_entries[-1], dict) else {}
            latest_run = str(latest.get("run_id") or latest.get("dynamic_run_id") or "")
        freeze_eligible = "yes" if entry.get("app_complete") else "no"
        if entry.get("app_complete"):
            blocking = ""
        else:
            missing_base = max(0, int(cfg.baseline_required) - base)
            missing_inter = max(0, int(cfg.interactive_required) - inter)
            parts = []
            if missing_base:
                parts.append(f"need baseline {missing_base}")
            if missing_inter:
                parts.append(f"need interactive {missing_inter}")
            blocking = ", ".join(parts) or "not quota complete"
        rows.append(
            {
                "Package": package,
                "Display": display_names.get(package, ""),
                "Target": app_target,
                "Runs": runs,
                "Valid packs": valid,
                "Latest run": latest_run[:12],
                "Freeze eligible": freeze_eligible,
                "Blocking reason": blocking,
            }
        )
    ui_level = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower()
    if ui_level in {"details", "debug"}:
        table_utils.print_table(
            rows,
            headers=[
                "Package",
                "Display",
                "Target",
                "Runs",
                "Valid packs",
                "Latest run",
                "Freeze eligible",
                "Blocking reason",
            ],
        )
        return
    for row in rows:
        display = str(row.get("Display") or "").strip()
        label = f"{display} ({row['Package']})" if display else str(row["Package"])
        print(
            f"{label} | quota={row['Valid packs']}/{row['Target']} "
            f"runs={row['Runs']} latest={row['Latest run'] or '-'} "
            f"freeze_eligible={row['Freeze eligible']} reason={row['Blocking reason'] or '-'}"
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
        env = _capture_environment_summary()
        handoff = (
            state_payload.get("static_handoff_plan_summary")
            if isinstance(state_payload.get("static_handoff_plan_summary"), dict)
            else {}
        )
        tracker = state_payload.get("tracker_vs_evidence_per_app")
        tracker_rows = len(tracker) if isinstance(tracker, list) else 0
        mismatches = 0
        if isinstance(tracker, list):
            for row in tracker:
                if not isinstance(row, dict):
                    continue
                if int(row.get("tracker_countable") or 0) != int(row.get("evidence_eligible_countable") or 0):
                    mismatches += 1
        sections = [
            (
                "Environment",
                [
                    ("capture tools", "ready" if not env.get("blocking_issues") else "blocking issues"),
                    ("blocking issues", str(len(env.get("blocking_issues") or []))),
                ],
            ),
            (
                "Static handoff",
                [
                    (
                        "dataset apps ready",
                        f"{int(handoff.get('dataset_packages_with_plan') or 0)}/"
                        f"{int(handoff.get('dataset_packages_total') or 0)}",
                    ),
                    ("plan files", str(int(handoff.get("dynamic_plan_files") or 0))),
                    ("source", str(handoff.get("plan_dir") or "")),
                ],
            ),
            (
                "Evidence",
                [
                    ("evidence packs", f"{summary.total_runs} total / {summary.valid_runs} valid / {max(int(summary.total_runs) - int(summary.valid_runs), 0)} invalid"),
                    ("incomplete dirs", str(summary.missing_run_manifest_dirs)),
                    ("evidence root exists", _bool_text(summary.evidence_root_exists)),
                    ("evidence root", str(summary.evidence_root)),
                ],
            ),
            (
                "Tracker",
                [
                    ("tracker exists", _bool_text(_tracker_path().exists())),
                    ("tracker rows", str(int(summary.tracker_runs_hint))),
                    ("tracker/evidence mismatches", str(mismatches)),
                    ("dataset rows evaluated", str(tracker_rows)),
                ],
            ),
            (
                "Freeze",
                [
                    ("can_freeze", _bool_text(summary.can_freeze)),
                    ("first blocker", str(summary.first_failing_reason or "none")),
                    ("audit report", str(summary.report_path)),
                ],
            ),
        ]
        for title, rows_for_section in sections:
            print()
            menu_utils.print_header(title)
            table_utils.render_table(["Signal", "Value"], rows_for_section, compact=False)
        if "NO_EVIDENCE_PACKS_FOUND" in summary.reasons:
            print(
                status_messages.status(
                    "No dynamic evidence packs are present. This is expected after cleanup or before the first run.",
                    level="info",
                )
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
        menu_utils.print_header("Static Handoff Plans")
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
            ("Ready for guided dataset run", str(bool(handoff.get("ready_for_guided_dataset_run"))).lower()),
        ]
        table_utils.render_table(["Metric", "Value"], hrows, compact=False)
        missing_pkgs = handoff.get("missing_packages") if isinstance(handoff.get("missing_packages"), list) else []
        if missing_pkgs:
            print(status_messages.status("Missing dataset plans: " + ", ".join(str(pkg) for pkg in missing_pkgs), level="warn"))

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
    """Render host/device toolchain status required for dynamic capture."""

    print()
    menu_utils.print_header("Capture Environment")
    env = _capture_environment_summary()
    tools = env.get("tools") if isinstance(env.get("tools"), dict) else {}
    required = tuple(env.get("required_tools") or ())
    optional = tuple(env.get("optional_tools") or ())
    devices = env.get("adb_devices") if isinstance(env.get("adb_devices"), list) else []
    blocking = env.get("blocking_issues") if isinstance(env.get("blocking_issues"), list) else []
    ui_level = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower()
    verbose = ui_level in {"details", "debug"}

    required_rows = []
    for name in required:
        meta = tools.get(name) if isinstance(tools.get(name), dict) else {}
        present = bool(meta.get("present"))
        value = "present" if present else "missing"
        if verbose and meta.get("path"):
            value = str(meta.get("path"))
        required_rows.append((name, value))
    required_rows.append(("device visible", ", ".join(str(d) for d in devices) if devices else "missing"))
    required_rows.append(("dynamic evidence root writable", "yes" if env.get("evidence_root_ready") else "no"))
    menu_utils.print_header("Required")
    table_utils.render_table(["Check", "Status"], required_rows, compact=False)

    optional_present = []
    optional_missing = []
    for name in optional:
        meta = tools.get(name) if isinstance(tools.get(name), dict) else {}
        if meta.get("present"):
            optional_present.append((name, str(meta.get("path") or "present")))
        else:
            optional_missing.append(name)
    if optional_present:
        print()
        menu_utils.print_header("Optional Present")
        table_utils.render_table(["Tool", "Path"], optional_present, compact=False)
    print()
    menu_utils.print_header("Optional Missing")
    print(", ".join(optional_missing) if optional_missing else "none")

    print()
    menu_utils.print_header("Blocking Issues")
    if blocking:
        for issue in blocking:
            print(status_messages.status(str(issue), level="warn"))
    else:
        print(status_messages.status("required ready", level="success"))


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
