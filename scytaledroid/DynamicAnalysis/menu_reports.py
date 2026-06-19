"""Rendering helpers for dynamic menu reports."""

from __future__ import annotations

import os
import shutil
import subprocess
import textwrap
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.research_cohort_archive import (
    resolve_dataset_freeze_read_path,
    resolve_dataset_plan_read_path,
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
    if not isinstance(apps, dict):
        return 0
    return sum(
        len(entry.get("runs", []))
        for entry in apps.values()
        if isinstance(entry, dict) and isinstance(entry.get("runs"), list)
    )


def _tracker_path() -> Path:
    return resolve_dataset_plan_read_path()


def _freeze_path() -> Path:
    return resolve_dataset_freeze_read_path()


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
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker

    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig

    print()
    menu_utils.print_header("Cohort Status Overview")
    menu_utils.print_hint(
        "Review cohort progress from local evidence packs and tracker state without starting collection."
    )
    cohort_label = active_research_cohort_label()
    print(status_messages.status(f"Active research cohort: {cohort_label}", level="info"))
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
            ("Research cohort", cohort_label),
            ("Cohort runs", "none recorded"),
            ("Evidence packs", str(int(summary.total_runs))),
            ("Tracker", "present" if tracker_exists else "missing"),
            ("Freeze file", "present" if _freeze_path().exists() else "missing"),
            (
                "Static handoff",
                f"ready {int(handoff.get('dataset_packages_with_plan') or 0)}/"
                f"{int(handoff.get('dataset_packages_total') or 0)}",
            ),
            ("Next", f"run cohort ({cohort_label})"),
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
        cohort_label = active_research_cohort_label()
        total_runs = int(getattr(summary, "total_runs", 0) or 0)
        valid_runs = int(getattr(summary, "valid_runs", 0) or 0)
        missing_run_manifest_dirs = int(getattr(summary, "missing_run_manifest_dirs", 0) or 0)
        evidence_root_exists = bool(getattr(summary, "evidence_root_exists", False))
        evidence_root = str(getattr(summary, "evidence_root", "") or "")
        tracker_runs_hint = int(getattr(summary, "tracker_runs_hint", 0) or 0)
        reasons = tuple(getattr(summary, "reasons", ()) or ())
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
                "Research cohort",
                [
                    ("active cohort", cohort_label),
                ],
            ),
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
                "Repeatability",
                [
                    (
                        "runs ready",
                        f"{int(((state_payload.get('repeatability_summary') or {}) if isinstance(state_payload.get('repeatability_summary'), dict) else {}).get('runs_repeatability_ready') or 0)}/"
                        f"{int(((state_payload.get('repeatability_summary') or {}) if isinstance(state_payload.get('repeatability_summary'), dict) else {}).get('runs_total') or 0)}",
                    ),
                    ("freeze role", str((((state_payload.get("repeatability_summary") or {}) if isinstance(state_payload.get("repeatability_summary"), dict) else {}).get("freeze_role") or "none"))),
                    (
                        "publication manifests",
                        _bool_text((((state_payload.get("repeatability_summary") or {}) if isinstance(state_payload.get("repeatability_summary"), dict) else {}).get("publication_manifests_present"))),
                    ),
                ],
            ),
                (
                    "Evidence",
                    [
                        ("evidence packs", f"{total_runs} total / {valid_runs} valid / {max(total_runs - valid_runs, 0)} invalid"),
                        ("incomplete dirs", str(missing_run_manifest_dirs)),
                        ("evidence root exists", _bool_text(evidence_root_exists)),
                        ("evidence root", evidence_root),
                    ],
                ),
                (
                    "Tracker",
                    [
                        ("tracker exists", _bool_text(_tracker_path().exists())),
                        ("tracker rows", str(tracker_runs_hint)),
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
        if "NO_EVIDENCE_PACKS_FOUND" in reasons:
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
    historical_valid_runs_total: int,
    historical_build_count_total: int,
    mixed_identity_app_count: int,
    legacy_only_app_count: int,
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
    print("Progress")
    print(f"  Apps complete         : {int(evidence_summary.get('apps_satisfied', 0))} / {dataset_apps_total}")
    print(f"  Quota-valid remaining : {quota_remaining}")
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
    print(f"  Active-build counted  : {dataset_valid_runs_total} / {expected_runs}")
    print(f"  Baseline target       : {baseline_required} per app")
    print(f"  Manual target         : {interactive_required} per app")
    if historical_valid_runs_total > 0 or historical_build_count_total > 0:
        print()
        print("Historical context")
        print(f"  Mixed apps            : {mixed_identity_app_count}")
        print(f"  Legacy-only apps      : {legacy_only_app_count}")
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
    prompt_utils.press_enter_to_continue()


def render_cohort_build_history(row_models: list[object], build_rows: list[list[str]]) -> None:
    print()
    menu_utils.print_header("History", "Build lineage and why an app looks current, mixed, or legacy")
    summary_rows = []
    for row in row_models:
        notes: list[str] = []
        if int(getattr(row, "baseline_extra", 0)) > 0:
            notes.append("extra baseline outside quota")
        if int(getattr(row, "interactive_extra", 0)) > 0:
            notes.append("extra manual outside quota")
        if int(getattr(row, "historical_valid_runs_count", 0)) > 0:
            notes.append("legacy evidence present")
        if bool(getattr(row, "live_build_drift", False)):
            notes.append("installed build needs static refresh")
        if str(getattr(row, "qa_label", "")).startswith("invalid"):
            notes.append("latest QA invalid")
        if "id_mismatch" in str(getattr(row, "qa_label", "")):
            notes.append("identity mismatch")
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
                "notes": "; ".join(notes) or "—",
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


def render_cohort_status_help() -> None:
    print()
    menu_utils.print_header("Help", "Queue legend")
    print("Status   = high-level app bucket: complete, manual, baseline, blocked, or review.")
    print("Missing  = what is missing now, e.g. base 0/3, manual 0/2, or review QA.")
    print("Quota    = quota-valid runs against total quota; +N or + extra means supplemental valid runs outside quota.")
    print("Build/QA = static prep state plus latest QA badge, e.g. current/✓, mixed/+L, stale/✓, ready/invalid.")
    print("Template = scripted template availability: news, acct, generic, or none.")
    print("Action   = the recommended next operator move shown on the queue.")
    print("locked   = manual phase unavailable until baseline minimum is met.")
    print("mixed    = current-build and legacy-build evidence both exist.")
    print("stale    = installed device build drifted from the newest static plan; rerun harvest/static for this app.")
    print("valid+L  = latest QA valid, legacy evidence also exists.")
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
            ]
            for row in row_models
        ]
        table_utils.render_table(
            ["App", "Base ct", "Base ex", "Manual ct", "Manual ex", "Legacy", "L builds", "Need B", "Need M"],
            raw_rows,
            compact=True,
        )
    prompt_utils.press_enter_to_continue()


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
