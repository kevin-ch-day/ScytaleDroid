"""Cohort status report rendering for Dynamic Analysis menus."""

from __future__ import annotations

import os

from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages, table_utils


def count_tracker_runs(apps: object) -> int:
    if not isinstance(apps, dict):
        return 0
    return sum(
        len(entry.get("runs", []))
        for entry in apps.values()
        if isinstance(entry, dict) and isinstance(entry.get("runs"), list)
    )


def render_dataset_status(
    *,
    active_research_cohort_label_fn,
    run_freeze_readiness_audit_fn,
    build_state_summary_fn,
    group_artifacts_fn,
    load_display_name_map_fn,
    tracker_path_fn,
    freeze_path_fn,
) -> None:
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
        DatasetTrackerConfig,
        load_dataset_tracker,
    )

    print()
    menu_utils.print_header("Cohort Status Overview")
    menu_utils.print_hint(
        "Review cohort progress from local evidence packs and tracker state without starting collection."
    )
    cohort_label = active_research_cohort_label_fn()
    print(status_messages.status(f"Active research cohort: {cohort_label}", level="info"))
    summary = run_freeze_readiness_audit_fn()
    state_payload = build_state_summary_fn()
    handoff = (
        state_payload.get("static_handoff_plan_summary")
        if isinstance(state_payload.get("static_handoff_plan_summary"), dict)
        else {}
    )
    try:
        display_names = load_display_name_map_fn(group_artifacts_fn())
    except Exception:
        display_names = {}
    payload = load_dataset_tracker()
    apps = payload.get("apps", {})
    tracker_exists = tracker_path_fn().exists()
    tracker_rows = count_tracker_runs(apps)
    if not tracker_rows:
        rows = [
            ("Research cohort", cohort_label),
            ("Cohort runs", "none recorded"),
            ("Evidence packs", str(int(summary.total_runs))),
            ("Tracker", "present" if tracker_exists else "missing"),
            ("Freeze file", "present" if freeze_path_fn().exists() else "missing"),
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
        headers = [
            "Package",
            "Display",
            "Target",
            "Runs",
            "Valid packs",
            "Latest run",
            "Freeze eligible",
            "Blocking reason",
        ]
        table_utils.render_table(
            headers,
            ([row.get(header) for header in headers] for row in rows),
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
