"""Maintenance and archive helper menus for Dynamic Analysis."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.freeze_eligibility import derive_freeze_eligibility
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.menus.summary_support import (
    build_collection_priorities,
    compute_tracker_vs_evidence_deltas,
    min_windows_per_run,
)
from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_packages
from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root, resolve_dynamic_run_dir
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, table_utils
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption


@dataclass(frozen=True)
class LegacyStructuralCallbacks:
    run_guided_capture: Callable[[], None]
    show_runbook: Callable[[], None]
    show_recapture_plan: Callable[[], None]
    show_status_dashboard: Callable[[], None]
    show_integrity_gates: Callable[[], None]
    build_manifest: Callable[[], None]


@dataclass(frozen=True)
class DynamicMaintenanceCallbacks:
    run_state_summary: Callable[[], None]
    read_json: Callable[[Path], dict | None]
    min_windows_per_run: Callable[[], int]
    summarize_evidence_quota: Callable[[set[str], object], dict[str, int | bool]]


def legacy_structural_archive_menu(
    *,
    callbacks: LegacyStructuralCallbacks,
    pause_if_verbose: Callable[[], None],
) -> None:
    options = [
        MenuOption("1", "Guided capture"),
        MenuOption("2", "Runbook"),
        MenuOption("3", "Recapture plan"),
        MenuOption("4", "Status dashboard"),
        MenuOption("5", "Integrity gates"),
        MenuOption("6", "Manifest build"),
    ]

    while True:
        print()
        menu_utils.print_header("Archived Structural Cohort")
        menu_utils.print_menu(options, show_exit=True, exit_label="Back", show_descriptions=False, compact=True)
        choice = prompt_utils.get_choice(menu_utils.selectable_keys(options, include_exit=True), default="0")
        if choice == "0":
            return
        if choice == "1":
            callbacks.run_guided_capture()
            pause_if_verbose()
            continue
        if choice == "2":
            callbacks.show_runbook()
            pause_if_verbose()
            continue
        if choice == "3":
            callbacks.show_recapture_plan()
            pause_if_verbose()
            continue
        if choice == "4":
            callbacks.show_status_dashboard()
            pause_if_verbose()
            continue
        if choice == "5":
            callbacks.show_integrity_gates()
            pause_if_verbose()
            continue
        if choice == "6":
            callbacks.build_manifest()
            pause_if_verbose()


def prune_incomplete_dynamic_evidence_dirs(*, run_state_summary: Callable[[], None]) -> None:
    from scytaledroid.DynamicAnalysis.utils.run_cleanup import (
        find_incomplete_dynamic_run_dirs,
        prune_incomplete_dynamic_run_dirs,
    )

    print()
    menu_utils.print_header("Prune Incomplete Dynamic Evidence")
    incomplete = find_incomplete_dynamic_run_dirs()
    if not incomplete:
        print(status_messages.status("No incomplete evidence dirs found.", level="success"))
        print(status_messages.status("Next: run option 3 (State summary) before collection.", level="info"))
        return

    print(
        status_messages.status(
            f"Found {len(incomplete)} incomplete dir(s) missing run_manifest.json.",
            level="warn",
        )
    )
    preview = [p.name for p in incomplete[:10]]
    if preview:
        print(status_messages.status("Examples: " + ", ".join(preview), level="info"))
    confirmed = prompt_utils.prompt_yes_no("Delete these incomplete dirs now? (safe)", default=False)
    if not confirmed:
        print(status_messages.status("Prune canceled.", level="info"))
        return
    deleted = prune_incomplete_dynamic_run_dirs()
    remaining = len(find_incomplete_dynamic_run_dirs())
    print(
        status_messages.status(
            f"Deleted incomplete dirs: {deleted}. Remaining incomplete dirs: {remaining}.",
            level="success" if remaining == 0 else "warn",
        )
    )
    if remaining == 0:
        print(status_messages.status("Next: run option 3 (State summary) to verify CAN_FREEZE and blockers.", level="info"))
        if prompt_utils.prompt_yes_no("Run state summary now?", default=True):
            run_state_summary()
    else:
        print(status_messages.status("Still blocked: cleanup remaining incomplete dirs before freeze/export.", level="warn"))


def repair_reindex_tracker(*, callbacks: DynamicMaintenanceCallbacks) -> None:
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
        DatasetTrackerConfig,
        load_dataset_tracker,
        recompute_dataset_tracker,
    )
    from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import run_freeze_readiness_audit

    print()
    menu_utils.print_header("Repair/Reindex Tracker")
    cfg = DatasetTrackerConfig()
    tracker_before = load_dataset_tracker()
    before_apps = tracker_before.get("apps") if isinstance(tracker_before, dict) else {}
    before_runs = sum(
        len(v.get("runs", []))
        for v in before_apps.values()
        if isinstance(v, dict) and isinstance(v.get("runs"), list)
    ) if isinstance(before_apps, dict) else 0
    evidence_root = dynamic_evidence_root()

    if not evidence_root.exists():
        print(status_messages.status("No dynamic evidence root found.", level="info"))
        print(status_messages.status("Nothing to reindex yet.", level="info"))
        print(status_messages.status("Run Guided research cohort first to create evidence packs.", level="info"))
        return
    if not os.access(evidence_root, os.R_OK):
        print(status_messages.status(f"Evidence root exists but is not readable: {evidence_root}", level="error"))
        return
    evidence_dirs = [p for p in evidence_root.iterdir() if p.is_dir()]
    if not evidence_dirs:
        print(status_messages.status("No dynamic evidence packs found under the evidence root.", level="info"))
        print(status_messages.status("Nothing to reindex yet.", level="info"))
        print(status_messages.status("Run Guided research cohort first to create evidence packs.", level="info"))
        return
    complete_dirs = [p for p in evidence_dirs if (p / "run_manifest.json").exists()]
    if not complete_dirs:
        print(status_messages.status("No complete dynamic evidence packs found.", level="info"))
        print(status_messages.status(f"Incomplete evidence dirs found: {len(evidence_dirs)}", level="warn"))
        print(status_messages.status("Nothing to reindex yet. Use Prune incomplete evidence or run a cohort.", level="info"))
        return

    if before_runs > 0:
        print(
            status_messages.status(
                "Reindex rebuilds tracker from local evidence packs only and drops tracker-only historical rows.",
                level="warn",
            )
        )
        confirmed = prompt_utils.prompt_yes_no(
            f"Proceed with reindex? current tracker runs={before_runs}",
            default=False,
        )
        if not confirmed:
            print(status_messages.status("Reindex canceled.", level="info"))
            return

    summary_before = run_freeze_readiness_audit()
    try:
        out = recompute_dataset_tracker(config=cfg)
    except Exception as exc:
        print(status_messages.status(f"Reindex failed unexpectedly: {exc}", level="error"))
        return
    if out is None:
        print(
            status_messages.status(
                "No dynamic evidence packs are present, so there is nothing to reindex yet.",
                level="info",
            )
        )
        print(status_messages.status("Next: use option 1 (Focused app run) or option 2 (Cohort run) to create evidence packs.", level="info"))
        return

    tracker_after = load_dataset_tracker()
    apps = tracker_after.get("apps") if isinstance(tracker_after, dict) else {}
    app_count = len(apps) if isinstance(apps, dict) else 0
    run_count = 0
    valid_count = 0
    missing_window_count = 0
    missing_paper_identity_count = 0
    for entry in (apps.values() if isinstance(apps, dict) else []):
        if not isinstance(entry, dict):
            continue
        runs = entry.get("runs")
        if not isinstance(runs, list):
            continue
        for run in runs:
            if not isinstance(run, dict):
                continue
            run_count += 1
            if run.get("valid_dataset_run") is not True:
                continue
            valid_count += 1
            if run.get("window_count") in (None, ""):
                missing_window_count += 1
            run_id = str(run.get("run_id") or "").strip()
            if not run_id:
                missing_paper_identity_count += 1
                continue
            run_dir = resolve_dynamic_run_dir(run_id)
            manifest = callbacks.read_json(run_dir / "run_manifest.json") if run_dir else {}
            plan = callbacks.read_json(run_dir / "inputs" / "static_dynamic_plan.json") if run_dir else {}
            manifest = manifest or {}
            plan = plan or {}
            eligibility = derive_freeze_eligibility(
                manifest=manifest,
                plan=plan,
                min_windows=callbacks.min_windows_per_run(),
                required_capture_policy_version=int(profile_config.PAPER_CONTRACT_VERSION),
            )
            if not eligibility.paper_eligible and eligibility.reason_code == "EXCLUDED_MISSING_REQUIRED_IDENTITY_FIELD":
                missing_paper_identity_count += 1

    evidence_summary = callbacks.summarize_evidence_quota(
        {pkg.lower() for pkg in active_research_cohort_packages()},
        cfg,
    )
    expected_runs = len(active_research_cohort_packages()) * (int(cfg.baseline_required) + int(cfg.interactive_required))
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    report_path = Path(app_config.OUTPUT_DIR) / "audit" / "dynamic" / f"tracker_reindex_{stamp}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_payload = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "tracker_path": str(out),
        "evidence_packs_found": int(summary_before.total_runs),
        "evidence_valid_packs_found": int(summary_before.valid_runs),
        "evidence_invalid_packs_found": max(int(summary_before.total_runs) - int(summary_before.valid_runs), 0),
        "evidence_incomplete_dirs_found": int(summary_before.missing_run_manifest_dirs),
        "tracker_before_runs": int(before_runs),
        "tracker_after_runs": int(run_count),
        "tracker_after_apps": int(app_count),
        "valid_runs": int(valid_count),
        "missing_window_count_in_valid_runs": int(missing_window_count),
        "missing_paper_identity_in_valid_runs": int(missing_paper_identity_count),
        "evidence_root_exists": bool(evidence_summary.get("evidence_root_exists")),
        "evidence_quota_runs_counted": int(evidence_summary.get("quota_runs_counted", 0)),
        "evidence_paper_eligible_runs": int(evidence_summary.get("paper_eligible_runs", 0)),
        "expected_runs": int(expected_runs),
    }
    report_path.write_text(json.dumps(report_payload, indent=2, sort_keys=True), encoding="utf-8")

    rows = [
        ("Evidence packs found", str(summary_before.total_runs)),
        ("Valid evidence packs", str(summary_before.valid_runs)),
        ("Invalid evidence packs", str(max(int(summary_before.total_runs) - int(summary_before.valid_runs), 0))),
        ("Incomplete evidence dirs", str(summary_before.missing_run_manifest_dirs)),
        ("Tracker runs (before)", str(before_runs)),
        ("Tracker runs (after)", str(run_count)),
        ("Tracker apps (after)", str(app_count)),
        ("Valid runs (after)", str(valid_count)),
        ("Valid runs missing window_count", str(missing_window_count)),
        ("Valid runs missing required identity fields", str(missing_paper_identity_count)),
        ("Evidence quota counted", f"{int(evidence_summary.get('quota_runs_counted', 0))}/{expected_runs}"),
        ("Evidence eligible", str(int(evidence_summary.get('paper_eligible_runs', 0)))),
    ]
    ui_level = str(os.environ.get("SCYTALEDROID_UI_LEVEL") or "").strip().lower()
    verbose = ui_level in {"details", "debug"}
    if verbose:
        table_utils.render_table(["Metric", "Count"], rows, compact=False)
    else:
        quota_line = next((value for key, value in rows if key == "Evidence quota counted"), "")
        print(
            status_messages.status(
                f"Reindex complete | packs={summary_before.total_runs} valid_packs={summary_before.valid_runs} "
                f"| tracker_runs={run_count} apps={app_count} | quota={quota_line}",
                level="success",
            )
        )
    print(status_messages.status(f"Tracker reindexed from evidence: {out}", level="success"))
    print(status_messages.status(f"Report: {report_path}", level="info"))

    db_sync: dict[str, object] = {"attempted": False, "skipped_reason": None}
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.DynamicAnalysis.storage.index_from_evidence import index_dynamic_evidence_packs_to_db

        if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
            db_sync["skipped_reason"] = "db_disabled"
        else:
            db_sync["attempted"] = True
            db_result = index_dynamic_evidence_packs_to_db(evidence_root)
            db_sync.update(db_result if isinstance(db_result, dict) else {"ok": bool(db_result)})
            indexed = int((db_result or {}).get("ok") or 0) if isinstance(db_result, dict) else 0
            print(
                status_messages.status(
                    f"DB sync from evidence complete | indexed={indexed} "
                    f"scanned={(db_result or {}).get('scanned') if isinstance(db_result, dict) else '?'}",
                    level="success" if indexed else "warn",
                )
            )
    except Exception as exc:  # noqa: BLE001
        db_sync["error"] = str(exc)
        print(status_messages.status(f"DB sync from evidence failed (tracker reindex still saved): {exc}", level="warn"))

    if db_sync.get("attempted"):
        report_payload["db_sync"] = db_sync
        report_path.write_text(json.dumps(report_payload, indent=2, sort_keys=True), encoding="utf-8")


def run_freeze_readiness_audit_action() -> None:
    from scytaledroid.DynamicAnalysis.menus.status_reports import run_freeze_readiness_audit_report

    run_freeze_readiness_audit_report()


def run_state_summary_action() -> None:
    from scytaledroid.DynamicAnalysis.menus.status_reports import run_state_summary_report
    from scytaledroid.DynamicAnalysis.tools.evidence.freeze_readiness_audit import (
        run_freeze_readiness_audit,
    )
    from scytaledroid.DynamicAnalysis.tools.evidence.state_summary import build_state_summary

    summary = run_freeze_readiness_audit()
    payload = _read_report_json(Path(summary.report_path))
    state_payload = build_state_summary()
    delta_rows = compute_tracker_vs_evidence_deltas(
        read_json=_read_report_json,
        min_windows_per_run=min_windows_per_run,
    )
    priorities = build_collection_priorities(delta_rows)
    run_state_summary_report(
        summary=summary,
        payload=payload,
        state_payload=state_payload,
        delta_rows=delta_rows,
        priorities=priorities,
    )


def verify_host_pcap_tools_action() -> None:
    from scytaledroid.DynamicAnalysis.menus.status_reports import render_host_pcap_tools

    render_host_pcap_tools()


def choose_active_research_cohort_action(
    *,
    chooseable_active_research_cohorts_fn,
    active_research_cohort_key_fn,
    persist_active_research_cohort_key_fn,
) -> dict[str, object] | None:
    rows = chooseable_active_research_cohorts_fn()
    if not rows:
        print(status_messages.status("No active app cohorts are defined in the DB.", level="warn"))
        return None

    print()
    menu_utils.print_header(
        "Select Cohort",
        "Choose the DB-backed app cohort used for dynamic runs and readiness review.",
    )
    preferred_key = active_research_cohort_key_fn()
    table_rows = [
        [
            str(idx),
            str(row.get("display_name") or row.get("cohort_key") or ""),
            str(int(row.get("active_member_count") or 0)),
            "active" if str(row.get("cohort_key") or "").strip().lower() == str(preferred_key or "").strip().lower() else "",
        ]
        for idx, row in enumerate(rows, start=1)
    ]
    table_utils.render_table(["#", "Cohort", "Apps", "State"], table_rows, compact=True, padding=2)
    default_choice = "1"
    for idx, row in enumerate(rows, start=1):
        if str(row.get("cohort_key") or "").strip().lower() == str(preferred_key or "").strip().lower():
            default_choice = str(idx)
            break
    print()
    choice = prompt_utils.get_choice(
        [str(index) for index in range(1, len(rows) + 1)] + ["0"],
        default=default_choice,
        prompt="Select cohort #",
    )
    if choice == "0":
        print(status_messages.status("Cohort selection canceled.", level="info"))
        return None
    selected = rows[int(choice) - 1]
    cohort_key = str(selected.get("cohort_key") or "").strip().lower()
    label = str(selected.get("display_name") or cohort_key).strip() or cohort_key
    member_count = int(selected.get("active_member_count") or 0)
    if cohort_key == str(preferred_key or "").strip().lower():
        return dict(selected)
    receipt = persist_active_research_cohort_key_fn(cohort_key, label=label)
    print(status_messages.status(f"Active cohort set to {label} ({member_count} apps).", level="success"))
    print(status_messages.status(f"Saved under {receipt}", level="info"))
    return dict(selected)


def _read_report_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}
