"""State summary rendering helpers for Dynamic Analysis menus."""

from __future__ import annotations

from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages, table_utils


def render_compact_state_summary(
    *,
    summary: object,
    state_payload: dict[str, object],
    capture_environment_summary_fn,
    active_research_cohort_label_fn,
    tracker_path_fn,
    bool_text_fn,
) -> bool:
    env = capture_environment_summary_fn()
    cohort_label = active_research_cohort_label_fn()
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
    repeatability = (
        state_payload.get("repeatability_summary")
        if isinstance(state_payload.get("repeatability_summary"), dict)
        else {}
    )
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
                    f"{int(repeatability.get('runs_repeatability_ready') or 0)}/"
                    f"{int(repeatability.get('runs_total') or 0)}",
                ),
                ("freeze role", str(repeatability.get("freeze_role") or "none")),
                (
                    "publication manifests",
                    bool_text_fn(repeatability.get("publication_manifests_present")),
                ),
            ],
        ),
        (
            "Evidence",
            [
                ("evidence packs", f"{total_runs} total / {valid_runs} valid / {max(total_runs - valid_runs, 0)} invalid"),
                ("incomplete dirs", str(missing_run_manifest_dirs)),
                ("evidence root exists", bool_text_fn(evidence_root_exists)),
                ("evidence root", evidence_root),
            ],
        ),
        (
            "Tracker",
            [
                ("tracker exists", bool_text_fn(tracker_path_fn().exists())),
                ("tracker rows", str(tracker_runs_hint)),
                ("tracker/evidence mismatches", str(mismatches)),
                ("dataset rows evaluated", str(tracker_rows)),
            ],
        ),
        (
            "Freeze",
            [
                ("can_freeze", bool_text_fn(summary.can_freeze)),
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
    return True
