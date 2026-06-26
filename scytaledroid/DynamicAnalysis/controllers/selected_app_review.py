"""Selected-app review and diagnostics surfaces."""

from __future__ import annotations

from typing import Any, Callable


def render_selected_app_review(
    *,
    display_label: str,
    latest_recent: Any,
    print_tier1_qa_result: Callable[[str], None] | None,
    menu_utils: Any,
    status_messages: Any,
    run_profile_label_fn: Callable[[str | None], str],
) -> None:
    print()
    menu_utils.print_header("Stored QA Review", display_label)
    if latest_recent is None:
        print(
            status_messages.status(
                "No stored current-build run is available yet for QA review.",
                level="warn",
            )
        )
        return
    run_id = str(getattr(latest_recent, "run_id", "") or "").strip()
    if getattr(latest_recent, "valid", None) is True:
        qa_status = "QA valid"
    elif getattr(latest_recent, "valid", None) is False:
        qa_status = "QA invalid"
    else:
        qa_status = "QA unknown"
    invalid_reason = str(getattr(latest_recent, "invalid_reason_code", "") or "—").strip()
    rows = [
        ["Run ID", run_id or "—"],
        ["QA status", qa_status],
        ["Profile", run_profile_label_fn(getattr(latest_recent, "run_profile", None))],
        ["Ended", str(getattr(latest_recent, "ended_at", None) or "—")],
        ["Invalid reason", invalid_reason or "—"],
    ]
    menu_utils.print_table(["Field", "Value"], rows)
    if getattr(latest_recent, "valid", None) is True:
        print(status_messages.status("Latest current-build run is QA valid.", level="success"))
    elif getattr(latest_recent, "valid", None) is False:
        print(
            status_messages.status(
                "Latest current-build run is QA invalid and excluded from quota/publication use.",
                level="warn",
            )
        )
    else:
        print(status_messages.status("Latest current-build run has QA unknown status.", level="warn"))
    if print_tier1_qa_result and run_id:
        try:
            print_tier1_qa_result(run_id)
        except Exception as exc:
            print(status_messages.status(f"QA detail rendering failed: {exc}", level="warn"))


def render_selected_app_recent_runs(
    state: Any,
    *,
    menu_utils: Any,
    status_messages: Any,
    run_profile_label_fn: Callable[[str | None], str],
) -> None:
    print()
    menu_utils.print_header("Recent Tracker Runs")
    recent_runs = tuple(getattr(state, "recent_runs", ()) or ())
    if not recent_runs:
        print(status_messages.status("No recent tracker-scoped runs are stored for this app.", level="warn"))
        return
    rows: list[list[str]] = []
    for index, row in enumerate(recent_runs, start=1):
        if getattr(row, "valid", None) is True:
            qa_label = "QA valid"
        elif getattr(row, "valid", None) is False:
            qa_label = "QA invalid"
        else:
            qa_label = "QA unknown"
        rows.append(
            [
                str(index),
                str(getattr(row, "ended_at", None) or "—"),
                run_profile_label_fn(getattr(row, "run_profile", None)),
                qa_label,
                str(getattr(row, "run_id", None) or "—"),
            ]
        )
    menu_utils.print_table(["#", "Ended", "Profile", "QA", "Run ID"], rows)
    if int(getattr(state, "baseline_idle_pcap_missing_streak", 0) or 0) > 0:
        print(
            status_messages.status(
                f"Recent baseline PCAP-missing streak: {int(getattr(state, 'baseline_idle_pcap_missing_streak', 0) or 0)}",
                level="warn",
            )
        )
    if int(getattr(state, "baseline_idle_low_signal_streak", 0) or 0) > 0:
        print(
            status_messages.status(
                f"Recent low-signal baseline streak: {int(getattr(state, 'baseline_idle_low_signal_streak', 0) or 0)}",
                level="warn",
            )
        )
    if int(getattr(state, "baseline_connected_insufficient_duration_streak", 0) or 0) > 0:
        print(
            status_messages.status(
                "Recent messaging baseline streak: insufficient duration on connected-idle baselines.",
                level="warn",
            )
        )


def render_selected_app_diagnostics(
    *,
    package_name: str,
    display_label: str,
    state: Any,
    queue_action: str,
    db_active_sessions: int,
    db_historical_sessions: int,
    menu_utils: Any,
) -> None:
    print()
    menu_utils.print_header("Diagnostics", display_label)
    rows = [
        ["Package", package_name],
        ["Recommended action", str(queue_action or "—")],
        ["Tracker-scoped latest-run state", str(getattr(state, "tracker_status", "unknown") or "unknown")],
        ["Evidence lineage state", str(getattr(state, "evidence_status", "unknown") or "unknown")],
        ["Workflow state", str(getattr(state, "state_status", "unknown") or "unknown")],
        ["Local evidence packs", str(int(getattr(state, "local_evidence_dir_count", 0) or 0))],
        ["Quota-valid local runs", str(int(getattr(state, "quota_counted_local", 0) or 0))],
        ["Paper-eligible local runs", str(int(getattr(state, "paper_eligible_local", 0) or 0))],
        ["DB current-build evidence", str(int(db_active_sessions))],
        ["DB historical evidence", str(int(db_historical_sessions))],
    ]
    menu_utils.print_table(["Field", "Value"], rows)
    top = tuple(getattr(state, "exclusion_reason_top", ()) or ())
    if top:
        print()
        menu_utils.print_section("Top Exclusions")
        menu_utils.print_table(
            ["Reason", "Count"],
            [[str(reason), str(int(count))] for reason, count in top],
        )


__all__ = [
    "render_selected_app_diagnostics",
    "render_selected_app_recent_runs",
    "render_selected_app_review",
]
