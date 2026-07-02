"""Selected-app review and diagnostics surfaces."""

from __future__ import annotations

from typing import Any, Callable

from scytaledroid.DynamicAnalysis.services.dynamic_target_state import derive_dynamic_target_state
from scytaledroid.Utils.DisplayUtils.summary_cards import print_summary_card, summary_item


def _dataset_impact_label(latest_recent: Any) -> str:
    valid = getattr(latest_recent, "valid", None)
    if valid is True:
        supplemental_reason = str(getattr(latest_recent, "supplemental_reason", "") or "").strip().upper()
        if supplemental_reason == "LOW_SIGNAL_IDLE":
            return "ML training pool (LOW_SIGNAL_IDLE)"
        if supplemental_reason == "BASELINE_NOT_IDLE":
            return "ML training pool (BASELINE_NOT_IDLE)"
        if supplemental_reason == "MANUAL_EXTRA_RUN":
            return "retained extra (manual extra)"
        if supplemental_reason == "SCRIPTED_EXTRA_RUN":
            return "retained extra (scripted extra)"
        if supplemental_reason == "EXTRA_RUN":
            return "ML training pool (supplemental baseline)"
        if getattr(latest_recent, "countable", None) is True:
            return "quota-counted"
        return "valid retained"
    if valid is False:
        return "excluded from quota/publication"
    return "unknown"


def _next_step_lines(*, valid: bool | None, invalid_reason: str) -> list[str]:
    reason = str(invalid_reason or "").strip().upper()
    if valid is True:
        return [
            "Next step:",
            "This review is display-only; no acceptance action is required here.",
            "Return to the app screen for supplemental baseline, interactive, or manual evidence.",
        ]
    if valid is False:
        if reason == "PCAP_MISSING":
            return [
                "Next step:",
                "This review is display-only; the stored run remains excluded from quota/publication use.",
                "Recollect a current-build run after verifying PCAP capture/export is working.",
            ]
        if reason == "PCAP_TOO_SMALL":
            return [
                "Next step:",
                "This review is display-only; the stored run remains excluded from quota/publication use.",
                "Recollect a longer or higher-signal current-build run before relying on it.",
            ]
        return [
            "Next step:",
            "This review is display-only; the stored run remains excluded from quota/publication use.",
            "Collect a replacement current-build run before relying on this app for publication/archive readiness.",
        ]
    return [
        "Next step:",
        "This review is display-only; no stored QA verdict is available to accept or reject here.",
        "Use run history and diagnostics to decide whether recollection is needed.",
    ]


def _qa_status_label(valid: bool | None) -> str:
    if valid is True:
        return "QA valid"
    if valid is False:
        return "QA invalid"
    return "QA unknown"


def _qa_value_style(valid: bool | None) -> str:
    if valid is True:
        return "success"
    if valid is False:
        return "warning"
    return "muted"


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
    valid = getattr(latest_recent, "valid", None)
    qa_status = _qa_status_label(valid)
    invalid_reason = str(getattr(latest_recent, "invalid_reason_code", "") or "—").strip()
    pcap_failure_detail = str(getattr(latest_recent, "pcap_failure_detail", "") or "").strip()
    dataset_impact = _dataset_impact_label(latest_recent)
    profile_label = run_profile_label_fn(getattr(latest_recent, "run_profile", None))
    print_summary_card(
        display_label,
        [
            summary_item("QA", qa_status, value_style=_qa_value_style(valid)),
            summary_item("Dataset impact", dataset_impact, value_style="accent"),
            summary_item("Profile", profile_label, value_style="muted"),
            summary_item("Run ID", run_id or "—", value_style="muted"),
            summary_item("Ended", str(getattr(latest_recent, "ended_at", None) or "—"), value_style="muted"),
        ],
        subtitle="Stored QA review",
    )
    print()
    rows = [
        ["Invalid reason", invalid_reason or "—"],
    ]
    if valid is False and pcap_failure_detail:
        rows.append(["PCAP detail", pcap_failure_detail])
    if len(rows) > 0:
        menu_utils.print_table(["Field", "Value"], rows)
    if valid is True:
        print(status_messages.status("Latest current-build run is QA valid.", level="success"))
    elif valid is False:
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
    print()
    next_lines = _next_step_lines(valid=valid, invalid_reason=invalid_reason)
    if next_lines:
        print(status_messages.status(next_lines[0], level="info"))
        for line in next_lines[1:]:
            if line.strip():
                print(status_messages.status(line, level="info", show_prefix=False))


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
    print(status_messages.status(f"{len(recent_runs)} recent tracker-scoped run(s) on file.", level="info"))
    print()
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
                _dataset_impact_label(row),
                str(getattr(row, "run_id", None) or "—"),
            ]
        )
    menu_utils.print_table(["#", "Ended", "Profile", "QA", "Dataset", "Run ID"], rows)
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
    latest_recent: Any = None,
    has_identity_mismatch: bool = False,
    live_build_drift: bool | None = None,
    menu_utils: Any,
) -> None:
    print()
    target_state = derive_dynamic_target_state(
        package_name=package_name,
        state=state,
        latest_recent=latest_recent,
        db_active_sessions=db_active_sessions,
        db_historical_sessions=db_historical_sessions,
        has_identity_mismatch=has_identity_mismatch,
        live_build_drift=live_build_drift,
        study_identity_available=bool(
            str(getattr(state, "active_version_code", "") or "").strip()
            or str(getattr(state, "active_base_sha", "") or "").strip()
        ),
    )
    study_build = "—"
    if target_state.study_identity.version_code:
        study_build = str(target_state.study_identity.version_code)
    ml_pool_total = int(getattr(state.counts, "baseline_extra_valid", 0) or 0) + int(
        getattr(state.counts, "baseline_low_signal_valid", 0) or 0
    )
    print_summary_card(
        display_label,
        [
            summary_item("Recommended", str(queue_action or "—"), value_style="accent"),
            summary_item("Study", target_state.study_status, value_style="muted"),
            summary_item("Live device", target_state.live_device_status, value_style="muted"),
            summary_item("Capture", target_state.capture_status, value_style="muted"),
            summary_item("Publication", target_state.publication_status, value_style="muted"),
            summary_item("Study build", study_build, value_style="muted"),
            summary_item(
                "Quota baseline",
                f"{int(getattr(state.counts, 'baseline_valid_runs', 0) or 0)} / {int(getattr(state, 'baseline_required', 0) or 0)}",
                value_style="muted",
            ),
            summary_item(
                "Quota interactive",
                f"{int(getattr(state.counts, 'interactive_valid_runs', 0) or 0)} / {int(getattr(state, 'interactive_required', 0) or 0)}",
                value_style="muted",
            ),
            summary_item("ML pool", str(ml_pool_total), value_style="accent" if ml_pool_total > 0 else "muted"),
        ],
        subtitle="Diagnostics",
    )
    print()
    rows = [
        ["Package", package_name],
        [
            "Historical evidence",
            f"{int(target_state.historical.valid_runs)} valid run(s) across {int(target_state.historical.build_count)} build(s)",
        ],
        ["Identity mismatch", "yes" if target_state.has_identity_mismatch else "no"],
        ["Tracker-scoped latest-run state", str(getattr(state, "tracker_status", "unknown") or "unknown")],
        ["Evidence lineage state", str(getattr(state, "evidence_status", "unknown") or "unknown")],
        ["Workflow state", str(getattr(state, "state_status", "unknown") or "unknown")],
        ["Local evidence packs", str(int(getattr(state, "local_evidence_dir_count", 0) or 0))],
        [
            "Quota-counted baseline",
            f"{int(getattr(state.counts, 'baseline_valid_runs', 0) or 0)} / {int(getattr(state, 'baseline_required', 0) or 0)}",
        ],
        [
            "Quota-counted interactive",
            f"{int(getattr(state.counts, 'interactive_valid_runs', 0) or 0)} / {int(getattr(state, 'interactive_required', 0) or 0)}",
        ],
        [
            "ML training pool (baseline)",
            (
                f"supplemental={int(getattr(state.counts, 'baseline_extra_valid', 0) or 0)}"
                f" | low-signal={int(getattr(state.counts, 'baseline_low_signal_valid', 0) or 0)}"
                f" | total={int(getattr(state.counts, 'baseline_extra_valid', 0) or 0) + int(getattr(state.counts, 'baseline_low_signal_valid', 0) or 0)}"
            ),
        ],
        [
            "Retained extra interactive",
            (
                f"extra={int(getattr(state.counts, 'interactive_extra_valid', 0) or 0)}"
                f" | low-signal={int(getattr(state.counts, 'interactive_low_signal_valid', 0) or 0)}"
            ),
        ],
        ["Quota-valid local runs", str(int(getattr(state, "quota_counted_local", 0) or 0))],
        ["Paper-eligible local runs", str(int(getattr(state, "paper_eligible_local", 0) or 0))],
        ["DB current-build evidence", str(int(db_active_sessions))],
        ["DB historical evidence", str(int(db_historical_sessions))],
    ]
    if target_state.latest_invalid_reason:
        rows.append(["Latest invalid reason", target_state.latest_invalid_reason])
    if target_state.latest_pcap_failure_detail:
        rows.append(["Latest PCAP detail", target_state.latest_pcap_failure_detail])
    menu_utils.print_section("Detail")
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
    "_next_step_lines",
    "render_selected_app_diagnostics",
    "render_selected_app_recent_runs",
    "render_selected_app_review",
]
