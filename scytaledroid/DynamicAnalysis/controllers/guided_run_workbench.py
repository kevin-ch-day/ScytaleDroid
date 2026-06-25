"""Selected-app workbench helpers for guided dynamic runs."""

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
    status_label = str(getattr(latest_recent, "status_label", "") or "UNKNOWN").strip()
    invalid_reason = str(getattr(latest_recent, "invalid_reason_code", "") or "—").strip()
    rows = [
        ["Run ID", run_id or "—"],
        ["Status", status_label or "UNKNOWN"],
        ["Profile", run_profile_label_fn(getattr(latest_recent, "run_profile", None))],
        ["Ended", str(getattr(latest_recent, "ended_at", None) or "—")],
        ["Invalid reason", invalid_reason or "—"],
    ]
    menu_utils.print_table(["Field", "Value"], rows)
    if getattr(latest_recent, "valid", None) is True:
        print(status_messages.status("Latest current-build run is QA-valid.", level="success"))
    elif getattr(latest_recent, "valid", None) is False:
        print(
            status_messages.status(
                "Latest current-build run is QA-invalid and excluded from quota/publication use.",
                level="warn",
            )
        )
    else:
        print(status_messages.status("Latest current-build run has unknown QA status.", level="warn"))
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
        rows.append(
            [
                str(index),
                str(getattr(row, "ended_at", None) or "—"),
                run_profile_label_fn(getattr(row, "run_profile", None)),
                str(getattr(row, "status_label", None) or "UNKNOWN"),
                str(getattr(row, "run_id", None) or "—"),
            ]
        )
    menu_utils.print_table(["#", "Ended", "Profile", "Status", "Run ID"], rows)
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
        ["Queue action", str(queue_action or "—")],
        ["Tracker state", str(getattr(state, "tracker_status", "unknown") or "unknown")],
        ["Evidence state", str(getattr(state, "evidence_status", "unknown") or "unknown")],
        ["Overall state", str(getattr(state, "state_status", "unknown") or "unknown")],
        ["Local evidence packs", str(int(getattr(state, "local_evidence_dir_count", 0) or 0))],
        ["Quota-counted local runs", str(int(getattr(state, "quota_counted_local", 0) or 0))],
        ["Paper-eligible local runs", str(int(getattr(state, "paper_eligible_local", 0) or 0))],
        ["DB current-build sessions", str(int(db_active_sessions))],
        ["DB historical sessions", str(int(db_historical_sessions))],
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


def build_selected_app_protocol_options(
    app: Any,
    *,
    menu_utils: Any,
    queue_action_key_fn: Callable[[str | None], str],
    is_messaging_package_or_category_fn: Callable[[str], bool],
    queue_action_review_qa: str,
    queue_action_restore_local: str,
) -> list[Any]:
    counts = app.counts
    cfg = app.cfg
    baseline_complete = int(counts.baseline_valid_runs) >= int(cfg.baseline_required)
    suggested_default_key = app.suggested_default_key
    scripted_template_ready = app.scripted_template_ready
    can_reset = app.can_reset
    is_messaging = is_messaging_package_or_category_fn(app.package_name)
    queue_action = queue_action_key_fn(app.queue_action)

    def _badge_for(key: str) -> str | None:
        if not app.state.suggested_slot:
            return None
        return "suggested" if key == suggested_default_key else None

    def _baseline_option_description() -> str:
        if int(counts.baseline_valid_runs) < int(cfg.baseline_required):
            return "suggested · counts toward quota"
        return "supplemental · outside quota"

    def _interactive_option_description(*, template_available: bool = True) -> str:
        if not template_available:
            return "unavailable"
        if not baseline_complete:
            return "held until baseline complete"
        if int(counts.interactive_valid_runs) < int(cfg.interactive_required):
            return "counts toward quota"
        return "supplemental · outside quota"

    options = [
        menu_utils.MenuOption(
            "A",
            "Review QA",
            description="no device",
            badge=("suggested" if queue_action == queue_action_review_qa else None),
        ),
        menu_utils.MenuOption("H", "Run history", description="no device", badge=None),
        menu_utils.MenuOption("G", "Diagnostics", description="no device", badge=None),
        menu_utils.MenuOption(
            "1",
            "Baseline (connected)" if is_messaging else "Baseline",
            description=_baseline_option_description(),
            badge=_badge_for("1"),
        ),
        menu_utils.MenuOption(
            "2",
            "Scripted",
            description=_interactive_option_description(template_available=scripted_template_ready),
            badge=_badge_for("2"),
            disabled=(not scripted_template_ready),
        ),
        menu_utils.MenuOption(
            "3",
            "Manual",
            description=(
                "suggested · counts toward quota"
                if _interactive_option_description() == "counts toward quota"
                else _interactive_option_description()
            ),
            badge=_badge_for("3"),
        ),
        menu_utils.MenuOption("4", "Test app", description="no saving", badge=None),
        menu_utils.MenuOption(
            "D",
            "Reset app (dangerous)",
            description=("enabled" if can_reset else "disabled"),
            badge=None,
            disabled=(not can_reset),
        ),
    ]
    if queue_action == queue_action_restore_local:
        options.insert(
            1,
            menu_utils.MenuOption(
                "R",
                "Restore / recollect",
                description="suggested · recover current-build evidence",
                badge="suggested",
            ),
        )
    return options


def print_selected_app_workbench_summary(
    app: Any,
    *,
    status_messages: Any,
    selected_app_active_valid_runs_fn: Callable[[Any], int],
    selected_app_lineage_state_fn: Callable[..., str],
    print_selected_app_evidence_context_fn: Callable[..., None],
    print_selected_app_state_summary_fn: Callable[..., None],
    print_selected_app_queue_action_fn: Callable[[str, str | None], None],
    is_messaging_package_or_category_fn: Callable[[str], bool],
) -> None:
    active_valid_runs = selected_app_active_valid_runs_fn(app)
    lineage_state = selected_app_lineage_state_fn(
        active_valid_runs=active_valid_runs,
        legacy_valid_runs=app.historical_valid_local,
        db_active_sessions=app.db_active_sessions,
        db_historical_sessions=app.db_historical_sessions,
    )
    if app.meta_family_note:
        print(
            status_messages.status(
                "Meta-family app: Facebook, Messenger, Instagram, and WhatsApp are tracked as separate apps.",
                level="info",
            )
        )
    print_selected_app_evidence_context_fn(
        package_name=app.package_name,
        active_valid_runs=active_valid_runs,
        legacy_valid_runs=app.historical_valid_local,
        historical_build_count=app.historical_build_count,
        db_active_sessions=app.db_active_sessions,
        db_historical_sessions=app.db_historical_sessions,
    )
    print_selected_app_state_summary_fn(
        lineage_state=lineage_state,
        active_valid_runs=active_valid_runs,
        legacy_valid_runs=app.historical_valid_local,
        db_active_sessions=app.db_active_sessions,
        db_historical_sessions=app.db_historical_sessions,
        latest_valid=app.latest_valid,
        queue_action=app.queue_action,
        baseline_valid_runs=int(app.counts.baseline_valid_runs),
        interactive_valid_runs=int(app.counts.interactive_valid_runs),
        baseline_required=int(app.cfg.baseline_required),
        interactive_required=int(app.cfg.interactive_required),
        extra_valid_runs=app.extra_valid_local,
    )
    print_selected_app_queue_action_fn(app.queue_action, app.queue_reason)
    if (
        is_messaging_package_or_category_fn(app.package_name)
        and int(app.counts.baseline_valid_runs) < int(app.cfg.baseline_required)
    ):
        print(
            status_messages.status(
                "Messaging baseline uses connected idle: open an existing conversation thread and keep it visible; no send/call.",
                level="info",
            )
        )
    if app.extra_valid_local > 0:
        print(
            status_messages.status(
                f"Supplemental current-build evidence: {app.extra_valid_local} extra valid run(s) retained outside quota.",
                level="info",
            )
        )


def handle_selected_app_aux_action(
    *,
    selected_protocol: str,
    app: Any,
    print_tier1_qa_result: Callable[[str], None] | None,
    prompt_utils: Any,
    status_messages: Any,
    menu_utils: Any,
    render_selected_app_review_fn: Callable[..., None],
    render_selected_app_recent_runs_fn: Callable[[Any], None],
    render_selected_app_diagnostics_fn: Callable[..., None],
) -> str | None:
    if selected_protocol == "A":
        render_selected_app_review_fn(
            display_label=app.display_label,
            latest_recent=app.latest_recent,
            print_tier1_qa_result=print_tier1_qa_result,
        )
        prompt_utils.press_enter_to_continue()
        return None
    if selected_protocol == "H":
        render_selected_app_recent_runs_fn(app.state)
        prompt_utils.press_enter_to_continue()
        return None
    if selected_protocol == "G":
        render_selected_app_diagnostics_fn(
            package_name=app.package_name,
            display_label=app.display_label,
            state=app.state,
            queue_action=app.queue_action,
            db_active_sessions=app.db_active_sessions,
            db_historical_sessions=app.db_historical_sessions,
        )
        prompt_utils.press_enter_to_continue()
        return None
    if selected_protocol == "R":
        print()
        menu_utils.print_header("Restore / Recollect")
        print(
            status_messages.status(
                "Current-build sessions exist in the DB, but the local evidence pack is missing from this workspace.",
                level="warn",
            )
        )
        print("Recommended path:")
        print("Restore the missing evidence pack if you have it, or recollect a current-build baseline now.")
        print()
        if prompt_utils.prompt_yes_no("Start baseline recollection for the installed build now?", default=True):
            return "1"
        return None
    return selected_protocol


def render_selected_app_workbench(
    *,
    app: Any,
    print_tier1_qa_result: Callable[[str], None] | None,
    menu_utils: Any,
    prompt_utils: Any,
    queue_action_key_fn: Callable[[str | None], str],
    queue_action_review_qa: str,
    build_selected_app_protocol_options_fn: Callable[[Any], list[Any]],
    print_selected_app_workbench_summary_fn: Callable[[Any], None],
    handle_selected_app_aux_action_fn: Callable[..., str | None],
) -> str:
    protocol_options = build_selected_app_protocol_options_fn(app)
    default_choice = (
        "A"
        if queue_action_key_fn(app.queue_action) == queue_action_review_qa
        else (app.suggested_default_key if app.suggested_is_interactive else "1")
    )
    menu_utils.print_header("Dynamic Workbench", app.display_label)
    print_selected_app_workbench_summary_fn(app)
    while True:
        menu_utils.print_section("Actions")
        menu_utils.render_menu(
            menu_utils.MenuSpec(
                items=protocol_options,
                default=default_choice,
                exit_label="Back",
                show_exit=True,
                show_descriptions=True,
                compact=True,
            )
        )
        selected_protocol = prompt_utils.get_choice(
            menu_utils.selectable_keys(protocol_options, include_exit=True),
            default=default_choice,
            casefold=True,
            invalid_message="Choose one of the listed actions.",
            disabled=[option.key for option in protocol_options if option.disabled],
        ).upper()
        resolved_protocol = handle_selected_app_aux_action_fn(
            selected_protocol=selected_protocol,
            app=app,
            print_tier1_qa_result=print_tier1_qa_result,
        )
        if resolved_protocol is None:
            continue
        return resolved_protocol


__all__ = [
    "build_selected_app_protocol_options",
    "handle_selected_app_aux_action",
    "print_selected_app_workbench_summary",
    "render_selected_app_diagnostics",
    "render_selected_app_recent_runs",
    "render_selected_app_review",
    "render_selected_app_workbench",
]
