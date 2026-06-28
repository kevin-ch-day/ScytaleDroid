"""Selected-app action menu and recommendation surfaces."""

from __future__ import annotations

from typing import Any, Callable

from scytaledroid.DynamicAnalysis.controllers.selected_app_state import (
    selected_app_build_text,
    selected_app_evidence_text,
    selected_app_qa_text,
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
            "Interactive",
            description=_interactive_option_description(),
            badge=("suggested" if suggested_default_key in {"2", "3"} else None),
        ),
        menu_utils.MenuOption(
            "3",
            "Test app",
            description="no saving",
            badge=None,
        ),
        menu_utils.MenuOption(
            "X",
            "Reset app",
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


def _summary_phrase(app: Any) -> str:
    quota = f"quota {int(app.counts.baseline_valid_runs) + int(app.counts.interactive_valid_runs)}/{int(app.cfg.baseline_required) + int(app.cfg.interactive_required)}"
    qa_badge = "—"

    if int(app.counts.baseline_valid_runs) + int(app.counts.interactive_valid_runs) > 0 or int(app.db_active_sessions) > 0:
        build_label = "current"
    elif int(app.historical_valid_local) > 0 or int(app.db_historical_sessions) > 0:
        build_label = "legacy"
    else:
        build_label = "unknown"

    if app.latest_valid is True:
        qa_badge = "✓"
    elif app.latest_valid is False:
        qa_badge = "inv"

    evidence_label = "none"
    if int(app.counts.baseline_valid_runs) + int(app.counts.interactive_valid_runs) > 0:
        evidence_label = "local+db"
    elif int(app.db_active_sessions) > 0:
        evidence_label = "db-only"
    elif int(app.historical_valid_local) > 0:
        evidence_label = "local-only"
    elif int(app.db_historical_sessions) > 0:
        evidence_label = "db-only"

    build = selected_app_build_text(build_label)
    evidence = selected_app_evidence_text(build_label, evidence_label)
    qa = selected_app_qa_text(qa_badge)
    return f"{build} · {evidence} · {qa} · {quota}"


def _recommended_action(
    *,
    app: Any,
    protocol_options: list[Any],
    queue_action_key_fn: Callable[[str | None], str],
    queue_action_review_qa: str,
    queue_action_restore_local: str,
) -> tuple[str, str]:
    action_key = queue_action_key_fn(app.queue_action)
    option_keys = {str(option.key): option for option in protocol_options}

    if action_key == queue_action_review_qa:
        detail = str(app.queue_reason or "").strip()
        if detail:
            return "A", f"QA needs review; {detail}."
        return "A", "QA needs review before this app can be treated as archive-ready."
    if action_key == queue_action_restore_local and "R" in option_keys:
        return "R", "current-build evidence exists in the DB, but the local evidence pack is missing from this workspace."
    if action_key == "baseline":
        return "1", str(app.queue_reason or "baseline quota is not yet met.")
    if action_key in {"scripted_interaction", "manual_interaction"} and "2" in option_keys:
        return "2", str(app.queue_reason or "interactive quota is still missing.")
    if getattr(app.counts, "quota_met", False) and app.latest_valid is True:
        return "2", "quota is already satisfied; this run would be supplemental."
    if int(app.counts.baseline_valid_runs) < int(app.cfg.baseline_required):
        return "1", f"baseline quota is not yet met ({int(app.counts.baseline_valid_runs)}/{int(app.cfg.baseline_required)})."
    if int(app.counts.interactive_valid_runs) < int(app.cfg.interactive_required):
        return "2", f"interactive quota is still missing ({int(app.counts.interactive_valid_runs)}/{int(app.cfg.interactive_required)})."
    return "2", "interactive collection is available as supplemental work."


def _action_line(key: str, label: str, *, is_default: bool = False, disabled: bool = False) -> str:
    line = f"{key}) {label}"
    if is_default:
        line += " [default]"
    if disabled:
        line += " (held)"
    return line


def _render_recommended_screen(
    *,
    app: Any,
    protocol_options: list[Any],
    default_choice: str,
    reason: str,
    menu_utils: Any,
) -> None:
    option_map = {str(option.key): option for option in protocol_options}

    def _label(key: str) -> str:
        option = option_map[key]
        raw = str(option.label)
        if key == "1":
            return "Baseline run"
        if key == "2":
            return "Interactive run"
        if key == "3":
            return "Test app"
        if key == "A":
            return "Review QA"
        if key == "H":
            return "Run history"
        if key == "G":
            return "Diagnostics"
        if key == "X":
            return "Reset app"
        if key == "R":
            return "Restore / recollect"
        return raw

    print(_summary_phrase(app))
    print()
    run_keys = [key for key in ["1", "2", "3"] if key in option_map]
    if default_choice in run_keys:
        menu_utils.print_section("Run Option")
        for key in run_keys:
            option = option_map[key]
            print(
                _action_line(
                    key,
                    _label(key),
                    is_default=(key == default_choice),
                    disabled=bool(option.disabled),
                )
            )
    else:
        menu_utils.print_section("Recommended")
        print(
            _action_line(
                default_choice,
                _label(default_choice),
                is_default=True,
                disabled=bool(getattr(option_map.get(default_choice), "disabled", False)),
            )
        )
        print(f"Reason: {reason}")
        if run_keys:
            print()
            menu_utils.print_section("Run Option")
            for key in run_keys:
                option = option_map[key]
                print(_action_line(key, _label(key), disabled=bool(option.disabled)))

    inspect_keys = [key for key in ["A", "H", "G", "R", "X"] if key in option_map and key != default_choice]
    if inspect_keys:
        print()
        menu_utils.print_section("Review / inspect")
        for key in inspect_keys:
            option = option_map[key]
            print(_action_line(key, _label(key), disabled=bool(option.disabled)))

    print()
    print("0) Back")


def print_selected_app_workbench_summary(
    app: Any,
    *,
    status_messages: Any,
    selected_app_active_valid_runs_fn: Callable[[Any], int],
    print_selected_app_evidence_context_fn: Callable[..., None],
    is_messaging_package_or_category_fn: Callable[[str], bool],
) -> None:
    active_valid_runs = selected_app_active_valid_runs_fn(app)
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
        include_why=True,
    )
    if (
        is_messaging_package_or_category_fn(app.package_name)
        and int(app.counts.baseline_valid_runs) < int(app.cfg.baseline_required)
    ):
        print()
        print(
            status_messages.status(
                "Messaging baseline uses connected idle: open an existing conversation thread and keep it visible; no send/call.",
                level="info",
            )
        )
    if app.extra_valid_local > 0:
        print()
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
            latest_recent=app.latest_recent,
            has_identity_mismatch=app.has_identity_mismatch,
            live_build_drift=getattr(app, "live_build_drift", None),
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
    if selected_protocol == "2":
        if (
            app.scripted_template_ready
            and int(app.counts.baseline_valid_runs) >= int(app.cfg.baseline_required)
            and (
                str(app.suggested_default_key or "") == "2"
                or "scripted" in str(app.queue_action or "").lower()
            )
        ):
            return "2"
        return "3"
    if selected_protocol == "3":
        return "4"
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
    default_choice, reason = _recommended_action(
        app=app,
        protocol_options=protocol_options,
        queue_action_key_fn=queue_action_key_fn,
        queue_action_review_qa=queue_action_review_qa,
        queue_action_restore_local="restore_local_evidence",
    )
    menu_utils.print_header(app.display_label)
    print_selected_app_workbench_summary_fn(app)
    print()
    while True:
        _render_recommended_screen(
            app=app,
            protocol_options=protocol_options,
            default_choice=default_choice,
            reason=reason,
            menu_utils=menu_utils,
        )
        selected_protocol = prompt_utils.get_choice(
            [str(option.key) for option in protocol_options if not option.disabled] + ["0", "B"],
            default=default_choice,
            casefold=True,
            invalid_message="Choose one of the listed actions.",
            disabled=[option.key for option in protocol_options if option.disabled],
        ).upper()
        if selected_protocol == "B":
            return "0"
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
    "render_selected_app_workbench",
]
