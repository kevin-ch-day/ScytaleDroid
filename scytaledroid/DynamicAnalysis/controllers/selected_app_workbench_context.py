"""Summary and auxiliary action helpers for the selected-app workbench."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from scytaledroid.DynamicAnalysis.controllers.selected_app_state import (
    selected_app_build_label,
    selected_app_evidence_label,
    selected_app_evidence_text,
    selected_app_qa_badge,
    selected_app_qa_text,
)
from scytaledroid.DynamicAnalysis.run_qualification import (
    format_baseline_ml_training_pool_phrase,
    format_workbench_qualification_lines,
)
from scytaledroid.Utils.DisplayUtils.summary_cards import summary_item


def workbench_summary_card_items(app: Any) -> list[Any]:
    quota = (
        f"quota {int(app.counts.baseline_valid_runs) + int(app.counts.interactive_valid_runs)}"
        f"/{int(app.cfg.baseline_required) + int(app.cfg.interactive_required)}"
    )
    active_valid_runs = int(app.counts.baseline_valid_runs) + int(app.counts.interactive_valid_runs)
    build_label = selected_app_build_label(
        active_valid_runs=active_valid_runs,
        legacy_valid_runs=int(app.historical_valid_local),
        db_active_sessions=int(app.db_active_sessions),
        db_historical_sessions=int(app.db_historical_sessions),
    )
    evidence_label = selected_app_evidence_label(
        "",
        technical_valid_active=active_valid_runs,
        db_active_sessions=int(app.db_active_sessions),
        historical_valid_runs_count=int(app.historical_valid_local),
        db_historical_sessions=int(app.db_historical_sessions),
    )
    if app.latest_valid is False:
        effective_latest_valid = False
    elif app.latest_valid is True and active_valid_runs > 0:
        effective_latest_valid = True
    else:
        effective_latest_valid = None
    qa_badge = selected_app_qa_badge(effective_latest_valid)

    qa_text = selected_app_qa_text(qa_badge)
    quota_complete = int(app.counts.baseline_valid_runs) >= int(app.cfg.baseline_required) and int(
        app.counts.interactive_valid_runs
    ) >= int(app.cfg.interactive_required)
    if qa_badge.startswith("QA invalid"):
        qa_style = "error"
    elif "needs review" in qa_badge.lower():
        qa_style = "warning"
    elif "valid" in qa_badge.lower():
        qa_style = "success"
    else:
        qa_style = "muted"

    build_value = "installed/current"
    evidence_value = selected_app_evidence_text(build_label, evidence_label)
    items = [
        summary_item("Target build", build_value, value_style="success"),
        summary_item(
            "Evidence state",
            evidence_value,
            value_style="warning" if "historical" in evidence_value.lower() or "db-only" in evidence_value.lower() else "accent",
        ),
        summary_item("Current QA", qa_text, value_style=qa_style),
        summary_item("Quota", quota, value_style="success" if quota_complete else "warning"),
    ]
    pool_phrase = format_baseline_ml_training_pool_phrase(
        extra_valid=int(getattr(app.counts, "baseline_extra_valid", 0) or 0),
        low_signal_retained=int(getattr(app.counts, "baseline_low_signal_valid", 0) or 0),
        compact=True,
    )
    if pool_phrase:
        items.append(summary_item("ML pool", pool_phrase.replace("ML pool ", ""), value_style="emphasis"))
    elif int(app.counts.baseline_valid_runs) >= int(app.cfg.baseline_required):
        items.append(summary_item("ML pool", "empty — run supplemental baselines", value_style="muted"))
    return items


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
    print()
    for line in format_workbench_qualification_lines(app):
        print(line)
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
        print(
            status_messages.status(
                "If login/setup is still in the way, use Interactive run -> Manual first. That preparation run is retained as extra evidence outside baseline quota.",
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
        return "2"
    if selected_protocol == "3":
        return "4"
    return selected_protocol


__all__ = [
    "handle_selected_app_aux_action",
    "print_selected_app_workbench_summary",
    "workbench_summary_card_items",
]
