"""Option policy and menu rendering helpers for the selected-app workbench."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from scytaledroid.DynamicAnalysis.queue_operator_ui import workbench_ml_pool_phrase
from scytaledroid.DynamicAnalysis.run_qualification import baseline_ml_training_pool_count
from scytaledroid.Utils.DisplayUtils import terminal
from scytaledroid.Utils.DisplayUtils.summary_cards import print_summary_card

from .selected_app_workbench_context import workbench_summary_card_items


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
    can_reset = app.can_reset
    is_messaging = is_messaging_package_or_category_fn(app.package_name)
    queue_action = queue_action_key_fn(app.queue_action)

    def _badge_for(key: str) -> str | None:
        if not app.state.suggested_slot:
            return None
        return "suggested" if key == suggested_default_key else None

    options = [
        menu_utils.MenuOption(
            "A",
            "Review QA",
            badge=("suggested" if queue_action == queue_action_review_qa else None),
        ),
        menu_utils.MenuOption("H", "Run history", badge=None),
        menu_utils.MenuOption("G", "Diagnostics", badge=None),
        menu_utils.MenuOption(
            "1",
            "Baseline (connected)" if is_messaging else "Baseline",
            badge=_badge_for("1"),
        ),
        menu_utils.MenuOption(
            "2",
            "Interactive",
            badge=("suggested" if suggested_default_key in {"2", "3"} else None),
            disabled=(not baseline_complete),
        ),
        menu_utils.MenuOption("3", "Test app", badge=None),
        menu_utils.MenuOption(
            "X",
            "Reset app",
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
                badge="suggested",
            ),
        )
    return options


def recommended_action(
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
        return (
            "R",
            "current-build evidence exists in the DB, but the local evidence pack is missing from this workspace.",
        )
    if action_key in {"supplemental_baseline", "supplemental baseline"}:
        pool = baseline_ml_training_pool_count(
            extra_valid=int(getattr(app.counts, "baseline_extra_valid", 0) or 0),
            low_signal_retained=int(getattr(app.counts, "baseline_low_signal_valid", 0) or 0),
        )
        return (
            "1",
            str(
                app.queue_reason
                or f"ML training pool has {pool} supplemental baseline(s); run more for pattern averages."
            ),
        )
    if action_key == "baseline":
        return "1", str(app.queue_reason or "baseline quota is not yet met.")
    if action_key in {"scripted_interaction", "manual_interaction"} and "2" in option_keys:
        return "2", str(app.queue_reason or "interactive quota is still missing.")
    if getattr(app.counts, "quota_met", False) and app.latest_valid is True:
        return (
            "1",
            "baseline quota is satisfied; supplemental baselines improve ML training and pattern averages.",
        )
    if int(app.counts.baseline_valid_runs) < int(app.cfg.baseline_required):
        return (
            "1",
            f"baseline quota is not yet met ({int(app.counts.baseline_valid_runs)}/{int(app.cfg.baseline_required)}).",
        )
    if int(app.counts.interactive_valid_runs) < int(app.cfg.interactive_required):
        return (
            "2",
            f"interactive quota is still missing ({int(app.counts.interactive_valid_runs)}/{int(app.cfg.interactive_required)}).",
        )
    return "2", "interactive collection is available as retained extra work."


def workbench_option_label(key: str, option_map: dict[str, Any]) -> str:
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
    return str(option_map[key].label)


def render_recommended_screen(
    *,
    app: Any,
    protocol_options: list[Any],
    default_choice: str,
    menu_utils: Any,
    status_messages: Any | None = None,
) -> None:
    option_map = {str(option.key): option for option in protocol_options}
    run_keys = [key for key in ["1", "2", "3"] if key in option_map]
    inspect_keys = [
        key for key in ["A", "H", "G", "R", "X"] if key in option_map and key != default_choice
    ]
    use_panels = terminal.get_terminal_width(force_refresh=True) >= 108

    def _panel_option(key: str, *, suggested: bool = False) -> Any:
        option = option_map[key]
        badge = "suggested" if suggested else option.badge
        return menu_utils.MenuOption(
            key,
            workbench_option_label(key, option_map),
            badge=badge,
            disabled=bool(option.disabled),
        )

    print_summary_card(app.display_label, workbench_summary_card_items(app))
    print()

    if default_choice in run_keys:
        run_options = [_panel_option(key, suggested=(key == default_choice)) for key in run_keys]
        if use_panels:
            menu_utils.print_menu_panels(
                [("Run Option", run_options)],
                columns=1,
                default_keys=[default_choice],
                compact=True,
            )
        else:
            menu_utils.print_section("Run Option")
            menu_utils.print_menu(
                run_options,
                default=default_choice,
                show_descriptions=False,
                show_exit=False,
                compact=True,
            )
        if (
            default_choice == "1"
            and int(app.counts.baseline_valid_runs) >= int(app.cfg.baseline_required)
            and status_messages is not None
        ):
            print()
            print(
                status_messages.status(
                    workbench_ml_pool_phrase(
                        extra_valid=int(getattr(app.counts, "baseline_extra_valid", 0) or 0),
                        low_signal_retained=int(
                            getattr(app.counts, "baseline_low_signal_valid", 0) or 0
                        ),
                    )
                    + " Run as many supplemental baselines as needed.",
                    level="info",
                )
            )
    else:
        recommended_options = [_panel_option(default_choice, suggested=True)]
        if use_panels:
            menu_utils.print_menu_panels(
                [("Recommended", recommended_options)],
                columns=1,
                default_keys=[default_choice],
                compact=True,
            )
        else:
            menu_utils.print_section("Recommended")
            menu_utils.print_menu(
                recommended_options,
                default=default_choice,
                show_descriptions=False,
                show_exit=False,
                compact=True,
            )
        if run_keys:
            print()
            run_options = [_panel_option(key) for key in run_keys]
            if use_panels:
                menu_utils.print_menu_panels(
                    [("Run Option", run_options)],
                    columns=1,
                    compact=True,
                )
            else:
                menu_utils.print_section("Run Option")
                menu_utils.print_menu(
                    run_options,
                    show_descriptions=False,
                    show_exit=False,
                    compact=True,
                )

    if inspect_keys:
        print()
        inspect_options = [_panel_option(key) for key in inspect_keys]
        if use_panels:
            menu_utils.print_menu_panels(
                [("Review / inspect", inspect_options)],
                columns=1,
                compact=True,
            )
        else:
            menu_utils.print_section("Review / inspect")
            menu_utils.print_menu(
                inspect_options,
                show_descriptions=False,
                show_exit=False,
                compact=True,
            )

    print()
    print("0) Back")


__all__ = [
    "build_selected_app_protocol_options",
    "recommended_action",
    "render_recommended_screen",
    "workbench_option_label",
]
