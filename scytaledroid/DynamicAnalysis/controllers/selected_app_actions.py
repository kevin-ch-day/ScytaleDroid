"""Selected-app action menu orchestration for the dynamic workbench."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .selected_app_workbench_context import (
    handle_selected_app_aux_action,
    print_selected_app_workbench_summary,
)
from .selected_app_workbench_menu import (
    build_selected_app_protocol_options,
)
from .selected_app_workbench_menu import (
    recommended_action as _recommended_action,
)
from .selected_app_workbench_menu import (
    render_recommended_screen as _render_recommended_screen,
)


def render_selected_app_workbench(
    *,
    app: Any,
    print_tier1_qa_result: Callable[[str], None] | None,
    menu_utils: Any,
    prompt_utils: Any,
    status_messages: Any,
    queue_action_key_fn: Callable[[str | None], str],
    queue_action_review_qa: str,
    build_selected_app_protocol_options_fn: Callable[[Any], list[Any]],
    print_selected_app_workbench_summary_fn: Callable[[Any], None],
    handle_selected_app_aux_action_fn: Callable[..., str | None],
) -> str:
    protocol_options = build_selected_app_protocol_options_fn(app)
    default_choice, _reason = _recommended_action(
        app=app,
        protocol_options=protocol_options,
        queue_action_key_fn=queue_action_key_fn,
        queue_action_review_qa=queue_action_review_qa,
        queue_action_restore_local="restore_local_evidence",
    )
    print_selected_app_workbench_summary_fn(app)
    print()
    while True:
        _render_recommended_screen(
            app=app,
            protocol_options=protocol_options,
            default_choice=default_choice,
            menu_utils=menu_utils,
            status_messages=status_messages,
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
