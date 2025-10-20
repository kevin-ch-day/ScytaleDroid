"""Support functions for the static analysis interactive menu."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

from .commands.models import Command
from .models import RunParameters


def apply_command_overrides(params: RunParameters, command: Command) -> RunParameters:
    """Return run parameters updated according to command flags."""

    effective = params
    if command.dry_run or not command.persist:
        effective = replace(effective, dry_run=True)
    if command.force_app_scope:
        effective = replace(effective, verbose_output=True)
    return effective


def confirm_reset() -> bool:
    """Prompt the user to confirm resetting static-analysis tables."""

    return prompt_utils.prompt_yes_no(
        "Reset static-analysis tables before running?",
        default=False,
    )


def render_reset_outcome(outcome: Any) -> None:
    """Display the result of a static-analysis reset request."""

    print()
    menu_utils.print_section("Reset summary")
    if getattr(outcome, "truncated", None):
        truncated = ", ".join(outcome.truncated)
        print(
            status_messages.status(
                f"Truncated tables: {truncated}",
                level="success",
            )
        )
    if getattr(outcome, "failed", None):
        failures = ", ".join(f"{table} ({reason})" for table, reason in outcome.failed)
        print(status_messages.status(f"Failures: {failures}", level="error"))
    if getattr(outcome, "skipped_protected", None):
        protected = ", ".join(outcome.skipped_protected)
        print(
            status_messages.status(
                f"Protected tables skipped: {protected}",
                level="info",
            )
        )
    if getattr(outcome, "skipped_missing", None):
        missing = ", ".join(outcome.skipped_missing)
        print(status_messages.status(f"Missing tables skipped: {missing}", level="warn"))
    if not (
        getattr(outcome, "truncated", None)
        or getattr(outcome, "failed", None)
        or getattr(outcome, "skipped_missing", None)
    ):
        print(status_messages.status("No tables were modified.", level="info"))


def prompt_session_label(params: RunParameters) -> RunParameters:
    """Ask the user to override the generated session label."""

    current = params.session_stamp or ""
    label = prompt_utils.prompt_text(
        "Session label (press Enter to keep auto-generated)",
        default=current,
        required=False,
    ).strip()
    if not label or label == current:
        return params
    return replace(params, session_stamp=label)


def ask_run_controls() -> str:
    """Prompt the user for the next action when running a command."""

    while True:
        print()
        menu_utils.print_section("Run controls")
        print("  R) Run with defaults")
        print("  A) Advanced options")
        print("  0) Back")

        response = prompt_utils.prompt_text(
            "",
            default="R",
            required=False,
            error_message="Invalid choice. Please try again.",
        )
        choice = (response or "R").strip().lower()

        if choice in {"", "r", "run", "1"}:
            return "run"
        if choice in {"a", "adv", "advanced", "2"}:
            return "advanced"
        if choice in {"0", "back", "b"}:
            return "back"

        print(status_messages.status("Invalid choice. Please try again.", level="warn"))
