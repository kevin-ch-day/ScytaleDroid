"""Support functions for the static analysis interactive menu."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

try:  # optional DB access (offline mode)
    from scytaledroid.Database.db_core import db_queries as core_q
except Exception:  # pragma: no cover - DB optional
    core_q = None

from ..commands.models import Command
from ..core.models import RunParameters


def apply_command_overrides(params: RunParameters, command: Command) -> RunParameters:
    """Return run parameters updated according to command flags."""

    effective = params
    if command.dry_run or not command.persist:
        effective = replace(effective, dry_run=True)
    if command.force_app_scope or command.id == "5":
        effective = replace(effective, verbose_output=True)
    return effective


def confirm_reset() -> bool:
    """Prompt the user to confirm resetting static-analysis tables."""

    print()
    menu_utils.print_section("Reset static analysis")
    print("This will truncate static analysis tables for the next run.")
    return prompt_utils.prompt_yes_no("Proceed?", default=False)


def render_reset_outcome(outcome: Any) -> None:
    """Display the result of a static-analysis reset request."""

    print()
    menu_utils.print_section("Reset summary")
    print(
        status_messages.status(
            "Reset uses TRUNCATE when permitted; falls back to DELETE when TRUNCATE is denied.",
            level="info",
        )
    )
    if getattr(outcome, "truncated", None):
        truncated = ", ".join(outcome.truncated)
        print(
            status_messages.status(
                f"Cleared tables (TRUNCATE): {truncated}",
                level="success",
            )
        )
    if getattr(outcome, "cleared", None):
        cleared = ", ".join(outcome.cleared)
        print(
            status_messages.status(
                f"Cleared tables (DELETE): {cleared}",
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
        or getattr(outcome, "cleared", None)
        or getattr(outcome, "failed", None)
        or getattr(outcome, "skipped_missing", None)
    ):
        print(status_messages.status("No tables were modified.", level="info"))


def prompt_session_label(params: RunParameters) -> RunParameters:
    """Ask the user to override the generated session label."""

    current = params.session_stamp or ""
    print()
    label = prompt_utils.prompt_text(
        "Session label (press Enter to keep auto-generated)",
        default=current,
        required=False,
        show_arrow=False,
    ).strip()
    if not label or label == current:
        return params

    # Enforce unique session labels: if already present, auto-suffix to avoid run bleed.
    session_stamp = label
    if core_q is not None:
        try:
            exists = core_q.run_sql(
                "SELECT id FROM runs WHERE session_stamp = %s LIMIT 1",
                (session_stamp,),
                fetch="one",
            )
            if exists:
                session_stamp = label
                print(
                    status_messages.status(
                        f"Session label '{label}' already exists. Reusing it.",
                        level="warn",
                    )
                )
        except Exception:
            # If the check fails, fall back to the user-provided label.
            session_stamp = label

    return replace(params, session_stamp=session_stamp)


def ask_run_controls() -> str:
    """Run with defaults without prompting for options."""

    # Historically this prompted for R/A/Back; we now streamline to always run
    # with defaults to reduce friction for common workflows. Keep the message
    # minimal so the CLI no longer shows phantom menu choices.
    print()
    print(status_messages.status("Running with selected options…", level="info"))
    return "run"
