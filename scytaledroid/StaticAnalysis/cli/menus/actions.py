"""Support functions for the static analysis interactive menu."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
import re
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.StaticAnalysis.session import normalize_session_stamp
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages

try:  # optional DB access (offline mode)
    from scytaledroid.Database.db_core import db_queries as core_q
except Exception:  # pragma: no cover - DB optional
    core_q = None

from ..commands.models import Command
from ..core.models import RunParameters


def _scope_token(params: RunParameters) -> str:
    scope = (params.scope or "").strip().lower()
    label = (params.scope_label or "").strip().lower()
    if scope == "all":
        return "all"
    if not label:
        return scope or "scope"
    # Prefer concise package tail names when scope label is a package.
    if "." in label and " " not in label:
        parts = [segment for segment in label.split(".") if segment]
        if len(parts) >= 2:
            return "-".join(parts[-2:])
        return parts[-1]
    slug = re.sub(r"[^a-z0-9]+", "-", label).strip("-")
    if not slug:
        return scope or "scope"
    # If verbose, collapse to initials for readability.
    if len(slug) > 18:
        words = [word for word in slug.split("-") if word]
        if len(words) >= 2:
            initials = "".join(word[0] for word in words)
            return initials[:10]
        return slug[:18]
    return slug


def _profile_token(params: RunParameters) -> str:
    profile = (params.profile or "").strip().lower()
    aliases = {
        "full": "full",
        "lightweight": "lite",
        "permissions": "perm",
        "metadata": "meta",
        "split": "split",
    }
    return aliases.get(profile, profile[:8] or "run")


def _suggest_session_label(params: RunParameters) -> str:
    current = (params.session_stamp or "").strip()
    if not current:
        current = datetime.now(UTC).strftime("%Y%m%d")
    # Respect existing explicit labels that are already descriptive.
    if not re.fullmatch(r"\d{8}", current):
        return current
    scope_token = _scope_token(params)
    profile_token = _profile_token(params)
    suggested = f"{current}-{scope_token}-{profile_token}"
    return normalize_session_stamp(suggested)


def apply_command_overrides(params: RunParameters, command: Command) -> RunParameters:
    """Return run parameters updated according to command flags."""

    effective = params
    if command.dry_run or not command.persist:
        effective = replace(effective, dry_run=True)
    if command.force_app_scope or command.force_verbose:
        effective = replace(effective, verbose_output=True)
    return effective


def confirm_reset() -> str | None:
    """Prompt reset mode.

    Returns:
      - ``"session"`` for session-scoped reset (default)
      - ``None`` when cancelled
    """

    print()
    menu_utils.print_section("Reset static analysis")
    print("Default reset is session-scoped (preserves historical runs).")
    print("  [1] Session-scoped reset (recommended)")
    print("  [0] Cancel")
    choice = prompt_utils.get_choice(["1", "0"], default="1", prompt="Choice [1]: ")
    if choice == "0":
        return None
    return "session"


def render_reset_outcome(outcome: Any, *, session_label: str | None = None) -> None:
    """Display the result of a static-analysis reset request."""

    print()
    menu_utils.print_section("Reset summary")
    if getattr(outcome, "truncated", None):
        print(
            status_messages.status(
                "Maintenance TRUNCATE occurred (not part of normal static workflow).",
                level="warn",
            )
        )
    else:
        print(status_messages.status("Reset mode: session-scoped DELETE", level="info"))
        if session_label:
            print(status_messages.status(f"Session label: {session_label}", level="info"))
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
                f"Cleared session rows (DELETE): {cleared}",
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
    suggested = _suggest_session_label(params)
    print()
    if suggested and suggested != current:
        print(status_messages.status(f"Suggested: {suggested}", level="info"))
    label = prompt_utils.prompt_text(
        "Session label (press Enter to use default)",
        default=suggested or current,
        required=False,
        show_arrow=True,
    ).strip()
    if not label or label == (suggested or current):
        if suggested and suggested != current:
            return replace(params, session_stamp=suggested)
        return params

    session_stamp = normalize_session_stamp(label)

    # Collision handling must live in the menu (UI) layer. Execution paths are
    # prompt-free and require a resolved stamp/action for reproducibility.
    sessions_dir = Path(app_config.DATA_DIR) / "sessions"
    run_map_path = sessions_dir / session_stamp / "run_map.json"
    if run_map_path.exists():
        attempts = None
        canonical_id = None
        if core_q is not None:
            try:
                row = core_q.run_sql(
                    "SELECT COUNT(*) FROM static_analysis_runs WHERE session_label=%s",
                    (session_stamp,),
                    fetch="one",
                )
                attempts = int(row[0]) if row and row[0] is not None else 0
                row = core_q.run_sql(
                    """
                    SELECT id FROM static_analysis_runs
                    WHERE session_label=%s AND is_canonical=1
                    ORDER BY canonical_set_at_utc DESC
                    LIMIT 1
                    """,
                    (session_stamp,),
                    fetch="one",
                )
                canonical_id = int(row[0]) if row and row[0] is not None else None
            except Exception:
                attempts = None
                canonical_id = None

        print(status_messages.status(f"Session label already exists for today: {session_stamp}", level="warn"))
        if attempts is not None:
            canonical_text = f" (canonical: static_run_id={canonical_id})" if canonical_id else ""
            print(status_messages.status(f"Existing attempts: {attempts}{canonical_text}", level="info"))
        print()
        print("Action options:")
        print("  [1] Replace today's run        (overwrite local artifacts, DB history preserved)")
        print("  [2] Append as another attempt  (keep prior attempts, new suffix)")
        print("  [0] Cancel (keep previous label)")
        choice = prompt_utils.get_choice(["1", "2", "0"], default="1", prompt="Choice [1]: ")
        if choice == "0":
            return params
        if choice == "1":
            return replace(params, session_stamp=session_stamp, canonical_action="replace")
        # Append: generate a new, collision-free stamp now so execution is deterministic.
        suffix = None
        if isinstance(attempts, int) and attempts >= 0:
            suffix = str(attempts + 1)
        if not suffix:
            suffix = datetime.now(UTC).strftime("%H%M%S")
        session_stamp = normalize_session_stamp(f"{session_stamp}-{suffix}")
        return replace(params, session_stamp=session_stamp, canonical_action="append")

    return replace(params, session_stamp=session_stamp)


def ask_run_controls() -> str:
    """Run with defaults without prompting for options."""

    # Historically this prompted for R/A/Back; we now streamline to always run
    # with defaults to reduce friction for common workflows. Keep the message
    # minimal so the CLI no longer shows phantom menu choices.
    print()
    print(status_messages.status("Running with selected options…", level="info"))
    return "run"
