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
        if "persistence test" in label:
            match = re.search(r"(\d+)", label)
            size = match.group(1) if match else "batch"
            return f"all-persist{size}"
        if "smoke batch" in label:
            match = re.search(r"(\d+)", label)
            size = match.group(1) if match else "batch"
            return f"all-smoke{size}"
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
    explicit = (params.session_label or "").strip()
    if explicit:
        return normalize_session_stamp(explicit)

    current = (params.session_stamp or "").strip()
    if not current:
        current = datetime.now(UTC).strftime("%Y%m%d")

    # Rebuild generated defaults from the date prefix so the suggested label
    # stays aligned with the selected scope/preset instead of reusing a stale
    # prior full-run stamp for smoke or persistence-test batches.
    if not re.fullmatch(r"\d{8}", current):
        match = re.match(r"^(\d{8})", current)
        if match:
            current = match.group(1)
        else:
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
    if command.workers_override:
        effective = replace(effective, workers=command.workers_override)
    return effective


def render_run_preflight(
    params: RunParameters,
    selection: Any,
    command: Command,
    *,
    reset_mode: str | None,
) -> None:
    groups = tuple(getattr(selection, "groups", ()) or ())
    package_count = len(groups)
    artifact_count = sum(len(getattr(group, "artifacts", ()) or ()) for group in groups)
    print()
    menu_utils.print_section("Run preflight")
    print(f"Session label   : {params.session_stamp or 'unspecified'}")
    print(f"Packages        : {package_count}")
    print(f"Artifacts est.  : {artifact_count}")
    workers = str(params.workers or "auto")
    if workers == "auto":
        mode = f"{params.profile_label} | workers=auto"
    else:
        mode = f"{params.profile_label} | workers={workers}"
    print(f"Mode            : {mode}")
    if reset_mode == "session":
        print("Reset           : session")
    elif reset_mode:
        print(f"Reset           : {reset_mode}")


def confirm_reset(session_label: str | None = None) -> str | None:
    """Prompt reset mode.

    Returns:
      - ``"session"`` for session-scoped reset (default)
      - ``None`` when cancelled
    """

    print()
    menu_utils.print_section("Session reset")
    if session_label:
        print(f"Session: {session_label}")
    print("  [1] Clear this session")
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
        label = session_label or "session"
        if getattr(outcome, "cleared", None):
            cleared_count = len(getattr(outcome, "cleared", ()) or ())
            print(
                status_messages.status(
                    f"Cleared prior session rows for {label} ({cleared_count} tables).",
                    level="success",
                )
            )
        else:
            print(status_messages.status(f"No prior session rows found for {label}.", level="info"))
    if getattr(outcome, "truncated", None):
        truncated = ", ".join(outcome.truncated)
        print(
            status_messages.status(
                f"Cleared tables (TRUNCATE): {truncated}",
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


def _lookup_existing_session_state(session_stamp: str) -> tuple[bool, int | None, int | None]:
    sessions_dir = Path(app_config.DATA_DIR) / "sessions"
    run_map_path = sessions_dir / session_stamp / "run_map.json"
    has_local_session = run_map_path.exists()
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
    return has_local_session, attempts, canonical_id


def prompt_session_label(params: RunParameters) -> RunParameters:
    """Ask the user to override the generated session label."""

    current = params.session_stamp or ""
    suggested = _suggest_session_label(params)
    print()
    label = prompt_utils.prompt_text(
        "Session label",
        default=suggested or current,
        required=False,
        show_arrow=True,
    ).strip()
    if not label:
        label = suggested or current
    session_stamp = normalize_session_stamp(label)

    # Collision handling must live in the menu (UI) layer. Execution paths are
    # prompt-free and require a resolved stamp/action for reproducibility.
    has_local_session, attempts, canonical_id = _lookup_existing_session_state(session_stamp)
    has_db_attempts = isinstance(attempts, int) and attempts > 0
    if has_local_session or has_db_attempts:
        print(status_messages.status(f"Session label already exists: {session_stamp}", level="warn"))
        if attempts is not None:
            summary = f"Apps: {attempts}"
            if canonical_id:
                summary += f" | canonical static_run_id={canonical_id}"
            print(status_messages.status(summary, level="info"))
        print()
        print("Choose strategy")
        print("  [1] Replace session")
        print("  [2] Append new label")
        print("  [0] Cancel")
        default_choice = "2" if "smoke batch" in (params.scope_label or "").lower() or "persistence test" in (params.scope_label or "").lower() else "1"
        choice = prompt_utils.get_choice(["1", "2", "0"], default=default_choice, prompt=f"Choice [{default_choice}]: ")
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
        print(status_messages.status(f"Append target: {session_stamp}", level="info"))
        return replace(params, session_stamp=session_stamp, canonical_action="append")

    return replace(params, session_stamp=session_stamp)


def _append_session_label(session_stamp: str, attempts: int | None) -> str:
    suffix = None
    if isinstance(attempts, int) and attempts >= 0:
        suffix = str(attempts + 1)
    if not suffix:
        suffix = datetime.now(UTC).strftime("%H%M%S")
    return normalize_session_stamp(f"{session_stamp}-{suffix}")


def prompt_run_setup(
    params: RunParameters,
    selection: Any,
    command: Command,
) -> tuple[str, RunParameters, str | None]:
    """Render one setup screen and return the requested run action.

    Returns ``("run", params, reset_mode)``, ``("advanced", params, None)``, or
    ``("cancel", params, None)``.
    """

    current = params.session_stamp or ""
    suggested = _suggest_session_label(params)
    session_stamp = normalize_session_stamp(suggested or current)
    effective = replace(params, session_stamp=session_stamp)

    groups = tuple(getattr(selection, "groups", ()) or ())
    package_count = len(groups)
    artifact_count = sum(len(getattr(group, "artifacts", ()) or ()) for group in groups)
    target = getattr(selection, "label", None) or "selected scope"
    if package_count == 1 and groups:
        group = groups[0]
        package_name = str(getattr(group, "package_name", "") or "").strip()
        label = str(getattr(selection, "label", "") or "").strip()
        if package_name and package_name not in label:
            target = f"{label or package_name} | {package_name}"

    has_local_session, attempts, canonical_id = _lookup_existing_session_state(session_stamp)
    has_existing = has_local_session or (isinstance(attempts, int) and attempts > 0)

    print()
    menu_utils.print_section("Run Setup")
    print(f"Target         : {target}")
    print(f"Mode           : {params.profile_label}")
    print(f"Artifacts est. : {artifact_count}")
    print(f"Session        : {session_stamp}")
    if has_existing:
        existing = "found"
        if canonical_id:
            existing += f", canonical static_run_id={canonical_id}"
        elif attempts is not None:
            existing += f", attempts={attempts}"
        print(f"Existing run   : {existing}")
    else:
        print("Existing run   : none")
    print()
    if has_existing:
        print("1) Replace existing session and run")
        print("2) Use new session label")
    else:
        print("1) Run now")
        print("2) Use new session label")
    print("3) Change options")
    print("0) Cancel")
    choice = prompt_utils.get_choice(["1", "2", "3", "0"], default="1", prompt="Choice [1]: ")
    if choice == "0":
        return "cancel", effective, None
    if choice == "3":
        return "advanced", effective, None
    if choice == "2":
        appended = _append_session_label(session_stamp, attempts)
        print(status_messages.status(f"Session label: {appended}", level="info"))
        return "run", replace(effective, session_stamp=appended, canonical_action="append"), None
    if has_existing:
        return "run", replace(effective, canonical_action="replace"), "session"
    return "run", effective, None


def ask_run_controls() -> str:
    """Prompt for a compact run/test control choice."""

    print()
    menu_utils.print_section("Run Options")
    print("1) Run now")
    print("2) Test options")
    print("0) Back")
    choice = prompt_utils.get_choice(["1", "2", "0"], default="1", prompt="Choice [1]: ")
    if choice == "0":
        return "back"
    if choice == "2":
        return "advanced"
    return "run"
