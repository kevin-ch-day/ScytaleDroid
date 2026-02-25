"""main.py - Entry point for ScytaleDroid CLI."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from datetime import datetime

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core.db_engine import ensure_db_ready
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuSpec
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.LoggingUtils.logging_core import LOG_DIR
from scytaledroid.Utils.System.world_clock.display import (
    ClockSnapshot,
    describe_timezone,
    format_display_time,
    format_dst_status_text,
    snapshot_clocks,
)
from scytaledroid.Utils.System.world_clock.state import WorldClockState, load_state


def _resolve_timezones() -> WorldClockState:
    return load_state()


def _describe_snapshot(snapshot: ClockSnapshot) -> tuple[str, str]:
    timestamp = format_display_time(snapshot.local_time)
    tz_label = describe_timezone(snapshot.timezone, snapshot.local_time)
    dst_text = format_dst_status_text(snapshot.dst_status, None, None)
    details = f"{timestamp} {tz_label} ({dst_text})"
    return snapshot.label, details


def _build_metrics(state: WorldClockState) -> list[tuple[str, str]]:
    try:
        snapshots = snapshot_clocks(
            state.clocks,
            primary=state.primary,
            category="configured",
            reference=state.reference,
        )
    except Exception as exc:  # pragma: no cover - defensive logging
        log.warning(
            f"Failed to load world clock snapshots: {exc}",
            category="application",
        )
        return []

    metrics: list[tuple[str, str]] = []
    for snapshot in snapshots:
        try:
            metrics.append(_describe_snapshot(snapshot))
        except Exception as exc:  # pragma: no cover - defensive logging
            log.warning(
                f"Failed to format clock metric for {snapshot.label}: {exc}",
                category="application",
            )
    return metrics


def print_banner(*, show_clocks: bool = False) -> None:
    """Display welcome banner with app metadata and optional world clock."""

    metrics: list[tuple[str, str]] = []
    if show_clocks:
        state = _resolve_timezones()
        metrics = _build_metrics(state)

    menu_utils.print_main_banner(
        app_config.APP_NAME,
        app_config.APP_VERSION,
        app_config.APP_RELEASE,
        app_config.APP_DESCRIPTION,
        metrics=metrics,
    )

    log.info(
        f"Application started - {app_config.APP_NAME} {app_config.APP_VERSION} ({app_config.APP_RELEASE})",
        category="application",
    )


def main_menu() -> None:
    """Render the main menu loop using the shared menu framework."""

    ensure_db_ready()
    from scytaledroid.Database.db_utils import schema_gate
    ok, message, detail = schema_gate.check_base_schema()
    if not ok:
        status_messages.print_status(f"[ERROR] {message}", level="error")
        if detail:
            status_messages.print_status(detail, level="error")
        status_messages.print_status(
            "Fix: Verify database connection and schema. Then run Database Tools → Apply baseline schema migrations (or import canonical DB export).",
            level="error",
        )
        return
    menu_actions: list[tuple[str, str, Callable[[], None]]] = [
        ("1", "Android Device Analysis", handle_device),
        ("2", "Static APK analysis", handle_static),
        ("3", "Dynamic analysis", handle_dynamic),
        ("4", "API server", handle_api),
        ("5", "Reporting", handle_reporting),
        ("6", "Database tools", handle_database),
        ("7", "Governance Inputs & Readiness", handle_data_workspace),
        ("8", "Workspace & Evidence", handle_workspace),
        ("9", "APK library & archives", handle_browse_apks),
        ("10", "About ScytaleDroid", handle_about),
    ]

    handlers = {key: (label, callback) for key, label, callback in menu_actions}
    valid_choices = list(handlers)
    # Keep a default for enter-to-select but do not show "(default)" in UI.
    default_choice = "1"
    while True:
        print()
        status_snapshot = _print_tier1_status_banner()
        print()
        menu_utils.print_header("Main Menu")
        spec = MenuSpec(
            items=[menu_utils.MenuOption(key, label) for key, label, _ in menu_actions],
            default=None,
            exit_label="Exit",
            show_exit=True,
            show_descriptions=False,
        )
        menu_utils.render_menu(spec)

        extra_valid: list[str] = []
        if status_snapshot.get("allow_copy_freeze_hash"):
            extra_valid.append("h")
        if status_snapshot.get("allow_details"):
            extra_valid.append("d")

        choice = prompt_utils.get_choice(
            valid=valid_choices + ["0", *extra_valid],
            default=default_choice,
            casefold=True,
        )

        if choice == "0":
            log.info("Application shutting down", category="application")
            shutdown_time = datetime.now().astimezone().strftime("%-m/%-d/%Y %-I:%M %p")
            status_messages.print_strip(
                "Session End",
                [
                    ("Time", shutdown_time),
                    ("Logs", str(LOG_DIR)),
                ],
                width=70,
            )
            status_messages.print_status("Goodbye!", level="info")
            break

        if choice.lower() == "h" and status_snapshot.get("allow_copy_freeze_hash"):
            _handle_copy_freeze_hash(status_snapshot)
            continue

        if choice.lower() == "d" and status_snapshot.get("allow_details"):
            _handle_main_menu_details(status_snapshot)
            continue

        selected = handlers.get(choice)
        if not selected:
            log.warning(f"Invalid menu choice: {choice}", category="application")
            status_messages.print_status("Invalid choice. Please try again.", level="warn")
            continue

        label, callback = selected
        log.info(f"User selected: {label}", category="application")
        callback()


def _resolve_operator_mode(*, pub_status: dict[str, object]) -> str:
    """Resolve operator UI mode (publication/collection).

    Default: auto-detect based on audit + freeze presence.
    Override: SCYTALEDROID_MODE=freeze|publication|collection.
    """

    override = str(os.environ.get("SCYTALEDROID_MODE") or "").strip().lower()
    # Back-compat aliases: "paper"/"paper2" map to publication mode.
    if override in {"paper", "paper2", "freeze", "publication", "pub"}:
        return "paper"
    if override in {"collection", "collect"}:
        return "collection"

    # Auto-detect: we treat "paper freeze" as locked only when we have both
    # an audit GO and a freeze anchor present (freeze hash exists).
    has_freeze = bool(pub_status.get("freeze_dataset_hash"))
    audit_go = str(pub_status.get("paper_audit_result") or "").strip().upper() == "GO"
    can_freeze = bool(pub_status.get("can_freeze"))
    if has_freeze and audit_go and can_freeze:
        return "paper"
    return "collection"


def _load_paper_cohort_counts() -> dict[str, int] | None:
    """Return compact cohort counts from paper_results_v1.json if present."""

    try:
        import json
        from pathlib import Path

        p = Path(app_config.OUTPUT_DIR) / "publication" / "manifests" / "paper_results_v1.json"
        if not p.exists():
            return None
        payload = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return None
        return {
            "apps": int(payload.get("n_apps") or 0),
            "runs": int(payload.get("runs_total") or 0),
            "windows": int(payload.get("windows_total") or 0),
        }
    except Exception:
        return None


def _handle_copy_freeze_hash(snapshot: dict[str, object]) -> None:
    freeze_hash = str(snapshot.get("freeze_dataset_hash") or "")
    if not freeze_hash:
        print(status_messages.status("No freeze hash available.", level="warn"))
        prompt_utils.press_enter_to_continue()
        return
    try:
        from scytaledroid.Utils.System.clipboard import copy_text
    except Exception:
        copy_text = None
    ok = bool(copy_text and copy_text(freeze_hash))
    if ok:
        print(status_messages.status("Copied freeze hash to clipboard.", level="success"))
    else:
        print(status_messages.status("Clipboard copy unavailable; full freeze hash:", level="info"))
        print(freeze_hash)
    prompt_utils.press_enter_to_continue()


def _handle_main_menu_details(snapshot: dict[str, object]) -> None:
    print()
    menu_utils.print_header("Dataset Status (Details)")
    for k in (
        "mode",
        "locked",
        "paper_audit_result",
        "can_freeze",
        "evidence_quota_counted",
        "evidence_quota_expected",
        "freeze_dataset_hash",
        "publication_root",
        "publication_ready",
    ):
        if k in snapshot:
            print(f"- {k}: {snapshot.get(k)}")
    override = str(os.environ.get("SCYTALEDROID_MODE") or "").strip()
    if override:
        print(f"- SCYTALEDROID_MODE (override): {override}")
    prompt_utils.press_enter_to_continue()


def _print_tier1_status_banner() -> dict[str, object]:
    """Render the main-menu mode banner. Returns a snapshot for extra actions."""

    try:
        from scytaledroid.Reporting.menu_actions import fetch_tier1_status
    except Exception:
        return {}

    try:
        tier1 = fetch_tier1_status()
    except Exception:
        tier1 = {}

    # Publication-facing status (authoritative for freeze-anchored exports).
    try:
        from scytaledroid.Reporting.menu_actions import fetch_publication_status

        pub_status = fetch_publication_status()
    except Exception:
        pub_status = {}

    mode = _resolve_operator_mode(pub_status=pub_status)
    audit = str(pub_status.get("paper_audit_result") or "unknown").upper()
    can_freeze = bool(pub_status.get("can_freeze"))
    freeze_hash = str(pub_status.get("freeze_dataset_hash") or "")
    freeze_short = freeze_hash[:12] if freeze_hash else "missing"
    quota = pub_status.get("evidence_quota_counted")
    expected = pub_status.get("evidence_quota_expected")
    quota_label = f"{quota}/{expected}" if quota is not None and expected is not None else "unknown"
    pub_root = str(pub_status.get("publication_root_label") or "output/publication")
    pub_ready = bool(pub_status.get("publication_ready"))

    locked = bool(mode == "paper" and freeze_hash and audit == "GO" and can_freeze)
    lock_label = "LOCKED" if locked else "NOT LOCKED"

    snapshot: dict[str, object] = {
        "mode": mode,
        "locked": locked,
        "paper_audit_result": audit,
        "can_freeze": can_freeze,
        "evidence_quota_counted": quota,
        "evidence_quota_expected": expected,
        "freeze_dataset_hash": freeze_hash,
        "publication_root": pub_root,
        "publication_ready": pub_ready,
        "allow_copy_freeze_hash": bool(locked and freeze_hash),
        "allow_details": True,
    }

    # Loud, impossible-to-miss banner (PM acceptance criteria).
    if mode == "paper":
        banner = f"Mode: FREEZE ({lock_label}) | Freeze: {freeze_short} | Audit: {audit}"
        print(status_messages.status(banner, level="success" if locked else "warn"))
        counts = _load_paper_cohort_counts() or {}
        apps = counts.get("apps")
        runs = counts.get("runs")
        windows = counts.get("windows")
        if apps and runs and windows:
            print(f"Cohort: {apps} apps | {runs} runs | {windows} windows | Quota: {quota_label}")
        else:
            print(f"Quota: {quota_label} | Publication: {'READY' if pub_ready else 'MISSING'}")
        print(f"Publication: {'READY' if pub_ready else 'MISSING'} | Path: {pub_root}")
        print("Commands: [H] Copy freeze hash | [D] Details")
        return snapshot

    # Collection/default mode: keep it compact; avoid DB noise unless needed.
    reason = ""
    if audit != "GO":
        reason = f" (Audit: {audit})"
    print(status_messages.status(f"Mode: COLLECTION | Quota: {quota_label}{reason}", level="info"))
    # Keep a single legacy hint if schema mismatch is present.
    schema_ver = tier1.get("schema_version") or "<unknown>"
    expected_schema = tier1.get("expected_schema") or "<unknown>"
    if schema_ver and expected_schema and schema_ver != expected_schema:
        print(status_messages.status(f"DB schema mismatch: {schema_ver} (expects {expected_schema})", level="warn"))
    print("Commands: [D] Details")
    return snapshot


# --- Handlers for each menu option ---

def handle_device() -> None:
    """Launch the Android Devices hub."""
    from scytaledroid.DeviceAnalysis.device_hub_menu import devices_hub

    devices_hub()


def handle_static() -> None:
    from scytaledroid.StaticAnalysis.cli import static_analysis_menu

    static_analysis_menu()


def handle_dynamic() -> None:
    from scytaledroid.DynamicAnalysis.menu import dynamic_analysis_menu

    dynamic_analysis_menu()


def handle_reporting() -> None:
    from scytaledroid.Reporting.menu import reporting_menu

    reporting_menu()


def handle_data_workspace() -> None:
    from scytaledroid.Utils.System.paper_grade_inputs import render_paper_grade_inputs

    render_paper_grade_inputs()


def handle_api() -> None:
    from scytaledroid.Api.menu import api_menu

    api_menu()


def handle_database() -> None:
    from scytaledroid.Database.db_utils.database_menu import database_menu

    database_menu()


def handle_workspace() -> None:
    from scytaledroid.Utils.System.workspace_maintenance_menu import workspace_menu

    workspace_menu()


def handle_browse_apks() -> None:
    """Jump straight to the APK library browser."""
    try:
        from scytaledroid.DeviceAnalysis.apk_library_menu import apk_library_menu

        apk_library_menu()
    except Exception as exc:
        log.error(f"Failed to open APK library: {exc}", category="application")
        status_messages.print_status(
            "Unable to open APK library. Check logs for details.",
            level="error",
        )


def handle_about() -> None:
    from scytaledroid.Utils.AboutApp.about_app import about_app

    about_app()


def _run_diagnostics(json_mode: bool) -> None:
    from scytaledroid.Diagnostics.runner import run as run_diagnostics

    run_diagnostics(json_mode=json_mode)


def _run_db_maintenance(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="ScytaleDroid DB maintenance commands",
    )
    parser.add_argument(
        "--truncate-static",
        action="store_true",
        help="Destructively truncate static-analysis tables (maintenance-only).",
    )
    parser.add_argument(
        "--include-harvest",
        action="store_true",
        help="Also truncate harvest APK inventory tables.",
    )
    parser.add_argument(
        "--i-understand",
        default="",
        help="Required confirmation token for destructive commands.",
    )
    args = parser.parse_args(argv)

    if not args.truncate_static:
        parser.error("No maintenance action selected. Use --truncate-static.")
    if args.i_understand != "DESTROY_DATA":
        parser.error("--i-understand must be exactly DESTROY_DATA for --truncate-static.")

    from scytaledroid.Database.db_utils.reset_static import reset_static_analysis_data

    outcome = reset_static_analysis_data(
        include_harvest=bool(args.include_harvest),
        truncate_all=True,
    )
    status_messages.print_status("Maintenance reset completed.", level="info")
    for line in outcome.as_lines():
        print(f"- {line}")
    return 2 if outcome.failed else 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "static":
        from scytaledroid.StaticAnalysis.cli.flows import headless_run

        return int(headless_run.main(argv[1:]))
    if argv and argv[0] == "dynamic-gate":
        from scytaledroid.DynamicAnalysis.tools import paper_gate

        return int(paper_gate.main(argv[1:]))
    if argv and argv[0] == "dynamic-research-gate":
        from scytaledroid.DynamicAnalysis.tools import paper_gate

        return int(paper_gate.main(["--research", *argv[1:]]))
    if argv and argv[0] == "dynamic":
        dynamic_parser = argparse.ArgumentParser(description="ScytaleDroid dynamic commands")
        dynamic_parser.add_argument(
            "--paper-gate",
            action="store_true",
            help="Run canonical research gate checks and exit (legacy alias).",
        )
        dynamic_parser.add_argument(
            "--research-gate",
            action="store_true",
            help="Run canonical research gate checks and exit.",
        )
        dynamic_args = dynamic_parser.parse_args(argv[1:])
        if dynamic_args.paper_gate or dynamic_args.research_gate:
            from scytaledroid.DynamicAnalysis.tools import paper_gate

            return int(paper_gate.main(["--research"]))
        dynamic_parser.error("No dynamic command selected. Use --research-gate.")
    if argv and argv[0] == "db":
        return _run_db_maintenance(argv[1:])

    parser = argparse.ArgumentParser(description="ScytaleDroid CLI")
    parser.add_argument(
        "--diag",
        action="store_true",
        help="Run diagnostics checks and exit",
    )
    parser.add_argument(
        "--with-clocks",
        action="store_true",
        help="Show multi-city clocks in the banner",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit diagnostics in JSON format (requires --diag)",
    )
    args = parser.parse_args(argv)

    if args.json and not args.diag:
        parser.error("--json requires --diag")

    if args.diag:
        _run_diagnostics(json_mode=args.json)
        return 0

    print_banner(show_clocks=args.with_clocks)
    try:
        main_menu()
    except KeyboardInterrupt:
        print()
        status_messages.print_status("Interrupted by user. Exiting…", level="warn")
        log.info("Application interrupted by user.", category="application")
    return 0


if __name__ == "__main__":
    sys.exit(main())
