"""main.py - Entry point for ScytaleDroid CLI."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core.db_engine import ensure_db_ready
from scytaledroid.Utils.DisplayUtils import menu_utils, prompt_utils, status_messages, summary_cards
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuSpec
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.System.world_clock.display import (
    ClockSnapshot,
    describe_timezone,
    format_display_time,
    format_dst_status_text,
    snapshot_clocks,
)
from scytaledroid.Utils.System.world_clock.state import WorldClockState, load_state
from scytaledroid.Utils.version_utils import get_git_commit


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


def _build_environment_metrics() -> list[tuple[str, str]]:
    if not app_config.SHOW_RUNTIME_IDENTITY:
        return []

    metrics: list[tuple[str, str]] = [
        ("Preset", app_config.RUNTIME_PRESET.upper()),
        ("Mode", app_config.EXECUTION_MODE),
        ("System", app_config.SYS_ENV),
    ]
    if app_config.DEBUG_MODE:
        metrics.append(("Debug", "ON"))
    if app_config.SYS_TEST:
        metrics.append(("Sys Test", "ON"))
    return metrics


def print_banner(*, show_clocks: bool = False) -> None:
    """Display welcome banner with app metadata and optional world clock."""

    metrics: list[tuple[str, str]] = _build_environment_metrics()
    if show_clocks:
        state = _resolve_timezones()
        metrics.extend(_build_metrics(state))

    menu_utils.print_main_banner(
        app_config.APP_NAME,
        app_config.APP_VERSION,
        app_config.APP_RELEASE,
        app_config.APP_DESCRIPTION,
        build_id=get_git_commit(),
        metrics=metrics,
    )

    log.info(
        f"Application started - {app_config.APP_NAME} {app_config.APP_VERSION} ({app_config.APP_RELEASE})",
        category="application",
    )
    logging_engine.emit_environment_snapshot()

def main_menu() -> None:
    """Render the main menu loop using the shared menu framework."""

    ensure_db_ready()
    from scytaledroid.Database.db_utils import schema_gate
    menu_actions: list[tuple[str, str, Callable[[], None]]] = [
        ("1", "Device Inventory & Harvest", handle_device),
        ("2", "Static Analysis Pipeline", handle_static),
        ("3", "Dynamic Analysis", handle_dynamic),
        ("4", "API server", handle_api),
        ("5", "Reporting & Exports", handle_reporting),
        ("6", "Database tools", handle_database),
        ("7", "Governance & Readiness", handle_data_workspace),
        ("8", "Evidence & Workspace", handle_workspace),
        ("9", "APK library", handle_browse_apks),
        ("10", "About ScytaleDroid", handle_about),
    ]

    handlers = {key: (label, callback) for key, label, callback in menu_actions}
    valid_choices = list(handlers)
    # Keep a default for enter-to-select but do not show "(default)" in UI.
    default_choice = "1"
    ui_once: dict[str, bool] = {}
    while True:
        print()
        status_snapshot = _print_tier1_status_banner()
        if status_snapshot.get("had_status_output"):
            print()
        ok, message, detail = schema_gate.check_base_schema()
        if not ok:
            msg_stripped = message.strip()
            if msg_stripped == "Database disabled.":
                if not ui_once.get("db_disabled_logged"):
                    log.info(
                        "Running without DB persistence (SCYTALEDROID_DB_URL unset).",
                        category="application",
                    )
                    ui_once["db_disabled_logged"] = True
            else:
                log.warning(
                    "Main menu continuing without base schema readiness",
                    category="application",
                    extra={"schema_gate_message": message, "schema_gate_detail": detail},
                )
        _emit_main_menu_db_connection_line(ok, message, detail or "")
        print()
        menu_utils.print_header("Main Menu")
        menu_utils.print_hint(
            "Choose a workflow stage."
        )
        spec = MenuSpec(
            items=[menu_utils.MenuOption(key, label) for key, label, _ in menu_actions],
            default=None,
            exit_label="Exit",
            show_exit=True,
            show_descriptions=False,
            compact=True,
        )
        menu_utils.render_menu(spec)

        extra_valid: list[str] = []
        if status_snapshot.get("allow_copy_freeze_hash"):
            extra_valid.append("h")
        choice = prompt_utils.get_choice(
            valid=valid_choices + ["0", *extra_valid],
            default=default_choice,
            casefold=True,
        )

        if choice == "0":
            log.info("Application shutting down", category="application")
            print("Exiting ScytaleDroid.")
            break

        if choice.lower() == "h" and status_snapshot.get("allow_copy_freeze_hash"):
            _handle_copy_freeze_hash(status_snapshot)
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

    # Auto-detect: treat publication freeze as locked only when we have both
    # an audit GO and a freeze anchor present (freeze hash exists).
    has_freeze = bool(pub_status.get("freeze_dataset_hash"))
    audit_go = str(pub_status.get("freeze_audit_result") or pub_status.get("paper_audit_result") or "").strip().upper() == "GO"
    can_freeze = bool(pub_status.get("can_freeze"))
    if has_freeze and audit_go and can_freeze:
        return "paper"
    return "collection"


def _load_publication_cohort_counts() -> dict[str, int] | None:
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


def _emit_main_menu_db_connection_line(ok: bool, message: str, detail: str) -> None:
    """Single-line persistence status on every main-menu draw (MariaDB/MySQL)."""

    from scytaledroid.Database.db_core import db_config

    if ok:
        cfg = db_config.DB_CONFIG
        host = cfg.get("host", "?")
        port = cfg.get("port", "?")
        database = (cfg.get("database") or "").strip() or "?"
        status_messages.print_status(
            f"DB: {database} @ {host}:{port}",
            level="success",
        )
        return

    headline = message.strip()
    if headline == "Database disabled.":
        status_messages.print_status(
            "DB: off — set DSN in .env (menu 6)",
            level="warn",
        )
        return

    status_messages.print_status(f"DB: error — {headline}", level="warn")
    trimmed = (detail or "").strip()
    if trimmed:
        status_messages.print_status(trimmed, level="warn")


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
    audit = str(pub_status.get("freeze_audit_result") or pub_status.get("paper_audit_result") or "unknown").upper()
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
        "freeze_dataset_hash": freeze_hash,
        "allow_copy_freeze_hash": bool(locked and freeze_hash),
        "had_status_output": False,
    }

    # Loud, impossible-to-miss banner (PM acceptance criteria).
    if mode == "paper":
        print(
            summary_cards.format_summary_card(
                "Freeze Mode",
                [
                    summary_cards.summary_item("Mode", lock_label, value_style="success" if locked else "warning"),
                    summary_cards.summary_item("Freeze", freeze_short, value_style="accent"),
                    summary_cards.summary_item("Audit", audit, value_style="success" if audit == "GO" else "warning"),
                    summary_cards.summary_item("Quota", quota_label, value_style="accent"),
                    summary_cards.summary_item("Publication", "present" if pub_ready else "missing", value_style="success" if pub_ready else "warning"),
                ],
                subtitle="Archive/export mode is anchored to a validated evidence freeze.",
                footer=f"Output root: {pub_root}",
            )
        )
        counts = _load_publication_cohort_counts() or {}
        apps = counts.get("apps")
        runs = counts.get("runs")
        windows = counts.get("windows")
        if apps and runs and windows:
            print(
                summary_cards.format_summary_card(
                    "Frozen Cohort",
                    [
                        summary_cards.summary_item("Apps", apps, value_style="accent"),
                        summary_cards.summary_item("Runs", runs, value_style="accent"),
                        summary_cards.summary_item("Windows", windows, value_style="accent"),
                    ],
                    footer="Command: [H] Copy freeze hash",
                )
            )
        else:
            menu_utils.print_hint("Command: [H] Copy freeze hash")
        snapshot["had_status_output"] = True
        return snapshot

    # Collection/default mode: stay quiet — routine publication/freeze state is
    # irrelevant for most runs. Surface only an actionable schema drift hint.
    from scytaledroid.Database.db_core import db_config

    schema_ver = tier1.get("schema_version") or "<unknown>"
    expected_schema = tier1.get("expected_schema") or "<unknown>"
    if (
        schema_ver
        and expected_schema
        and schema_ver != expected_schema
        and not (schema_ver == "<unknown>" and not db_config.db_enabled())
    ):
        menu_utils.print_hint(f"DB schema mismatch: {schema_ver} (expects {expected_schema})")
        snapshot["had_status_output"] = True
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
    from scytaledroid.Utils.System.governance_inputs import render_governance_inputs

    render_governance_inputs()


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
    if argv and argv[0] in {"dynamic-freeze-gate", "dynamic-gate"}:
        from scytaledroid.DynamicAnalysis.tools import freeze_gate

        return int(freeze_gate.main(argv[1:]))
    if argv and argv[0] == "dynamic-research-gate":
        from scytaledroid.DynamicAnalysis.tools import freeze_gate

        return int(freeze_gate.main(["--research", *argv[1:]]))
    if argv and argv[0] == "dynamic":
        dynamic_parser = argparse.ArgumentParser(description="ScytaleDroid dynamic commands")
        dynamic_parser.add_argument(
            "--freeze-gate",
            action="store_true",
            help="Run canonical research gate checks and exit.",
        )
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
        if dynamic_args.freeze_gate or dynamic_args.paper_gate or dynamic_args.research_gate:
            from scytaledroid.DynamicAnalysis.tools import freeze_gate

            return int(freeze_gate.main(["--research"]))
        dynamic_parser.error("No dynamic command selected. Use --freeze-gate.")
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
        "--deploy-check",
        action="store_true",
        help="Host / adb / DB smoke check, then exit",
    )
    parser.add_argument(
        "--require-database",
        action="store_true",
        help="With --deploy-check: fail if DB missing or unreachable",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON (with --diag or --deploy-check)",
    )
    args = parser.parse_args(argv)

    if args.json and not args.diag and not args.deploy_check:
        parser.error("--json requires --diag or --deploy-check")

    if args.diag and args.deploy_check:
        parser.error("Choose either --diag or --deploy-check (not both)")

    if args.deploy_check:
        from scytaledroid.Diagnostics.deployment_check import run as run_deploy_check

        return run_deploy_check(
            json_mode=args.json,
            require_database=args.require_database,
        )

    if args.diag:
        _run_diagnostics(json_mode=args.json)
        return 0

    print_banner(show_clocks=args.with_clocks)
    try:
        main_menu()
    except KeyboardInterrupt:
        try:
            from scytaledroid.DeviceAnalysis.inventory.cli_labels import MAIN_INTERRUPT_NOTICE
            from scytaledroid.DeviceAnalysis.inventory.progress import finalize_inventory_live_tty

            finalize_inventory_live_tty()
        except Exception:
            MAIN_INTERRUPT_NOTICE = "Stopped by operator (Ctrl+C)."
        print()
        status_messages.print_status(MAIN_INTERRUPT_NOTICE, level="warn")
        log.info("Application interrupted by user.", category="application")
    return 0


if __name__ == "__main__":
    sys.exit(main())
