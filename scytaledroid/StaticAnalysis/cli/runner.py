"""Compatibility layer exposing CLI execution helpers."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
from dataclasses import replace

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import summary_cards, status_messages
from scytaledroid.Utils.System import output_prefs
from scytaledroid.StaticAnalysis.persistence import ingest as canonical_ingest
from scytaledroid.StaticAnalysis.session import make_session_stamp

from .execution import (
    build_analysis_config,
    configure_logging_for_cli,
    execute_permission_scan,
    execute_scan,
    format_duration,
    generate_report,
    render_run_results,
)
from .models import RunParameters, RunOutcome, ScopeSelection
from .profiles import run_modules_for_profile
from .scope import format_scope_target


def launch_scan_flow(selection: ScopeSelection, params: RunParameters, base_dir: Path) -> RunOutcome | None:
    """Primary entry point for running static analysis flows from the CLI."""

    previous_stamp = (params.session_stamp or "").strip()
    session_stamp = make_session_stamp()
    if previous_stamp and session_stamp == previous_stamp:
        session_stamp = make_session_stamp()
    params = replace(params, session_stamp=session_stamp)
    output_prefs.set_verbose(bool(params.verbose_output))

    try:
        canonical_ingest.ensure_provider_plumbing()
        if params.session_stamp:
            canonical_ingest.build_session_string_view(params.session_stamp)
    except Exception:
        pass

    workers = _resolve_workers(params.workers)
    if not params.reuse_cache:
        _purge_run_cache()

    modules = _modules_for_run(params)
    scope_target = format_scope_target(selection)

    workers_label = f"auto ({workers})" if isinstance(params.workers, str) else str(workers)
    summary_items: list[tuple[str, object]] = [
        ("Scope", scope_target),
        ("Profile", params.profile_label),
        ("Session", params.session_stamp),
        ("Workers", workers_label),
        ("Cache", "purge" if not params.reuse_cache else "reuse"),
        ("Log level", params.log_level.upper()),
        (
            "Permission refresh",
            "on" if params.permission_snapshot_refresh else "off",
        ),
    ]
    if modules:
        summary_items.append(("Detectors", ", ".join(modules)))
    if params.trace_detectors:
        summary_items.append(("Trace IDs", ", ".join(params.trace_detectors)))

    print(
        summary_cards.format_summary_card(
            "Static Analysis Run",
            summary_items,
            subtitle=f"Target: {scope_target}",
            footer="Run executes immediately after this summary.",
            width=90,
        )
    )
    print()

    configure_logging_for_cli(params.log_level)

    if params.profile == "permissions":
        print(status_messages.step("Starting permission analysis workflow", label="Static Analysis"))
        execute_permission_scan(selection, params)
        return None

    print(status_messages.step("Starting detector pipeline", label="Static Analysis"))
    outcome = execute_scan(selection, params, base_dir)
    try:
        setattr(outcome, "session_stamp", params.session_stamp)
    except Exception:
        pass
    render_run_results(outcome, params)

    if params.session_stamp:
        try:
            canonical_ingest.upsert_base002_for_session(params.session_stamp)
            canonical_ingest.build_session_string_view(params.session_stamp)
        except Exception:
            pass

    if (
        params.permission_snapshot_refresh
        and params.profile in {"full", "lightweight"}
        and not params.dry_run
    ):
        try:
            print()
            print(
                status_messages.step(
                    "Re-rendering permission snapshot for parity",
                    label="Static Analysis",
                )
            )
            execute_permission_scan(selection, params, persist_detections=False)
        except Exception:
            pass
    elif params.profile in {"full", "lightweight"} and not params.dry_run:
        print()
        print(
            status_messages.status(
                "Post-run permission refresh skipped (toggle in advanced options).",
                level="info",
            )
        )

    return outcome


def _modules_for_run(params: RunParameters) -> tuple[str, ...]:
    if params.profile == "custom" and params.selected_tests:
        return params.selected_tests
    return run_modules_for_profile(params.profile)


def _resolve_workers(value: str | int) -> int:
    if isinstance(value, int):
        return max(1, value)
    text = (value or "").strip().lower()
    if text.isdigit():
        return max(1, int(text))
    return max(1, os.cpu_count() or 1)


def _purge_run_cache() -> None:
    cache_roots = [
        Path(app_config.DATA_DIR) / "static_analysis" / "cache",
        Path(app_config.DATA_DIR) / "static_analysis" / "tmp",
    ]
    for root in cache_roots:
        try:
            if root.exists():
                shutil.rmtree(root)
        except OSError:
            continue


__all__ = [
    "launch_scan_flow",
    "configure_logging_for_cli",
    "execute_scan",
    "execute_permission_scan",
    "generate_report",
    "build_analysis_config",
    "render_run_results",
    "format_duration",
]
