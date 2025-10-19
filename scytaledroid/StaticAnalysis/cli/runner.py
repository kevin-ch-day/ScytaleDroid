"""Compatibility layer exposing CLI execution helpers."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
from dataclasses import replace
from datetime import datetime, timedelta

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import menu_utils, text_blocks
from scytaledroid.Utils.System import output_prefs

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

    previous_stamp = params.session_stamp or ""
    now = datetime.now()
    session_stamp = now.strftime("%Y%m%d-%H%M%S")
    if session_stamp == previous_stamp:
        session_stamp = (now + timedelta(seconds=1)).strftime("%Y%m%d-%H%M%S")
    params = replace(params, session_stamp=session_stamp)
    output_prefs.set_verbose(bool(params.verbose_output))

    workers = _resolve_workers(params.workers)
    if not params.reuse_cache:
        _purge_run_cache()

    modules = _modules_for_run(params)
    scope_target = format_scope_target(selection)

    summary_lines = [
        f"Scope    : {scope_target}",
        f"Profile  : {params.profile_label}",
        f"Session  : {params.session_stamp}",
    ]
    workers_label = f"auto ({workers})" if isinstance(params.workers, str) else str(workers)
    summary_lines.append(f"Workers  : {workers_label}")
    summary_lines.append(f"Cache    : {'purge' if not params.reuse_cache else 'reuse'}")
    summary_lines.append(f"Log level: {params.log_level.upper()}")
    if modules:
        summary_lines.append(f"Detectors: {', '.join(modules)}")
    if params.trace_detectors:
        summary_lines.append(f"Trace IDs: {', '.join(params.trace_detectors)}")

    print(text_blocks.boxed(summary_lines, width=80))
    print()

    configure_logging_for_cli(params.log_level)

    if params.profile == "permissions":
        execute_permission_scan(selection, params)
        return None

    outcome = execute_scan(selection, params, base_dir)
    try:
        setattr(outcome, "session_stamp", params.session_stamp)
    except Exception:
        pass
    render_run_results(outcome, params)

    if params.profile in {"full", "lightweight"} and not params.dry_run:
        try:
            print()
            print("-- Re-rendering Permission Analysis snapshot for parity --")
            execute_permission_scan(selection, params, persist_detections=False)
        except Exception:
            pass

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
