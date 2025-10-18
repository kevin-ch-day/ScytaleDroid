"""Compatibility layer exposing CLI execution helpers."""

from __future__ import annotations

from pathlib import Path

from .execution import (
    build_analysis_config,
    configure_logging_for_cli,
    execute_permission_scan,
    execute_scan,
    format_duration,
    generate_report,
    render_run_results,
)
from .models import RunParameters, ScopeSelection
from .prompts import prompt_tuning
from .scope import format_scope_target


def launch_scan_flow(selection: ScopeSelection, params: RunParameters, base_dir: Path) -> None:
    """Primary entry point for running static analysis flows from the CLI."""

    scope_target = format_scope_target(selection)
    print()
    print(f"Running — {params.profile_label} static analysis")
    print(f"Target : {scope_target}")
    print(f"Profile: {params.profile_label}")
    print("-" * 41)

    configure_logging_for_cli(params.log_level)

    if params.profile == "permissions":
        execute_permission_scan(selection, params)
        return

    outcome = execute_scan(selection, params, base_dir)
    render_run_results(outcome, params)

    if params.profile in {"full", "lightweight"}:
        try:
            perm_params = prompt_tuning(params)
            print()
            print("-- Re-rendering Permission Analysis snapshot for parity --")
            execute_permission_scan(selection, perm_params, persist_detections=False)
        except Exception:
            pass


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
