"""Run- and app-level health summaries for static analysis (telemetry rollup, audit JSON).

V1 aggregates per-artifact pipeline metadata already produced by detector runs — no detector
behavior changes — and writes one ``run_health.json`` per CLI session directory after persistence.
"""

from __future__ import annotations

from .cli_output import (
    attach_run_health_outputs_on_document,
    compact_run_health_stdout_line,
    format_run_health_stdout_lines,
    sanitize_session_stamp_for_filename,
    write_run_health_json,
)
from .document import build_run_health_document
from .governance import infer_session_governance_snapshot
from .projection import collect_report_paths_for_app
from .rollup import merge_skipped_detectors, rollup_parse_fallback_signals
from .signals import string_summary_signals, summarize_execution_signals_for_app
from .status import (
    compute_app_final_status,
    compute_run_aggregate_status,
    reconcile_app_final_status_after_persistence,
)

__all__ = [
    "attach_run_health_outputs_on_document",
    "build_run_health_document",
    "collect_report_paths_for_app",
    "compact_run_health_stdout_line",
    "compute_app_final_status",
    "compute_run_aggregate_status",
    "format_run_health_stdout_lines",
    "infer_session_governance_snapshot",
    "merge_skipped_detectors",
    "reconcile_app_final_status_after_persistence",
    "rollup_parse_fallback_signals",
    "sanitize_session_stamp_for_filename",
    "string_summary_signals",
    "summarize_execution_signals_for_app",
    "write_run_health_json",
]
