"""Bindings re-exported on ``run_dispatch`` for lazy ``static_scan_launch`` (`_dispatch.*`) and pytest.

Keeping these in one module documents the patch surface and avoids noisy unused-import
warnings on the thin ``run_dispatch`` orchestration file.
"""

from __future__ import annotations

import signal

from scytaledroid.Config import app_config
from scytaledroid.Database.db_utils import diagnostics as db_diagnostics
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.LoggingUtils import logging_events as log_events
from scytaledroid.Utils.LoggingUtils.logging_context import get_run_logger

from ..core.run_lifecycle import finalize_open_runs
from ..execution.db_verification import _render_persistence_footer
from ..execution.heartbeat_state import set_phase as _hb_set_phase
from ..execution.heartbeat_state import set_run as _hb_set_run
from ..execution.results import _emit_static_persistence_event, prompt_deferred_post_run_diagnostics
from ..execution.results_persist import _persist_cohort_rollup
from ..execution.static_run_map import REQUIRED_FIELDS, validate_run_map
from . import persistence_runtime
from .postprocessing import run_post_summary_postprocessing
from .run_events import _emit_db_preflight_lock_warning, _emit_postprocessing_step
from .run_locking import _write_execution_marker
from .run_selection_manifest import _emit_selection_manifest
from .run_session_map import (
    _build_session_run_map,
    _detect_duplicate_packages,
    _ensure_session_finalization_outputs,
    _persist_session_run_links,
    _rebuild_session_run_map_from_db,
    _session_completed_run_count,
    _session_run_link_count,
    _session_run_map_path,
)
from .static_run_preflight import (
    emit_static_run_preflight_summary as _emit_static_run_preflight_summary,
)

__all__ = [
    "REQUIRED_FIELDS",
    "_build_session_run_map",
    "_detect_duplicate_packages",
    "_emit_db_preflight_lock_warning",
    "_emit_postprocessing_step",
    "_emit_selection_manifest",
    "_emit_static_persistence_event",
    "_emit_static_run_preflight_summary",
    "_ensure_session_finalization_outputs",
    "_hb_set_phase",
    "_hb_set_run",
    "_persist_cohort_rollup",
    "_persist_session_run_links",
    "_rebuild_session_run_map_from_db",
    "_render_persistence_footer",
    "_session_completed_run_count",
    "_session_run_link_count",
    "_session_run_map_path",
    "_write_execution_marker",
    "app_config",
    "db_diagnostics",
    "finalize_open_runs",
    "get_run_logger",
    "logging_engine",
    "log_events",
    "persistence_runtime",
    "prompt_deferred_post_run_diagnostics",
    "run_post_summary_postprocessing",
    "signal",
    "validate_run_map",
]
