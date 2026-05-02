"""Compatibility layer exposing CLI execution helpers."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from scytaledroid.Database.summary_surfaces import refresh_static_dynamic_summary_cache
from scytaledroid.StaticAnalysis.session import make_session_stamp, normalize_session_stamp
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.System import output_prefs

from ..core.models import RunOutcome, RunParameters, ScopeSelection
from ..core.run_specs import StaticRunSpec
from ..execution import (
    build_analysis_config,
    configure_logging_for_cli,
    execute_permission_scan,
    execute_scan,
    format_duration,
    generate_report,
    render_run_results,
)

# Star import: pytest monkeypatch + lazy `_dispatch.*` expect these on `run_dispatch`.
from .run_dispatch_surface import *  # noqa: F403
from .run_locking import (
    _acquire_static_run_lock,
    _release_static_run_lock,
)
from .run_persistence_audit import _emit_missing_run_ids_artifact
from .run_session_finalization import _session_finalization_issues
from .session_finalizer import refresh_static_session_cache
from .session_stamp_resolution import resolve_unique_session_stamp as _resolve_unique_session_stamp
from .static_run_preflight import (
    check_static_persistence_readiness as _check_static_persistence_readiness,
)
from .static_scan_launch import launch_scan_flow_resolved as _launch_scan_flow_resolved_impl


@dataclass(frozen=True)
class RunExecutionResult:
    """Execution result plus the effective parameters used for the run."""

    outcome: RunOutcome | None
    params: RunParameters
    completed: bool
    detail: str | None = None


def _resolve_effective_run_params(
    params: RunParameters,
    *,
    run_mode: str,
    noninteractive: bool,
    quiet: bool,
) -> tuple[RunParameters | None, str | None]:
    """Resolve session identity and persistence readiness before execution."""

    previous_stamp = (params.session_stamp or "").strip()
    session_stamp = make_session_stamp()
    if previous_stamp and session_stamp == previous_stamp:
        session_stamp = make_session_stamp()
    # Enforce unique session per run unless explicitly set by caller.
    if not previous_stamp:
        params = replace(params, session_stamp=session_stamp)
    desired_session_stamp = params.session_stamp or session_stamp
    if params.session_stamp:
        normalized = normalize_session_stamp(params.session_stamp)
        if normalized != params.session_stamp:
            reason = "character safety"
            if len(normalized) != len(params.session_stamp):
                reason = "length safety"
            if not output_prefs.effective_quiet():
                print(
                    status_messages.status(
                        (
                            "Session label normalized for cross-table "
                            f"{reason} ({len(params.session_stamp)}→{len(normalized)} chars): "
                            f"'{params.session_stamp}' → '{normalized}'."
                        ),
                        level="warn",
                    )
                )
            params = replace(params, session_stamp=normalized)
            desired_session_stamp = normalized
    try:
        resolved_stamp, session_label, canonical_action = _resolve_unique_session_stamp(
            desired_session_stamp,
            run_mode=run_mode,
            noninteractive=noninteractive,
            quiet=quiet,
            canonical_action=params.canonical_action,
        )
        params = replace(
            params,
            session_stamp=resolved_stamp,
            session_label=session_label,
            canonical_action=canonical_action,
        )
    except RuntimeError as exc:
        print(status_messages.status(str(exc), level="error"))
        return None, str(exc)
    # Honor output prefs when execute_run_spec has already set them.
    output_prefs.set_verbose(bool(params.verbose_output))

    persistence_ready, persistence_note, _ = _check_static_persistence_readiness(params)
    # Freeze persistence readiness into the run parameters for this run. We avoid mutating
    # process env mid-run to keep execution deterministic and auditable.
    params = replace(params, persistence_ready=bool(persistence_ready))
    if not persistence_ready:
        level = "error" if params.strict_persistence or params.paper_grade_requested else "warn"
        print(status_messages.status(persistence_note, level=level))
        if (params.strict_persistence or params.paper_grade_requested) and not params.dry_run:
            print(
                status_messages.status(
                    (
                        "Canonical-grade runs require canonical schema readiness. "
                        "Run schema bootstrap or set SCYTALEDROID_CANONICAL_GRADE=0 "
                        "to allow experimental runs."
                    ),
                    level="error",
                )
            )
            print(
                status_messages.status(
                    "Menu path: Database tools → Apply canonical schema bootstrap",
                    level="info",
                )
            )
            return None, (
                f"{persistence_note} Canonical-grade runs require canonical schema readiness."
            )

    return params, None


def launch_scan_flow(selection: ScopeSelection, params: RunParameters, base_dir: Path) -> RunOutcome | None:
    """Primary entry point for running static analysis flows from the CLI."""

    effective_params, _ = _resolve_effective_run_params(
        params,
        run_mode=output_prefs.effective_run_mode(),
        noninteractive=output_prefs.effective_noninteractive(),
        quiet=output_prefs.effective_quiet(),
    )
    if effective_params is None:
        return None
    lock_path: Path | None = None
    try:
        lock_path = _acquire_static_run_lock(effective_params)
    except RuntimeError as exc:
        print(status_messages.status(str(exc), level="error"))
        return None
    try:
        return _launch_scan_flow_resolved(selection, effective_params, base_dir)
    finally:
        _release_static_run_lock(lock_path)


def _launch_scan_flow_resolved(
    selection: ScopeSelection,
    params: RunParameters,
    base_dir: Path,
) -> RunOutcome | None:
    """Execute the static scan using already-resolved parameters."""

    return _launch_scan_flow_resolved_impl(
        selection,
        params,
        base_dir,
        emit_missing_run_ids_artifact=_emit_missing_run_ids_artifact,
        session_finalization_issues=_session_finalization_issues,
    )


def execute_run_spec_detailed(spec: StaticRunSpec) -> RunExecutionResult:
    """Execute a prepared run spec and return the effective params plus completion state."""

    prev_prefs = output_prefs.snapshot()
    prev_ctx = output_prefs.get_run_context()
    from scytaledroid.StaticAnalysis.engine.strings_runtime import get_config as _get_strings_cfg
    from scytaledroid.StaticAnalysis.engine.strings_runtime import set_config as _set_strings_cfg
    prev_strings_cfg = _get_strings_cfg()
    output_prefs.set_quiet(spec.quiet)
    output_prefs.set_batch(spec.run_mode == "batch" or spec.noninteractive)
    output_prefs.set_run_mode(spec.run_mode)
    output_prefs.set_noninteractive(spec.noninteractive)
    output_prefs.set_show_splits(bool(spec.params.show_split_summaries))
    from ..core.run_context import build_static_run_context
    output_prefs.set_run_context(build_static_run_context(spec))
    _set_strings_cfg(
        _get_strings_cfg().__class__(
            include_https_risk=bool(spec.params.string_include_https_risk),
            debug=bool(spec.params.string_debug),
            skip_resources_on_arsc_warn=bool(spec.params.string_skip_resources_on_warn),
            long_string_length=int(spec.params.string_long_string_length),
            low_entropy_threshold=float(spec.params.string_low_entropy_threshold),
        )
    )
    try:
        effective_params, detail = _resolve_effective_run_params(
            spec.params,
            run_mode=spec.run_mode,
            noninteractive=spec.noninteractive,
            quiet=spec.quiet,
        )
        if effective_params is None:
            return RunExecutionResult(
                outcome=None,
                params=spec.params,
                completed=False,
                detail=detail,
            )
        output_prefs.set_run_context(build_static_run_context(replace(spec, params=effective_params)))
        try:
            lock_path = _acquire_static_run_lock(effective_params)
        except RuntimeError as exc:
            print(status_messages.status(str(exc), level="error"))
            return RunExecutionResult(
                outcome=None,
                params=effective_params,
                completed=False,
                detail=str(exc),
            )
        try:
            outcome = _launch_scan_flow_resolved(spec.selection, effective_params, spec.base_dir)
        finally:
            _release_static_run_lock(lock_path)
        if outcome is not None and not bool(getattr(effective_params, "dry_run", False)):
            try:
                cache_result = refresh_static_session_cache(
                    refresh_cache=refresh_static_dynamic_summary_cache,
                )
                log.info(
                    "Refreshed static/dynamic summary cache "
                    f"(rows={cache_result.cache_rows} materialized_at={cache_result.cache_materialized_at})",
                    category="static_analysis",
                )
            except Exception as exc:
                log.warning(
                    f"Static analysis completed but summary cache refresh failed: {exc}",
                    category="static_analysis",
                )
        return RunExecutionResult(
            outcome=outcome,
            params=effective_params,
            completed=True,
            detail=detail,
        )
    finally:
        output_prefs.restore(prev_prefs)
        output_prefs.set_run_context(prev_ctx)
        _set_strings_cfg(prev_strings_cfg)


def execute_run_spec(spec: StaticRunSpec) -> RunOutcome | None:
    """Execute a prepared run spec without prompting."""

    return execute_run_spec_detailed(spec).outcome


__all__ = [
    "launch_scan_flow",
    "execute_run_spec",
    "execute_run_spec_detailed",
    "configure_logging_for_cli",
    "execute_scan",
    "execute_permission_scan",
    "generate_report",
    "build_analysis_config",
    "render_run_results",
    "format_duration",
]
