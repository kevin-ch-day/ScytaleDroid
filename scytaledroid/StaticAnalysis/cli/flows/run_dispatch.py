"""Compatibility layer exposing CLI execution helpers."""

from __future__ import annotations

import json
import os
import shutil
import signal
import hashlib
import re
import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_utils import diagnostics as db_diagnostics
from scytaledroid.Database.db_utils import schema_gate
from scytaledroid.StaticAnalysis.session import make_session_stamp, normalize_session_stamp
from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_engine
from scytaledroid.Utils.LoggingUtils import logging_events as log_events
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.LoggingUtils.logging_context import RunContext, get_run_logger
from scytaledroid.Utils.System import output_prefs

from ..core.abort_reasons import classify_exception, normalize_abort_reason
from ..core.analysis_profiles import run_modules_for_profile
from ..core.models import AppRunResult, RunOutcome, RunParameters, ScopeSelection
from ..core.run_context import StaticRunContext
from ..core.run_lifecycle import finalize_open_runs
from ..core.run_specs import StaticRunSpec
from ..execution import (
    build_analysis_config,
    configure_logging_for_cli,
    execute_permission_scan,
    execute_scan,
    format_duration,
    generate_report,
    render_run_results,
    request_abort,
)
from ..execution.static_run_map import REQUIRED_FIELDS, validate_run_map
from ..views.view_layouts import render_run_start, render_run_summary
from . import persistence_runtime
from .selection import format_scope_target


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
        try:
            resolved_stamp, session_label, canonical_action = _resolve_unique_session_stamp(
                params.session_stamp,
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
    else:
        try:
            resolved_stamp, session_label, canonical_action = _resolve_unique_session_stamp(
                session_stamp,
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

    persistence_ready, persistence_note = _check_static_persistence_readiness(params)
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
    return _launch_scan_flow_resolved(selection, effective_params, base_dir)


def _launch_scan_flow_resolved(
    selection: ScopeSelection,
    params: RunParameters,
    base_dir: Path,
) -> RunOutcome | None:
    """Execute the static scan using already-resolved parameters."""

    # Freeze run context once. Deep execution/render paths must not read env vars or
    # mutable output prefs after this point.
    frozen_ctx = StaticRunContext(
        run_mode=output_prefs.effective_run_mode(),
        quiet=output_prefs.effective_quiet(),
        batch=output_prefs.effective_batch(),
        noninteractive=output_prefs.effective_noninteractive(),
        show_splits=output_prefs.effective_show_splits(),
        session_stamp=params.session_stamp,
        persistence_ready=bool(getattr(params, "persistence_ready", True)),
        paper_grade_requested=bool(getattr(params, "paper_grade_requested", True)),
    )
    run_persistence_enabled = persistence_runtime.persistence_enabled(
        dry_run=params.dry_run,
        persistence_ready=bool(params.persistence_ready),
    )

    if run_persistence_enabled:
        persistence_runtime.bootstrap_runtime_persistence(
            session_stamp=params.session_stamp,
            dry_run=params.dry_run,
            persistence_ready=bool(params.persistence_ready),
            strict_persistence=bool(params.strict_persistence),
        )

    workers = _resolve_workers(params.workers)
    if not params.reuse_cache:
        _purge_run_cache()

    modules = _modules_for_run(params)
    scope_target = format_scope_target(selection)
    _emit_selection_manifest(selection, params.session_stamp)
    if not (frozen_ctx.quiet and frozen_ctx.batch):
        print()

    workers_label = f"auto ({workers})" if isinstance(params.workers, str) else str(workers)
    if not (frozen_ctx.quiet and frozen_ctx.batch):
        render_run_start(
            run_id=params.session_stamp,
            profile_label=params.profile_label,
            target=scope_target,
            modules=modules,
            workers_desc=workers_label,
            cache_desc="purge" if not params.reuse_cache else "reuse",
            log_level=params.log_level,
            perm_cache_desc="refresh" if params.permission_snapshot_refresh else "skip",
            run_ctx=frozen_ctx,
            trace_ids=params.trace_detectors,
        )

    # Structured RUN_START log with context
    run_ctx = RunContext(
        subsystem="static",
        device_serial=getattr(selection, "device_serial", None),
        device_model=None,
        run_id=params.session_stamp,
        scope=scope_target,
        profile=params.profile_label,
    )
    try:
        static_logger = get_run_logger("static", run_ctx)
        run_context_payload = dict(frozen_ctx.__dict__)
        run_context_payload["canonical_grade_requested"] = run_context_payload.pop(
            "paper_grade_requested",
            bool(getattr(params, "paper_grade_requested", True)),
        )
        static_logger.info(
            "Static RUN_START",
            extra={
                "event": log_events.RUN_START,
                "run_id": params.session_stamp,
                "target": scope_target,
                "profile": params.profile_label,
                "scope_label": params.scope_label,
                "analysis_version": params.analysis_version,
                "modules": modules,
                "workers": workers_label,
                "cache": "purge" if not params.reuse_cache else "reuse",
                "perm_cache": "refresh" if params.permission_snapshot_refresh else "skip",
                "dry_run": params.dry_run,
                "run_context": run_context_payload,
            },
        )
    except Exception:
        static_logger = None

    configure_logging_for_cli(params.log_level)

    abort_notified = {"shown": False}

    def _handle_sigint(signum, frame) -> None:  # pragma: no cover - signal path
        if not abort_notified["shown"]:
            print(status_messages.status("Interrupt received — stopping safely…", level="warn"))
            abort_notified["shown"] = True
        request_abort(reason="SIGINT", signal="SIGINT")

    previous_handler = None
    sigint_installed = False
    try:
        if threading.current_thread() is threading.main_thread():
            previous_handler = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, _handle_sigint)
            sigint_installed = True
    except ValueError as exc:  # pragma: no cover - defensive
        log.warning(f"Skipping SIGINT handler install: {exc}", category="static")

    if params.profile == "permissions":
        print(status_messages.step("Starting permission analysis workflow", label="Static Analysis"))
        try:
            execute_permission_scan(selection, params)
        finally:
            if sigint_installed and previous_handler is not None:
                signal.signal(signal.SIGINT, previous_handler)
        return None

    if params.dry_run:
        pipeline_version = getattr(params, "analysis_version", None)
        run_sig_version = getattr(params, "run_signature_version", "v1")
        print("DIAGNOSTIC MODE (dry run)")
        print("────────────────────────────────")
        print("persist=no  evidence_pack=no  plan_generation=no")
        print("identity_required=yes  linkage_required=yes")
        print("metadata=partial  linkage_sources=run_map,db_link")
        print(f"pipeline_version={pipeline_version or '—'}  run_signature_version={run_sig_version}")
        if params.session_stamp:
            print(
                f"Session: {params.session_stamp}  Profile: {params.profile_label}  "
                f"Scope: {params.scope_label or params.scope}"
            )
        print()
    from scytaledroid.Utils.DisplayUtils import text_blocks

    if not (frozen_ctx.quiet and frozen_ctx.batch):
        print("Starting Static Analysis pipeline")
        print(text_blocks.divider("─"))
    _emit_db_preflight_lock_warning(params=params, run_ctx=frozen_ctx)
    outcome: RunOutcome | None = None
    run_status: str | None = None
    abort_reason: str | None = None
    abort_signal: str | None = None
    try:
        outcome = execute_scan(selection, params, base_dir, run_ctx=frozen_ctx)
    finally:
        if sigint_installed and previous_handler is not None:
            signal.signal(signal.SIGINT, previous_handler)
    try:
        if outcome is not None:
            outcome.session_stamp = params.session_stamp
    except Exception:
        pass
    run_map = None
    linkage_blocked_reason = None
    linkage_warning_printed = False
    missing_id_packages: list[str] = []
    summary_render_failed = False

    try:
        if outcome is not None:
            run_status = "COMPLETED"
            if outcome.aborted or outcome.failures:
                run_status = "FAILED"
            abort_reason = normalize_abort_reason(outcome.abort_reason or ("SIGINT" if outcome.aborted else None))
            abort_signal = outcome.abort_signal
            _emit_postprocessing_step("Rendering run summary", run_ctx=frozen_ctx)
            try:
                render_run_results(outcome, params, run_ctx=frozen_ctx)
            except Exception as exc:
                run_status = "FAILED"
                abort_reason = "run_summary_render_failed"
                summary_render_failed = True
                failure_code = f"run_summary_render_failed:{exc.__class__.__name__}"
                if failure_code not in outcome.failures:
                    outcome.failures.append(failure_code)
                logging_engine.get_error_logger().exception(
                    "Run summary rendering failed",
                    extra=logging_engine.ensure_trace(
                        {
                            "event": "static.run_summary_render_failed",
                            "session_stamp": params.session_stamp,
                            "scope_label": params.scope_label,
                            "profile": params.profile_label,
                        }
                    ),
                )
                print(
                    status_messages.status(
                        (
                            "Run summary finalization failed — static run marked failed. "
                            "Skipping downstream post-processing."
                        ),
                        level="error",
                    )
                )
            if not params.dry_run:
                if summary_render_failed:
                    linkage_blocked_reason = (
                        "Run summary finalization failed; skipping run_map and permission refresh."
                    )
                elif not params.persistence_ready:
                    linkage_blocked_reason = "Persistence gate failed; skipping run_map and permission refresh."
                elif not outcome.results:
                    linkage_blocked_reason = (
                        "No analyzable artifacts; skipping run_map and permission refresh."
                    )
                else:
                    missing_id_packages = [res.package_name for res in outcome.results if not res.static_run_id]
                    if missing_id_packages:
                        linkage_blocked_reason = (
                            "static_run_id missing for one or more apps; skipping run_map and permission refresh."
                        )

                if params.session_stamp:
                    if linkage_blocked_reason:
                        print(status_messages.status(linkage_blocked_reason, level="warn"))
                        linkage_warning_printed = True
                    else:
                        _emit_postprocessing_step("Building session run map", run_ctx=frozen_ctx)
                        try:
                            run_map = _build_session_run_map(
                                outcome,
                                params.session_stamp,
                                allow_overwrite=bool(params.run_map_overwrite),
                            )
                            if run_map:
                                for entry in run_map.get("apps", []):
                                    missing = [
                                        field
                                        for field in ("static_run_id", *REQUIRED_FIELDS)
                                        if entry.get(field) in (None, "")
                                    ]
                                    if missing:
                                        raise RuntimeError(
                                            "run_map incomplete for package "
                                            f"{entry.get('package')}: missing {', '.join(missing)}"
                                        )
                                validate_run_map(run_map, params.session_stamp)
                                _persist_session_run_links(params.session_stamp, run_map)
                        except Exception as exc:
                            if params.strict_persistence:
                                raise RuntimeError(
                                    f"Failed to build run map for session {params.session_stamp}: {exc}"
                                ) from exc
                            print(
                                status_messages.status(
                                    f"Failed to build run map for session {params.session_stamp}: {exc}",
                                    level="error",
                                )
                            )
                            run_map = None

                _emit_postprocessing_step("Writing persistence audit artifacts", run_ctx=frozen_ctx)
                _emit_missing_run_ids_artifact(
                    outcome=outcome,
                    session_stamp=params.session_stamp,
                    linkage_blocked_reason=linkage_blocked_reason,
                    missing_id_packages=missing_id_packages,
                )

                if params.permission_snapshot_refresh and params.profile in {"full", "lightweight"}:
                    if linkage_blocked_reason:
                        if not linkage_warning_printed:
                            print()
                            print(status_messages.status(linkage_blocked_reason, level="warn"))
                            linkage_warning_printed = True
                    else:
                        try:
                            _emit_postprocessing_step(
                                "Re-rendering permission snapshot for parity",
                                run_ctx=frozen_ctx,
                            )
                            execute_permission_scan(
                                selection,
                                params,
                                persist_detections=True,
                                run_map=run_map,
                                require_run_map=True,
                                compact_output=True,
                                fail_on_persist_error=True,
                            )
                        except Exception as exc:
                            run_status = "FAILED"
                            abort_reason = "permission_snapshot_refresh_failed"
                            logging_engine.get_error_logger().exception(
                                "Permission snapshot refresh failed",
                                extra=logging_engine.ensure_trace(
                                    {
                                        "event": "static.permission_snapshot_refresh_failed",
                                        "session_stamp": params.session_stamp,
                                        "scope_label": params.scope_label,
                                        "profile": params.profile_label,
                                    }
                                ),
                            )
                            print(
                                status_messages.status(
                                    (
                                        "Permission snapshot refresh failed — static run marked failed. "
                                        "See logs for details."
                                    ),
                                    level="error",
                                )
                            )
                elif params.profile in {"full", "lightweight"}:
                    _emit_postprocessing_step(
                        "Permission snapshot refresh skipped (disabled)",
                        run_ctx=frozen_ctx,
                    )
                    print(
                        status_messages.status(
                            (
                                "Post-run permission refresh skipped. Enable it in Advanced options "
                                "or set SCYTALEDROID_STATIC_REFRESH_PERMISSION_SNAPSHOT=1."
                            ),
                            level="info",
                        )
                    )
    except Exception as exc:
        run_status = "FAILED"
        abort_reason = classify_exception(exc)
        if outcome is not None:
            failure_code = f"postprocess_exception:{exc.__class__.__name__}"
            if failure_code not in outcome.failures:
                outcome.failures.append(failure_code)
        raise
    finally:
        if outcome is not None and not params.dry_run and run_status:
            static_run_ids = [
                result.static_run_id
                for result in outcome.results
                if result.static_run_id
            ]
            # Recovery: persistence failures may null out static_run_id on app results
            # after a STARTED row was created. Close any lingering STARTED rows for
            # this session stamp so dashboards do not accumulate phantom open runs.
            if params.session_stamp:
                try:
                    from scytaledroid.Database.db_core import db_queries as core_q

                    rows = core_q.run_sql(
                        """
                        SELECT id
                        FROM static_analysis_runs
                        WHERE session_stamp=%s
                          AND status='STARTED'
                          AND ended_at_utc IS NULL
                        """,
                        (params.session_stamp,),
                        fetch="all",
                    )
                    for row in rows or []:
                        try:
                            sid = int(row[0])
                        except Exception:
                            continue
                        static_run_ids.append(sid)
                except Exception:
                    pass
            if static_run_ids:
                static_run_ids = sorted(set(int(sid) for sid in static_run_ids if sid))
                ended_at = outcome.finished_at.isoformat(timespec="seconds") + "Z"
                finalize_open_runs(
                    static_run_ids,
                    status=run_status,
                    ended_at_utc=ended_at,
                    abort_reason=normalize_abort_reason(abort_reason),
                    abort_signal=abort_signal,
                )

        # Always emit a RUN_END record even if summary rendering failed.
        if params.session_stamp:
            end_payload = {
                "event": log_events.RUN_END,
                "run_id": params.session_stamp,
                "target": scope_target,
                "profile": params.profile_label,
                "scope_label": params.scope_label,
                "analysis_version": params.analysis_version,
                "detectors": modules,
                "detectors_count": len(modules),
                "status": (run_status or "UNKNOWN").lower(),
                "dry_run": params.dry_run,
            }
            if outcome is not None:
                end_payload["duration_seconds"] = outcome.duration_seconds
                end_payload["applications"] = len(outcome.results or [])
                end_payload["artifacts"] = outcome.total_artifacts
                end_payload["artifacts_completed"] = outcome.completed_artifacts
                end_payload["dry_run_skipped"] = outcome.dry_run_skipped
                end_payload["warnings_count"] = len(outcome.warnings or [])
                end_payload["failures_count"] = len(outcome.failures or [])
            try:
                static_logger = get_run_logger("static", run_ctx)
                static_logger.info("Static RUN_END", extra=end_payload)
            except Exception:
                try:
                    logger = logging_engine.get_static_logger()
                    logger.info("Static RUN_END", extra=logging_engine.ensure_trace(end_payload))
                except Exception:
                    pass

    # Structured RUN SUMMARY (formatter-based) for transcripts/screenshots.
    # Batch mode must stay quiet and deterministic (no per-app blocks).
    if outcome and getattr(outcome, "summary", None) and not frozen_ctx.batch:
        summary = outcome.summary
        sev_counts = {
            "high": getattr(summary, "high", 0),
            "medium": getattr(summary, "medium", 0),
            "low": getattr(summary, "low", 0),
        }
        perm_stats = {
            "dangerous": getattr(summary, "dangerous_permissions", 0),
            "signature": getattr(summary, "signature_permissions", 0),
            "custom": getattr(summary, "custom_permissions", 0),
        }
        failed_masvs = list(getattr(summary, "failed_masvs", []) or [])
        evidence_root = getattr(summary, "evidence_root", None)

        render_run_summary(
            run_id=params.session_stamp,
            profile_label=params.profile_label,
            target=scope_target,
            detectors_count=len(modules),
            findings_total=getattr(summary, "findings_total", 0),
            sev_counts=sev_counts,
            failed_masvs=failed_masvs,
            perm_stats=perm_stats,
            run_ctx=frozen_ctx,
            evidence_root=evidence_root,
        )
    if run_persistence_enabled and params.session_stamp:
        _emit_postprocessing_step("Refreshing canonical session views", run_ctx=frozen_ctx)
        try:
            persistence_runtime.refresh_session_views(
                session_stamp=params.session_stamp,
                dry_run=params.dry_run,
                persistence_ready=bool(params.persistence_ready),
            )
        except Exception:
            pass

    return outcome


def _emit_selection_manifest(selection: ScopeSelection, session_stamp: str | None) -> None:
    stamp = (session_stamp or "").strip() or "unspecified-session"
    groups = tuple(getattr(selection, "groups", ()) or ())
    capture_distribution: dict[str, int] = {}
    app_rows: list[dict[str, object]] = []
    digest_inputs: list[str] = []

    for group in groups:
        artifacts = tuple(getattr(group, "artifacts", ()) or ())
        package = str(getattr(group, "package_name", "") or "")
        group_key = str(getattr(group, "group_key", "") or "")
        capture_id = str(getattr(group, "capture_id", None) or "unknown")
        capture_distribution[capture_id] = capture_distribution.get(capture_id, 0) + len(artifacts)
        artifact_paths = sorted(
            str(getattr(artifact, "display_path", "") or "")
            for artifact in artifacts
        )
        digest_inputs.extend(path for path in artifact_paths if path)
        app_rows.append(
            {
                "package_name": package,
                "group_key": group_key,
                "capture_id": capture_id,
                "artifact_count": len(artifacts),
                "artifacts": artifact_paths,
            }
        )

    digest_payload = "\n".join(sorted(digest_inputs)).encode("utf-8")
    manifest = {
        "session_stamp": stamp,
        "scope": getattr(selection, "scope", None),
        "scope_label": getattr(selection, "label", None),
        "group_count": len(groups),
        "artifact_count": sum(int(row["artifact_count"]) for row in app_rows),
        "capture_distribution": dict(sorted(capture_distribution.items())),
        "artifact_manifest_sha256": hashlib.sha256(digest_payload).hexdigest(),
        "apps": sorted(
            app_rows,
            key=lambda row: (str(row.get("package_name", "")), str(row.get("group_key", ""))),
        ),
    }

    out_dir = Path("output") / "audit" / "selection"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{stamp}_selected_artifacts.json"
    out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    print(status_messages.status(f"Selection manifest: {out_path}", level="info"))


def _emit_postprocessing_step(message: str, *, run_ctx: StaticRunContext) -> None:
    if run_ctx.quiet and run_ctx.batch:
        return
    print()
    print(status_messages.step(message, label="Static Analysis"))


def _emit_db_preflight_lock_warning(*, params: RunParameters, run_ctx: StaticRunContext) -> None:
    if run_ctx.quiet and run_ctx.batch:
        return
    if params.dry_run or not params.persistence_ready:
        return
    try:
        snapshot = db_diagnostics.get_lock_health_snapshot(limit=10)
    except Exception:
        return
    if not isinstance(snapshot, dict):
        return
    if snapshot.get("error"):
        return
    active = snapshot.get("active_processes")
    if not isinstance(active, list) or not active:
        return
    long_running = [row for row in active if int(row.get("time_s") or 0) >= 5]
    if not long_running:
        return
    top = long_running[0]
    state = str(top.get("state") or "unknown")
    time_s = int(top.get("time_s") or 0)
    info = str(top.get("info") or "").strip()
    preview = (info[:120] + "…") if len(info) > 120 else info
    wait_timeout = snapshot.get("lock_wait_timeout_s")
    print(
        status_messages.status(
            (
                "DB preflight detected active SQL work that may contend with persistence "
                f"(lock_wait_timeout={wait_timeout}s): state={state} time={time_s}s "
                f"query={preview or '<redacted>'}"
            ),
            level="warn",
        )
    )


def _emit_missing_run_ids_artifact(
    *,
    outcome: RunOutcome,
    session_stamp: str | None,
    linkage_blocked_reason: str | None,
    missing_id_packages: list[str],
) -> None:
    stamp = (session_stamp or "").strip() or "unspecified-session"
    missing_set = set(missing_id_packages)
    failure_lines = [
        str(line)
        for line in (
            list(getattr(outcome, "failures", []) or [])
            + list(getattr(outcome, "errors", []) or [])
        )
        if isinstance(line, str)
    ]
    schema_version = db_diagnostics.get_schema_version() or "<unknown>"

    def _failure_lines_for_package(package: str) -> list[str]:
        package_key = (package or "").strip().lower()
        if not package_key:
            return []
        return [line for line in failure_lines if package_key in line.lower()]

    def _extract_retry_count(lines: list[str]) -> int:
        max_retry = 0
        for line in lines:
            for pattern in (r"retry_count=(\d+)", r"retry=(\d+)", r"attempt=(\d+)"):
                for match in re.finditer(pattern, line, flags=re.IGNORECASE):
                    try:
                        max_retry = max(max_retry, int(match.group(1)))
                    except Exception:
                        continue
        return max_retry

    def _extract_errno(lines: list[str]) -> int | None:
        for line in lines:
            # Matches "(1205, ...)" and "errno=1205" forms.
            match = re.search(r"\((\d{4})\s*,", line)
            if match:
                try:
                    return int(match.group(1))
                except Exception:
                    pass
            match = re.search(r"errno=(\d{4})", line, flags=re.IGNORECASE)
            if match:
                try:
                    return int(match.group(1))
                except Exception:
                    pass
        return None

    def _extract_transaction_state(lines: list[str]) -> str | None:
        for line in lines:
            match = re.search(r"transaction_state=([a-zA-Z_]+)", line, flags=re.IGNORECASE)
            if match:
                token = str(match.group(1) or "").strip().lower()
                if token:
                    return token
        return None

    def _looks_like_disconnect(lines: list[str]) -> bool:
        markers = ("2013", "2014", "lost connection", "server has gone away", "transientdberror")
        lowered = " ".join(lines).lower()
        return any(marker in lowered for marker in markers)

    def _looks_like_lock_wait(lines: list[str]) -> bool:
        markers = ("1205", "lock wait timeout", "deadlock")
        lowered = " ".join(lines).lower()
        return any(marker in lowered for marker in markers)

    def _classify_missing_run_id(app: object, package: str, package_failures: list[str]) -> str:
        identity_valid = getattr(app, "identity_valid", None)
        if identity_valid is False:
            return "identity_invalid"
        stage_hint = str(getattr(app, "persistence_failure_stage", "") or "").strip().lower()
        if stage_hint:
            if _looks_like_lock_wait(package_failures):
                return "db_lock_wait"
            return "db_write_failed"
        if _looks_like_lock_wait(package_failures):
            return "db_lock_wait"
        if int(getattr(app, "persistence_skipped", 0) or 0) > 0:
            return "persistence_skipped"
        if any("db_write_failed" in line.lower() for line in package_failures):
            return "db_write_failed"
        if any("persist" in line.lower() for line in package_failures):
            return "persist_error"
        if int(getattr(app, "failed_artifacts", 0) or 0) > 0:
            return "artifact_failed"
        if int(getattr(app, "persisted_artifacts", 0) or 0) == 0:
            return "not_persisted"
        return "missing_static_run_id"

    def _extract_stage(classification: str, package_failures: list[str]) -> str:
        for line in package_failures:
            if "db_write_failed:" in line:
                parts = line.split("db_write_failed:", 1)[1].split(":")
                token = (parts[0] if parts else "").strip()
                if token:
                    return token
        if classification in {"db_write_failed", "persist_error"}:
            return "persistence"
        if classification == "identity_invalid":
            return "identity_validation"
        return "unknown"

    rows: list[dict[str, object]] = []
    for app in outcome.results:
        package = str(getattr(app, "package_name", "") or "")
        static_run_id = getattr(app, "static_run_id", None)
        package_failures = _failure_lines_for_package(package)
        classification = "ok"
        if package in missing_set or static_run_id is None:
            classification = _classify_missing_run_id(app, package, package_failures)
        retry_count = int(getattr(app, "persistence_retry_count", 0) or 0)
        if retry_count <= 0:
            retry_count = _extract_retry_count(package_failures)
        errno = _extract_errno(package_failures)
        db_disconnect = bool(getattr(app, "persistence_db_disconnect", False))
        if not db_disconnect:
            db_disconnect = _looks_like_disconnect(package_failures)
        db_lock_wait = _looks_like_lock_wait(package_failures) or errno in {1205, 1213}
        tx_state = getattr(app, "persistence_transaction_state", None)
        if not tx_state:
            tx_state = _extract_transaction_state(package_failures)
        if not tx_state:
            tx_state = "unknown"
        exc_class = getattr(app, "persistence_exception_class", None)
        if not exc_class and db_disconnect:
            exc_class = "TransientDbError"
        stage = getattr(app, "persistence_failure_stage", None) or _extract_stage(
            classification, package_failures
        )
        rows.append(
            {
                "package_name": package,
                "static_run_id": static_run_id,
                "missing_static_run_id": package in missing_set or static_run_id is None,
                "db_disconnect": db_disconnect,
                "db_lock_wait": bool(db_lock_wait),
                "errno": errno,
                "retry_count": retry_count,
                "classification": classification,
                "stage": stage,
                "exception_class": exc_class,
                "transaction_state": tx_state,
                "identity_error_reason": getattr(app, "identity_error_reason", None),
                "persisted_artifacts": int(getattr(app, "persisted_artifacts", 0) or 0),
                "failed_artifacts": int(getattr(app, "failed_artifacts", 0) or 0),
                "persistence_skipped": int(getattr(app, "persistence_skipped", 0) or 0),
            }
        )

    missing_count = len([row for row in rows if row["missing_static_run_id"]])
    artifact_kind = "missing_run_ids" if missing_count else "persistence_audit"
    payload = {
        "schema_version": "v1",
        "db_schema_version": schema_version,
        "artifact_kind": artifact_kind,
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "session_stamp": stamp,
        "total_apps": len(outcome.results),
        "missing_static_run_id_count": missing_count,
        "linkage_blocked_reason": linkage_blocked_reason,
        "rows": rows,
    }

    out_dir = Path("output") / "audit" / "persistence"
    out_dir.mkdir(parents=True, exist_ok=True)
    suffix = "missing_run_ids" if missing_count else "persistence_audit"
    out_path = out_dir / f"{stamp}_{suffix}.json"
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    # This artifact is emitted even on success; it serves as a persistence linkage receipt.
    print(status_messages.status(f"Persistence audit: {out_path}", level="info"))
    _emit_db_lock_health_artifact(
        stamp=stamp,
        rows=rows,
    )


def _emit_db_lock_health_artifact(*, stamp: str, rows: list[dict[str, object]]) -> None:
    # Emit lock-health context when persistence indicates likely DB contention.
    should_emit = any(
        bool(row.get("missing_static_run_id"))
        or bool(row.get("db_lock_wait"))
        or str(row.get("classification") or "") in {"db_lock_wait", "db_write_failed"}
        for row in rows
    )
    if not should_emit:
        return
    snapshot = db_diagnostics.get_lock_health_snapshot(limit=25)
    out_dir = Path("output") / "audit" / "persistence"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{stamp}_db_lock_health.json"
    out_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")
    print(status_messages.status(f"DB lock health: {out_path}", level="info"))


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
        outcome = _launch_scan_flow_resolved(spec.selection, effective_params, spec.base_dir)
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


def _check_static_persistence_readiness(params: RunParameters) -> tuple[bool, str]:
    if params.dry_run:
        return True, "dry-run: persistence gate skipped"
    ok_base, msg_base, detail_base = schema_gate.check_base_schema()
    if not ok_base:
        detail = f" {detail_base}" if detail_base else ""
        return False, f"{msg_base}{detail}"
    ok_static, msg_static, detail_static = schema_gate.static_schema_gate()
    if not ok_static:
        detail = f" {detail_static}" if detail_static else ""
        return False, f"{msg_static}{detail}"
    return True, "OK"


def _resolve_unique_session_stamp(
    session_stamp: str,
    *,
    run_mode: str,
    noninteractive: bool,
    quiet: bool,
    canonical_action: str | None,
) -> tuple[str, str, str]:
    base_stamp = session_stamp
    session_dir = Path(app_config.DATA_DIR) / "sessions"
    final_path = session_dir / base_stamp / "run_map.json"
    attempts = None
    canonical_id = None
    try:
        from scytaledroid.Database.db_core import db_queries as core_q

        row = core_q.run_sql(
            """
            SELECT COUNT(*)
            FROM static_analysis_runs
            WHERE session_label=%s
            """,
            (base_stamp,),
            fetch="one",
        )
        attempts = int(row[0]) if row and row[0] is not None else 0
        row = core_q.run_sql(
            """
            SELECT id
            FROM static_analysis_runs
            WHERE session_label=%s AND is_canonical=1
            ORDER BY canonical_set_at_utc DESC
            LIMIT 1
            """,
            (base_stamp,),
            fetch="one",
        )
        if row and row[0] is not None:
            canonical_id = int(row[0])
    except Exception:
        attempts = None
        canonical_id = None
    # A local run_map may be missing after reset/cleanup while DB attempts still exist.
    # Treat either source as "session already used".
    has_local_session = final_path.exists()
    has_db_attempts = isinstance(attempts, int) and attempts > 0
    if not has_local_session and not has_db_attempts:
        return base_stamp, base_stamp, "first_run"
    batch_mode = (run_mode == "batch")
    if batch_mode or noninteractive:
        suffix = None
        if attempts is not None and attempts >= 0:
            suffix = f"{attempts + 1}"
        if not suffix:
            suffix = datetime.now(UTC).strftime("%H%M%S")
        new_stamp = normalize_session_stamp(f"{base_stamp}-{suffix}")
        return new_stamp, new_stamp, "auto_suffix"
    # Interactive mode must not prompt inside execution. The menu layer should
    # resolve collisions into a canonical_action and/or a unique session_stamp.
    action = (canonical_action or "").strip().lower()
    if action in {"append", "auto_suffix"}:
        suffix = f"{attempts + 1}" if isinstance(attempts, int) else datetime.now(UTC).strftime("%H%M%S")
        new_stamp = normalize_session_stamp(f"{base_stamp}-{suffix}")
        return new_stamp, new_stamp, "append"
    if action == "":
        suffix = f"{attempts + 1}" if isinstance(attempts, int) else datetime.now(UTC).strftime("%H%M%S")
        new_stamp = normalize_session_stamp(f"{base_stamp}-{suffix}")
        if not quiet:
            print(
                status_messages.status(
                    (
                        f"Session label {base_stamp} already exists; "
                        f"auto-suffixing to {new_stamp}."
                    ),
                    level="warn",
                )
            )
        return new_stamp, new_stamp, "auto_suffix"
    if action in {"replace", "overwrite"}:
        try:
            archive_dir = session_dir / "_archive"
            archive_dir.mkdir(parents=True, exist_ok=True)
            if final_path.exists():
                timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
                archive_path = archive_dir / f"{base_stamp}-{timestamp}.run_map.json"
                shutil.copy2(final_path, archive_path)
            if not quiet:
                print(
                    status_messages.status(
                        "Replace mode: deleting local session folder only (DB history preserved).",
                        level="info",
                    )
                )
                if canonical_id:
                    print(
                        status_messages.status(
                            f"Previous canonical attempt: static_run_id={canonical_id}",
                            level="info",
                        )
                    )
            shutil.rmtree(session_dir / base_stamp)
        except Exception as exc:
            raise RuntimeError(f"Failed to replace existing session metadata: {exc}") from exc
        return base_stamp, base_stamp, "replace"
    if action in {"cancel", "abort"}:
        raise RuntimeError(f"Session label already used: {base_stamp}. Cancelled by caller.")
    raise RuntimeError(
        
            f"Session label already used: {base_stamp}. "
            "Resolve this in the menu layer (replace or append) before execution."
        
    )


def _build_session_run_map(
    outcome: RunOutcome | None,
    session_stamp: str | None,
    *,
    allow_overwrite: bool,
) -> dict | None:
    if outcome is None or not session_stamp:
        return None
    results = outcome.results or []
    if not results:
        return None
    duplicates = _detect_duplicate_packages(results)
    if duplicates:
        raise RuntimeError(
            "Duplicate package(s) detected in session; cannot build run map. "
            f"Duplicates: {', '.join(sorted(duplicates))}. "
            "Disambiguate the scope or rerun with a single package per session."
        )
    static_ids = [res.static_run_id for res in results if res.static_run_id]
    origin_map: dict[int, str | None] = {}
    if static_ids:
        try:
            from scytaledroid.Database.db_core import db_queries as core_q

            rows = core_q.run_sql(
                f"SELECT id, session_stamp FROM static_analysis_runs WHERE id IN ({','.join(['%s'] * len(static_ids))})",
                tuple(static_ids),
                fetch="all",
            )
            for row in rows:
                if not row or row[0] is None:
                    continue
                origin_map[int(row[0])] = row[1] if row[1] else None
        except Exception:
            origin_map = {}
    apps = []
    by_package = {}
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    for res in results:
        static_run_id = res.static_run_id
        base_report = res.base_report()
        meta = getattr(base_report, "metadata", {}) if base_report else {}
        if not isinstance(meta, dict):
            meta = {}
        entry = {
            "package": res.package_name,
            "static_run_id": static_run_id,
            "run_origin": None,
            "origin_session_stamp": None,
            "pipeline_version": meta.get("pipeline_version"),
            "base_apk_sha256": meta.get("base_apk_sha256"),
            "artifact_set_hash": meta.get("artifact_set_hash"),
            "run_signature": meta.get("run_signature"),
            "run_signature_version": meta.get("run_signature_version"),
            "identity_valid": meta.get("identity_valid"),
            "identity_error_reason": meta.get("identity_error_reason"),
        }
        if static_run_id:
            origin_session = origin_map.get(static_run_id)
            entry["origin_session_stamp"] = origin_session
            entry["run_origin"] = "created" if origin_session == session_stamp else "reused"
        apps.append(entry)
        by_package[res.package_name] = entry
    run_map = {
        "session_stamp": session_stamp,
        "created_at_utc": now,
        "apps": apps,
        "by_package": by_package,
    }
    _write_run_map_atomic(session_stamp, run_map, allow_overwrite=bool(allow_overwrite))
    return run_map


def _persist_session_run_links(session_stamp: str | None, run_map: dict | None) -> None:
    if not session_stamp or not run_map:
        return
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.Database.db_utils import diagnostics

        columns = diagnostics.get_table_columns("static_session_run_links") or []
        static_ids = sorted(
            {
                int(app.get("static_run_id"))
                for app in run_map.get("apps", [])
                if isinstance(app, dict) and app.get("static_run_id") is not None
            }
        )
        if static_ids:
            rows = core_q.run_sql(
                f"SELECT id FROM static_analysis_runs WHERE id IN ({','.join(['%s'] * len(static_ids))})",
                tuple(static_ids),
                fetch="all",
            )
            existing = {int(row[0]) for row in rows or [] if row and row[0] is not None}
            missing_ids = [sid for sid in static_ids if sid not in existing]
            if missing_ids:
                raise RuntimeError(
                    "static_session_run_links foreign key failure: "
                    f"static_run_id(s) missing from static_analysis_runs: {', '.join(map(str, missing_ids))}"
                )

        now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        insert_columns = ["session_stamp", "package_name", "static_run_id"]
        if "run_origin" in columns:
            insert_columns.append("run_origin")
        if "origin_session_stamp" in columns:
            insert_columns.append("origin_session_stamp")
        if "pipeline_version" in columns:
            insert_columns.append("pipeline_version")
        if "base_apk_sha256" in columns:
            insert_columns.append("base_apk_sha256")
        if "artifact_set_hash" in columns:
            insert_columns.append("artifact_set_hash")
        if "run_signature" in columns:
            insert_columns.append("run_signature")
        if "run_signature_version" in columns:
            insert_columns.append("run_signature_version")
        if "identity_valid" in columns:
            insert_columns.append("identity_valid")
        if "identity_error_reason" in columns:
            insert_columns.append("identity_error_reason")
        if "linked_at_utc" in columns:
            insert_columns.append("linked_at_utc")
        placeholders = ", ".join(["%s"] * len(insert_columns))
        update_clause = ", ".join(
            f"{col}=VALUES({col})" for col in insert_columns if col not in {"session_stamp", "package_name"}
        )
        insert_sql = (
            "INSERT INTO static_session_run_links ("
            + ", ".join(insert_columns)
            + ") VALUES ("
            + placeholders
            + ")"
            + (" ON DUPLICATE KEY UPDATE " + update_clause if update_clause else "")
        )
        failures: list[str] = []
        for app in run_map.get("apps", []):
            if not isinstance(app, dict):
                continue
            package = app.get("package")
            static_run_id = app.get("static_run_id")
            if not package or not static_run_id:
                continue
            origin = app.get("run_origin") or "reused"
            origin_session = app.get("origin_session_stamp")
            pipeline_version = app.get("pipeline_version")
            base_apk_sha256 = app.get("base_apk_sha256")
            artifact_set_hash = app.get("artifact_set_hash")
            run_signature = app.get("run_signature")
            run_signature_version = app.get("run_signature_version")
            identity_valid = app.get("identity_valid")
            identity_error_reason = app.get("identity_error_reason")
            values: list[object] = [session_stamp, package, int(static_run_id)]
            if "run_origin" in columns:
                values.append(origin)
            if "origin_session_stamp" in columns:
                values.append(origin_session)
            if "pipeline_version" in columns:
                values.append(pipeline_version)
            if "base_apk_sha256" in columns:
                values.append(base_apk_sha256)
            if "artifact_set_hash" in columns:
                values.append(artifact_set_hash)
            if "run_signature" in columns:
                values.append(run_signature)
            if "run_signature_version" in columns:
                values.append(run_signature_version)
            if "identity_valid" in columns:
                values.append(1 if identity_valid else 0 if identity_valid is not None else None)
            if "identity_error_reason" in columns:
                values.append(identity_error_reason)
            if "linked_at_utc" in columns:
                values.append(now)
            try:
                core_q.run_sql(insert_sql, tuple(values))
            except Exception as exc:
                failures.append(f"{package} (static_run_id={static_run_id}): {exc}")
                if len(failures) >= 3:
                    break
        if failures:
            raise RuntimeError(
                "static_session_run_links insert failed for "
                f"{len(failures)} row(s). First error: {failures[0]}"
            )
    except Exception as exc:
        print(
            status_messages.status(
                f"Failed to persist static session run links: {exc}", level="warn"
            )
        )


def _detect_duplicate_packages(results: list[AppRunResult]) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for res in results:
        pkg = res.package_name
        if not pkg:
            continue
        if pkg in seen:
            duplicates.add(pkg)
        else:
            seen.add(pkg)
    return duplicates


def _write_run_map_atomic(session_stamp: str, run_map: dict, *, allow_overwrite: bool) -> None:
    session_dir = Path(app_config.DATA_DIR) / "sessions" / session_stamp
    session_dir.mkdir(parents=True, exist_ok=True)
    final_path = session_dir / "run_map.json"
    if final_path.exists():
        if not allow_overwrite:
            raise RuntimeError(
                f"run_map.json already exists for session {session_stamp}; "
                "set SCYTALEDROID_RUN_MAP_OVERWRITE=1 to overwrite."
            )
        print(
            status_messages.status(
                f"Overwriting existing run_map.json for session {session_stamp}.",
                level="warn",
            )
        )
    lock_path = session_dir / ".run_map.lock"
    lock_fd = None
    try:
        lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeError(
            f"run_map.json is locked for session {session_stamp}; another process may be writing it."
        ) from exc
    try:
        tmp_path = session_dir / "run_map.json.tmp"
        payload = json.dumps(run_map, indent=2, sort_keys=True)
        with open(tmp_path, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, final_path)
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
            try:
                os.unlink(lock_path)
            except OSError:
                pass


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
