"""Compatibility layer exposing CLI execution helpers."""

from __future__ import annotations

import os
import json
from pathlib import Path
import shutil
import signal
from datetime import datetime, timezone
from dataclasses import replace

from scytaledroid.Config import app_config
from scytaledroid.Utils.DisplayUtils import summary_cards, status_messages
from scytaledroid.Utils.System import output_prefs
from scytaledroid.StaticAnalysis.persistence import ingest as canonical_ingest
from scytaledroid.StaticAnalysis.session import make_session_stamp, normalize_session_stamp
from scytaledroid.ui import formatter
from ..views.view_layouts import render_run_start, render_run_summary
from scytaledroid.Utils.LoggingUtils.logging_context import RunContext, get_run_logger
from scytaledroid.Utils.LoggingUtils import logging_events as log_events

from ..execution import (
    build_analysis_config,
    configure_logging_for_cli,
    execute_permission_scan,
    execute_scan,
    format_duration,
    generate_report,
    request_abort,
    render_run_results,
)
from ..core.models import RunParameters, RunOutcome, ScopeSelection
from ..core.run_lifecycle import finalize_open_runs
from ..core.abort_reasons import classify_exception, normalize_abort_reason
from ..core.analysis_profiles import run_modules_for_profile
from .selection import format_scope_target


def launch_scan_flow(selection: ScopeSelection, params: RunParameters, base_dir: Path) -> RunOutcome | None:
    """Primary entry point for running static analysis flows from the CLI."""

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
    render_run_start(
        run_id=params.session_stamp,
        profile_label=params.profile_label,
        target=scope_target,
        modules=modules,
        workers_desc=workers_label,
        cache_desc="purge" if not params.reuse_cache else "reuse",
        log_level=params.log_level,
        perm_cache_desc="refresh" if params.permission_snapshot_refresh else "skip",
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
        static_logger.info(
            "Static RUN_START",
            extra={
                "event": log_events.RUN_START,
                "run_id": params.session_stamp,
                "target": scope_target,
                "profile": params.profile_label,
                "modules": modules,
                "workers": workers_label,
                "cache": "purge" if not params.reuse_cache else "reuse",
                "perm_cache": "refresh" if params.permission_snapshot_refresh else "skip",
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

    previous_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _handle_sigint)

    if params.profile == "permissions":
        print(status_messages.step("Starting permission analysis workflow", label="Static Analysis"))
        try:
            execute_permission_scan(selection, params)
        finally:
            signal.signal(signal.SIGINT, previous_handler)
        return None

    print("Starting Static Analysis pipeline")
    outcome: RunOutcome | None = None
    run_status: str | None = None
    abort_reason: str | None = None
    abort_signal: str | None = None
    try:
        outcome = execute_scan(selection, params, base_dir)
    finally:
        signal.signal(signal.SIGINT, previous_handler)
    try:
        if outcome is not None:
            setattr(outcome, "session_stamp", params.session_stamp)
    except Exception:
        pass
    try:
        if outcome is not None:
            render_run_results(outcome, params)
            run_status = "COMPLETED"
            if outcome.aborted:
                run_status = "ABORTED"
            elif outcome.failures:
                run_status = "FAILED"
            abort_reason = normalize_abort_reason(outcome.abort_reason or ("SIGINT" if outcome.aborted else None))
            abort_signal = outcome.abort_signal
    except Exception as exc:
        run_status = "FAILED"
        abort_reason = classify_exception(exc)
        raise
    finally:
        if outcome is not None and not params.dry_run and run_status:
            static_run_ids = [
                result.static_run_id
                for result in outcome.results
                if result.static_run_id
            ]
            if static_run_ids:
                ended_at = outcome.finished_at.isoformat(timespec="seconds") + "Z"
                finalize_open_runs(
                    static_run_ids,
                    status=run_status,
                    ended_at_utc=ended_at,
                    abort_reason=normalize_abort_reason(abort_reason),
                    abort_signal=abort_signal,
                )

    # Structured RUN SUMMARY (formatter-based) for transcripts/screenshots.
    if outcome and getattr(outcome, "summary", None):
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
            evidence_root=evidence_root,
        )
        # Structured log for reproducibility (use fresh logger post-configuration)
        try:
            end_payload = {
                "event": log_events.RUN_END,
                "run_id": params.session_stamp,
                "target": scope_target,
                "profile": params.profile_label,
                "detectors": modules,
                "detectors_count": len(modules),
                "findings_total": getattr(summary, "findings_total", 0),
                "severity": sev_counts,
                "failed_masvs": failed_masvs,
                "permissions": perm_stats,
                "evidence_root": evidence_root,
                "status": "ok",
                "duration_seconds": getattr(summary, "duration_seconds", None),
                "applications": getattr(summary, "applications", None),
                "artifacts": getattr(summary, "artifacts", None),
            }
            logger = logging_engine.get_static_logger()
            logger.info("Static RUN_END", extra=logging_engine.ensure_trace(end_payload))
        except Exception:
            pass

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
            run_map = _build_session_run_map(outcome, params.session_stamp)
            if run_map:
                _persist_session_run_links(params.session_stamp, run_map)
            execute_permission_scan(
                selection,
                params,
                persist_detections=False,
                run_map=run_map,
                require_run_map=True,
            )
        except Exception:
            print(
                status_messages.status(
                    "Permission snapshot refresh failed — see logs for details.",
                    level="error",
                )
            )
    elif params.profile in {"full", "lightweight"} and not params.dry_run:
        print()
        print(
            status_messages.status(
                (
                    "Post-run permission refresh skipped. Enable it in Advanced options "
                    "or set SCYTALEDROID_STATIC_REFRESH_PERMISSION_SNAPSHOT=1."
                ),
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


def _build_session_run_map(outcome: RunOutcome | None, session_stamp: str | None) -> dict | None:
    if outcome is None or not session_stamp:
        return None
    results = outcome.results or []
    if not results:
        return None
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
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    for res in results:
        static_run_id = res.static_run_id
        entry = {
            "package": res.package_name,
            "static_run_id": static_run_id,
            "run_origin": None,
            "origin_session_stamp": None,
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
    try:
        session_dir = Path(app_config.DATA_DIR) / "sessions" / session_stamp
        session_dir.mkdir(parents=True, exist_ok=True)
        run_map_path = session_dir / "run_map.json"
        run_map_path.write_text(json.dumps(run_map, indent=2, sort_keys=True), encoding="utf-8")
    except Exception:
        print(status_messages.status("Failed to write session run map file.", level="warn"))
    return run_map


def _persist_session_run_links(session_stamp: str | None, run_map: dict | None) -> None:
    if not session_stamp or not run_map:
        return
    try:
        from scytaledroid.Database.db_core import db_queries as core_q

        row = core_q.run_sql(
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema = DATABASE() AND table_name = %s",
            ("static_session_run_links",),
            fetch="one",
        )
        if not row or int(row[0] or 0) == 0:
            print(status_messages.status("static_session_run_links table missing; skipping linkage.", level="warn"))
            return
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        for app in run_map.get("apps", []):
            if not isinstance(app, dict):
                continue
            package = app.get("package")
            static_run_id = app.get("static_run_id")
            if not package or not static_run_id:
                continue
            origin = app.get("run_origin") or "reused"
            origin_session = app.get("origin_session_stamp")
            core_q.run_sql(
                """
                INSERT INTO static_session_run_links (
                  session_stamp, package_name, static_run_id, run_origin, origin_session_stamp, linked_at_utc
                ) VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                  static_run_id=VALUES(static_run_id),
                  run_origin=VALUES(run_origin),
                  origin_session_stamp=VALUES(origin_session_stamp),
                  linked_at_utc=VALUES(linked_at_utc)
                """,
                (session_stamp, package, int(static_run_id), origin, origin_session, now),
            )
    except Exception:
        print(status_messages.status("Failed to persist static session run links.", level="warn"))


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
