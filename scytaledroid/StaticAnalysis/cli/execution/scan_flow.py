"""Scan execution helpers for static analysis CLI."""

from __future__ import annotations

import pickle
import time
from collections import Counter, deque
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...core import StaticAnalysisReport
from ...core.repository import load_display_name_map
from ...persistence.reports import StoredReport
from ..core.models import AppRunResult, RunOutcome, RunParameters, ScopeSelection
from ..core.run_context import StaticRunContext
from ..persistence.run_summary import create_static_run_ledger, finalize_open_static_runs
from ..persistence.run_writers import resolve_apk_set_id_for_artifact_set_hash
from ..persistence.static_session_summary import ensure_static_session_shell
from .heartbeat_state import set_app as _hb_set_app
from .heartbeat_state import set_stage as _hb_set_stage
from .operator_display_label import resolve_operator_app_label
from .run_health import compute_app_final_status, compute_run_aggregate_status
from .scan_formatters import (
    _HEARTBEAT_CONTINUATION_INDENT,
    _artifact_label,
    _format_compact_progress_text,
    _load_v3_catalog_label_overrides,
    format_duration,
    format_elapsed_for_progress,
    format_scan_progress_checkpoint_card,
    format_scan_progress_heartbeat_lines,
    format_static_run_final_summary_block,
)
from .scan_identity_helpers import (
    _artifact_manifest_sha256,
    _compute_config_hash,
    _compute_run_identity,
    _dedupe_artifacts,
    _run_signature_sha256,
    select_group_artifacts,
)
from .scan_progress_display import _PipelineProgress
from .scan_report import (
    _append_resource_warning,
    _execute_single_artifact,
    _summarize_app_pipeline,
    build_analysis_config,
    generate_report,
)
from .cohort_scan_notes import emit_post_scan_cohort_notes
from .scan_view import (
    format_recent_completion_line,
    is_compact_card_mode,
    render_app_completion,
    render_app_start,
    render_resource_warnings,
    reset_split_heavy_session_notice,
    show_copy_markers,
)
from .string_analysis_payload import analyse_string_payload

_abort_requested = False
_abort_reason: str | None = None
_abort_signal: str | None = None


def request_abort(reason: str = "SIGINT", signal: str = "SIGINT") -> None:
    global _abort_requested, _abort_reason, _abort_signal
    if _abort_requested:
        return
    _abort_requested = True
    _abort_reason = reason
    _abort_signal = signal


def _abort_state() -> tuple[bool, str | None, str | None]:
    return _abort_requested, _abort_reason, _abort_signal


def _artifact_group_metadata_mapping(group) -> Mapping[str, object]:
    """First deduped artifact metadata mapping for label/version reads."""

    base_artifact = next(iter(_dedupe_artifacts(group.artifacts)), None)
    meta = getattr(base_artifact, "metadata", {}) if base_artifact else {}
    return meta if isinstance(meta, Mapping) else {}


def _harvest_non_canonical_reasons(group) -> tuple[str, ...]:
    reasons = getattr(group, "harvest_non_canonical_reasons", ())
    if isinstance(reasons, tuple):
        return reasons
    if isinstance(reasons, list):
        return tuple(str(reason) for reason in reasons if str(reason).strip())
    return tuple()


def _apply_harvest_contract(app_result: AppRunResult, group) -> tuple[bool, tuple[str, ...]]:
    app_result.harvest_manifest_path = getattr(group, "harvest_manifest_path", None)
    app_result.harvest_capture_status = getattr(group, "harvest_capture_status", None)
    app_result.harvest_persistence_status = getattr(group, "harvest_persistence_status", None)
    app_result.harvest_research_status = getattr(group, "harvest_research_status", None)
    app_result.harvest_matches_planned_artifacts = getattr(group, "harvest_matches_planned_artifacts", None)
    app_result.harvest_observed_hashes_complete = getattr(group, "harvest_observed_hashes_complete", None)
    reasons = _harvest_non_canonical_reasons(group)
    app_result.research_block_reasons = reasons
    app_result.research_usable = not reasons
    app_result.exploratory_only = bool(reasons)
    return bool(app_result.research_usable), reasons


def _remember_runtime_saved_report(
    runtime_state: dict[str, object],
    *,
    package_name: str,
    report: StaticAnalysisReport,
    saved_path: str | None,
) -> None:
    if not saved_path:
        return
    metadata = getattr(report, "metadata", None)
    if not isinstance(metadata, Mapping):
        return
    split_group_id = metadata.get("split_group_id")
    if split_group_id is None:
        return
    capture_id = None
    for key in ("capture_id", "session_stamp"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            capture_id = value.strip()
            break
    if not capture_id:
        return
    package_norm = str(package_name or "").strip().lower()
    if not package_norm:
        return
    split_key = (package_norm, capture_id, str(split_group_id))
    split_reports = runtime_state.setdefault("saved_reports_by_split", {})
    if not isinstance(split_reports, dict):
        return
    split_reports.setdefault(split_key, []).append(
        StoredReport(path=Path(saved_path), report=report)
    )


def execute_scan(
    selection: ScopeSelection,
    params: RunParameters,
    base_dir: Path,
    *,
    run_ctx: StaticRunContext | None = None,
) -> RunOutcome:
    """Execute static analysis across all scoped artifacts."""

    if run_ctx is None:
        # Back-compat fallback (API/server callers). CLI paths should always pass an
        # explicit StaticRunContext to avoid hidden global state in deep layers.
        run_ctx = StaticRunContext(
            run_mode="interactive",
            quiet=False,
            batch=False,
            noninteractive=False,
            show_splits=bool(getattr(params, "show_split_summaries", False)),
            scan_splits_enabled=bool(getattr(params, "scan_splits", True)),
            session_stamp=getattr(params, "session_stamp", None),
            persistence_ready=bool(getattr(params, "persistence_ready", True)),
            paper_grade_requested=bool(getattr(params, "paper_grade_requested", True)),
        )

    global _abort_requested, _abort_reason, _abort_signal
    _abort_requested = False
    _abort_reason = None
    _abort_signal = None
    reset_split_heavy_session_notice()
    scan_splits_enabled = bool(getattr(params, "scan_splits", True))

    started_at = datetime.now(UTC)
    results: list[AppRunResult] = []
    warnings: list[str] = []
    failures: list[str] = []
    dry_run_skipped = 0
    completed_artifacts = 0
    total_artifacts = sum(
        len(select_group_artifacts(group, scan_splits=scan_splits_enabled))
        for group in selection.groups
    )
    artifact_phase_timings: dict[str, float] = {}
    session_parallel_peak_workers = 0
    show_splits = _show_split_breakdown(run_ctx)
    show_artifacts = (not params.dry_run) or bool(params.artifact_detail)
    if run_ctx.quiet and run_ctx.batch:
        show_artifacts = False
    display_name_map = load_display_name_map(selection.groups)
    v3_label_overrides = _load_v3_catalog_label_overrides(selection)
    compact_mode = is_compact_card_mode(params)
    total_apps = len(selection.groups)
    progress = _PipelineProgress(
        total=total_artifacts,
        show_splits=show_splits,
        show_artifacts=show_artifacts,
        show_checkpoints=not params.dry_run and show_artifacts,
        run_ctx=run_ctx,
        progress_every=max(
            int(getattr(params, "progress_every", 5) or 5),
            15 if total_apps >= 50 else 5,
        ),
        show_app_completion=not compact_mode,
    )
    all_apps_compact_mode = compact_mode
    apps_completed = 0
    banner_last_emit = time.monotonic()
    last_activity_pulse = time.monotonic()
    last_report_mono: float | None = None
    last_report_package: str | None = None
    archive_reports_written = 0
    agg_checks: Counter[str] = Counter()
    recent_completions: deque[str] = deque(maxlen=3)
    cached_static_session_id: int | None = None
    if not params.dry_run and bool(getattr(params, "persistence_ready", True)):
        try:
            cached_static_session_id = ensure_static_session_shell(
                session_stamp=params.session_stamp or "",
                scope_label=params.scope_label or selection.label,
                session_label=params.session_label or params.session_stamp or "",
            )
        except Exception:
            cached_static_session_id = None
    compact_session_display = (params.session_label or params.session_stamp or "").strip() or None
    compact_scope_display = f"{params.scope} - {selection.label}"
    config_hash = _compute_config_hash(params)
    pipeline_version = getattr(params, "analysis_version", None)
    persistence_ready = bool(getattr(params, "persistence_ready", True))
    if not persistence_ready and not params.dry_run:
        if bool(getattr(params, "paper_grade_requested", True)):
            raise RuntimeError(
                "Static persistence gate failed; canonical-grade runs require canonical schema readiness."
            )
        log.warning(
            "Static persistence gate failed; running in exploratory mode (no static_run_id, no evidence writes).",
            category="static_analysis",
        )

    # Crash safety: older runs can be left in STARTED state if the process died mid-run.
    # This creates persistent DB noise and breaks canonical-grade audit expectations. We do not
    # support concurrent static scans, so it is safe to finalize any open STARTED rows here.
    if persistence_ready and not params.dry_run:
        try:
            closed = finalize_open_static_runs(
                None,
                status="FAILED",
                abort_reason="stale_open_run_cleanup",
                abort_signal="cleanup",
            )
            if int(closed or 0) > 0:
                print(
                    status_messages.status(
                        f"Static run cleanup: finalized {closed} stale STARTED row(s) as FAILED.",
                        level="warn",
                    )
                )
        except Exception:
            # Cleanup is best-effort; it must not block the scan.
            pass

    last_elapsed_for_progress: float | None = None

    def _eta_snapshot(now_mono: float) -> tuple[str, bool]:
        elapsed = max(0.0, now_mono - progress._start)  # noqa: SLF001
        art_rate = (completed_artifacts / elapsed) if elapsed > 0 and completed_artifacts > 0 else 0.0
        remaining_art = max(0, total_artifacts - completed_artifacts)
        eta_sec = int(round((remaining_art / art_rate), 0)) if art_rate > 0 else -1
        eta_text = format_duration(float(eta_sec)) if eta_sec >= 0 else "--"
        eta_preliminary = bool(
            total_artifacts > 0
            and (completed_artifacts == 0 or (completed_artifacts / total_artifacts) < 0.10)
        )
        return eta_text, eta_preliminary

    if all_apps_compact_mode and total_apps > 0:
        first_pkg = getattr(selection.groups[0], "package_name", None) if selection.groups else None
        first_meta = (
            _artifact_group_metadata_mapping(selection.groups[0]) if selection.groups else {}
        )
        first_disp = (
            resolve_operator_app_label(
                str(first_pkg), first_meta, v3_label_overrides, display_name_map
            )
            if first_pkg
            else None
        )
        startup_card = _format_compact_progress_text(
            apps_completed=0,
            total_apps=total_apps,
            artifacts_done=0,
            total_artifacts=total_artifacts,
            agg_checks=agg_checks,
            elapsed_text=format_elapsed_for_progress(0.0),
            eta_text="--",
            current_app_label=str(first_disp) if first_disp else None,
            current_package_name=str(first_pkg) if first_pkg else None,
            recent_completions=[],
            last_report_seconds_ago=None,
            last_report_package=None,
            archive_reports_written=0,
            eta_preliminary=bool(total_artifacts > 0),
            session_display=compact_session_display,
            profile_display=params.profile_label,
            scope_display=compact_scope_display,
            workers_display=str(params.workers),
            dry_run=bool(params.dry_run),
            include_legend=True,
            include_run_context=False,
            verbose_metrics=bool(getattr(params, "verbose_output", False)),
        )
        print()
        print(startup_card)
        print()
        parts = ["APK reports are per artifact; DB roll-ups are per package."]
        if total_artifacts > 0:
            parts.append("Split APKs advance artifact counts faster than package counts.")
        print(status_messages.status(" ".join(parts), level="info"))
    for app_index, group in enumerate(selection.groups, start=1):
        app_result = AppRunResult(group.package_name, getattr(group, "category", "Uncategorized"))
        harvest_research_usable, harvest_block_reasons = _apply_harvest_contract(app_result, group)
        identity = _compute_run_identity(group)
        planned_artifacts = select_group_artifacts(group, scan_splits=scan_splits_enabled)
        manifest_sha256 = _artifact_manifest_sha256(group, artifacts=planned_artifacts)
        run_signature = _run_signature_sha256(
            identity["base_apk_sha256"],
            identity["artifact_set_hash"],
            config_hash=config_hash,
            profile=params.profile_label,
            pipeline_version=pipeline_version,
            run_signature_version=identity["run_signature_version"],
        )
        base_artifact = next(iter(_dedupe_artifacts(group.artifacts)), None)
        metadata = getattr(base_artifact, "metadata", {}) if base_artifact else {}
        if isinstance(metadata, Mapping):
            version_name = metadata.get("version_name")
            version_code_raw = metadata.get("version_code")
            min_sdk_raw = metadata.get("min_sdk")
            target_sdk_raw = metadata.get("target_sdk")
        else:
            version_name = None
            version_code_raw = None
            min_sdk_raw = None
            target_sdk_raw = None

        meta_map = metadata if isinstance(metadata, Mapping) else {}
        display_name = resolve_operator_app_label(
            group.package_name,
            meta_map,
            v3_label_overrides,
            display_name_map,
        )

        def _coerce_int(value: object) -> int | None:
            try:
                if value is None or value == "":
                    return None
                return int(value)  # type: ignore[arg-type]
            except Exception:
                return None

        app_result.app_label = str(display_name) if display_name else None
        app_result.version_name = str(version_name) if version_name else None
        app_result.version_code = _coerce_int(version_code_raw)
        app_result.min_sdk = _coerce_int(min_sdk_raw)
        app_result.target_sdk = _coerce_int(target_sdk_raw)
        app_result.identity_valid = identity.get("identity_valid")
        app_result.identity_error_reason = identity.get("identity_error_reason")
        app_result.base_apk_sha256 = identity.get("base_apk_sha256")
        app_result.artifact_set_hash = identity.get("artifact_set_hash")
        app_result.apk_set_id = resolve_apk_set_id_for_artifact_set_hash(app_result.artifact_set_hash)
        app_result.run_signature = run_signature
        app_result.run_signature_version = identity.get("run_signature_version")

        static_run_id = None
        if not identity["identity_valid"] and not params.dry_run:
            message = (
                "Run identity invalid; skipping static analysis. "
                f"Package={group.package_name}; reason={identity['identity_error_reason']}"
            )
            failures.append(message)
            log.warning(message, category="static")
            continue
        if harvest_block_reasons:
            reason_text = ",".join(harvest_block_reasons)
            message = (
                "Harvest contract marks package exploratory-only; "
                f"package={group.package_name}; reasons={reason_text}"
            )
            if not params.dry_run and bool(getattr(params, "paper_grade_requested", True)):
                failures.append(message)
                log.warning(message, category="static")
                app_result.final_status = "skipped"
                results.append(app_result)
                continue
            log.warning(message, category="static")
        if not params.dry_run and not persistence_ready:
            app_result.persistence_skipped += 1
        app_result.static_run_id = static_run_id
        results.append(app_result)
        abort_requested, _, _ = _abort_state()
        if abort_requested:
            break

        artifacts = planned_artifacts
        app_result.discovered_artifacts = len(artifacts)
        if not artifacts:
            message = f"No artifacts available for {group.package_name}; skipping."
            failures.append(message)
            log.warning(message, category="static")
            app_result.final_status = "failed"
            continue
        if not params.dry_run and persistence_ready and not app_result.static_run_id:
            try:
                app_result.static_run_id = create_static_run_ledger(
                    package_name=group.package_name,
                    session_stamp=params.session_stamp or "",
                    session_label=params.session_label or params.session_stamp or "",
                    canonical_action=params.canonical_action,
                    scope_label=params.scope_label or selection.label,
                    category=app_result.category,
                    profile=params.profile_label,
                    display_name=app_result.app_label,
                    version_name=app_result.version_name,
                    version_code=app_result.version_code,
                    min_sdk=app_result.min_sdk,
                    target_sdk=app_result.target_sdk,
                    sha256=app_result.base_apk_sha256,
                    base_apk_sha256=app_result.base_apk_sha256,
                    artifact_set_hash=app_result.artifact_set_hash,
                    apk_set_id=app_result.apk_set_id,
                    run_signature=app_result.run_signature,
                    run_signature_version=app_result.run_signature_version,
                    identity_valid=app_result.identity_valid,
                    identity_error_reason=app_result.identity_error_reason,
                    config_hash=getattr(params, "config_hash", None),
                    pipeline_version=getattr(params, "analysis_version", None),
                    analysis_version=getattr(params, "analysis_version", None),
                    catalog_versions=getattr(params, "catalog_versions", None),
                    study_tag=getattr(params, "study_tag", None),
                    static_session_id=cached_static_session_id,
                    run_started_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    dry_run=False,
                )
            except Exception:
                log.warning(
                    f"Failed to create STARTED static_run ledger for {group.package_name}",
                    category="static",
                )
        last_report_for_app: StaticAnalysisReport | None = None
        if display_name or group.package_name:
            progress.flush_line()
            render_app_start(
                title=display_name or group.package_name,
                package_name=group.package_name,
                profile_label=params.profile_label,
                run_ctx=run_ctx,
                card_mode=all_apps_compact_mode,
            )
            # Batch quiet mode suppresses per-artifact streaming. Heartbeat is the operator
            # visibility channel, so update a shared state with the current app context.
            try:
                _hb_set_app(str(display_name or group.package_name), total=len(artifacts))
            except Exception:
                pass
        app_start = time.monotonic()
        app_runtime_state: dict[str, object] = {}
        artifact_extra_meta = {
            "artifact_manifest_sha256": manifest_sha256,
            "config_hash": config_hash,
            "pipeline_version": pipeline_version,
            "base_apk_sha256": identity["base_apk_sha256"],
            "artifact_set_hash": identity["artifact_set_hash"],
            "apk_set_id": app_result.apk_set_id,
            "run_signature": run_signature,
            "run_signature_version": identity["run_signature_version"],
            "identity_valid": identity["identity_valid"],
            "identity_error_reason": identity["identity_error_reason"],
            "harvest_manifest_path": app_result.harvest_manifest_path,
            "harvest_capture_status": app_result.harvest_capture_status,
            "harvest_persistence_status": app_result.harvest_persistence_status,
            "harvest_research_status": app_result.harvest_research_status,
            "harvest_matches_planned_artifacts": app_result.harvest_matches_planned_artifacts,
            "harvest_observed_hashes_complete": app_result.harvest_observed_hashes_complete,
            "research_usable": harvest_research_usable,
            "exploratory_only": bool(harvest_block_reasons),
            "harvest_non_canonical_reasons": list(harvest_block_reasons),
        }
        parallel_precomputed: dict[str, StaticAnalysisReport] = {}
        try:
            from concurrent.futures import ProcessPoolExecutor, as_completed

            from .static_parallel_workers import (
                build_parallel_analyze_blob,
                effective_parallel_artifact_worker_count,
                parallel_static_analyze_worker,
            )

            pw_pkg = effective_parallel_artifact_worker_count(
                resolved_worker_budget=getattr(run_ctx, "resolved_worker_count", None),
                artifact_count=len(artifacts),
            )
            if pw_pkg > 1 and len(artifacts) > 1 and not (run_ctx.quiet and run_ctx.batch):
                jobs: list[tuple[str, bytes]] = []
                for art in artifacts:
                    jobs.append(
                        (
                            str(Path(art.path).resolve()),
                            build_parallel_analyze_blob(
                                art,
                                params,
                                base_dir,
                                extra_metadata=artifact_extra_meta,
                            ),
                        )
                    )
                with ProcessPoolExecutor(max_workers=pw_pkg) as pool:
                    futures = {
                        pool.submit(parallel_static_analyze_worker, blob): rpath
                        for rpath, blob in jobs
                    }
                    for fut in as_completed(futures):
                        rpath = futures[fut]
                        raw = pickle.loads(fut.result())
                        if not raw.get("ok"):
                            raise RuntimeError(str(raw.get("error") or "parallel analyze failed"))
                        parallel_precomputed[rpath] = raw["report"]
                        artifact_phase_timings["analyze_apk_wall_s"] = artifact_phase_timings.get(
                            "analyze_apk_wall_s", 0.0
                        ) + float(raw.get("analyze_wall_s") or 0.0)
                session_parallel_peak_workers = max(session_parallel_peak_workers, pw_pkg)
        except Exception as exc:
            parallel_precomputed.clear()
            log.warning(
                f"Parallel artifact analyze disabled for this package; serial fallback. reason={exc}",
                category="static",
            )
        for artifact_index, artifact in enumerate(artifacts, start=1):
            abort_requested, _, _ = _abort_state()
            if abort_requested:
                break
            artifact_label = _artifact_label(artifact, display_name=display_name)
            progress.start(artifact_index, artifact_label)
            try:
                _hb_set_stage(f"scan:{artifact_label}", done=artifact_index - 1, total=len(artifacts))
            except Exception:
                pass
            try:
                rp_resolved = str(Path(artifact.path).resolve())
                pre_report = parallel_precomputed.get(rp_resolved)
                report, summary, timings, error_message, skipped = _execute_single_artifact(
                    artifact,
                    params,
                    selection,
                    base_dir,
                    extra_metadata=artifact_extra_meta,
                    phase_timing_sink=artifact_phase_timings,
                    runtime_state=app_runtime_state,
                    precomputed_report=pre_report if isinstance(pre_report, StaticAnalysisReport) else None,
                )
            except Exception as exc:
                message = f"Artifact scan failed for {artifact.display_path}: {exc}"
                failures.append(message)
                app_result.failed_artifacts += 1
                completed_artifacts += 1
                app_result.executed_artifacts += 1
                log.warning(message, category="static")
                progress.error(completed_artifacts, artifact_label, str(exc))
                if _abort_state()[0]:
                    break
                continue
            if skipped:
                index_for_progress = completed_artifacts + 1
                if error_message:
                    if error_message == "dry-run (not persisted)":
                        dry_run_skipped += 1
                        app_result.persistence_skipped += 1
                        progress.skip(index_for_progress, artifact_label, error_message)
                    else:
                        app_result.failed_artifacts += 1
                        progress.error(index_for_progress, artifact_label, error_message)
                        failures.append(error_message)
                else:
                    if not params.dry_run:
                        app_result.failed_artifacts += 1
                        failures.append(f"No report generated for {artifact.display_path}")
                completed_artifacts += 1
                app_result.executed_artifacts += 1
                progress.finish(completed_artifacts, artifact_label)
                try:
                    _hb_set_stage(f"scan:{artifact_label}", done=artifact_index, total=len(artifacts))
                except Exception:
                    pass
                if _abort_state()[0]:
                    break
                continue

            if summary is None:
                index_for_progress = completed_artifacts + 1
                if error_message:
                    if error_message == "dry-run (not persisted)":
                        dry_run_skipped += 1
                        app_result.persistence_skipped += 1
                        progress.skip(index_for_progress, artifact_label, error_message)
                    else:
                        app_result.failed_artifacts += 1
                        progress.error(index_for_progress, artifact_label, error_message)
                        failures.append(error_message)
                else:
                    if not params.dry_run:
                        app_result.failed_artifacts += 1
                        failures.append(f"No report generated for {artifact.display_path}")
                completed_artifacts += 1
                app_result.executed_artifacts += 1
                progress.finish(completed_artifacts, artifact_label)
                try:
                    _hb_set_stage(f"scan:{artifact_label}", done=artifact_index, total=len(artifacts))
                except Exception:
                    pass
                if _abort_state()[0]:
                    break
                continue

            app_result.artifacts.append(summary)
            completed_artifacts += 1
            app_result.executed_artifacts += 1
            if summary.saved_path:
                app_result.persisted_artifacts += 1
            elif params.dry_run:
                app_result.persistence_skipped += 1
            warning_lines: list[str] = []
            if report is not None:
                warning_lines = _append_resource_warning(
                    warnings,
                    report,
                    group.package_name,
                    artifact.display_path,
                )
                last_report_for_app = report
                _remember_runtime_saved_report(
                    app_runtime_state,
                    package_name=group.package_name,
                    report=report,
                    saved_path=summary.saved_path,
                )
            if report is not None:
                progress.finish(completed_artifacts, artifact_label)
                try:
                    _hb_set_stage(f"scan:{artifact_label}", done=artifact_index, total=len(artifacts))
                except Exception:
                    pass
                now_mono = time.monotonic()
                last_report_mono = now_mono
                last_report_package = group.package_name
                last_report_app_display = str(display_name or group.package_name or "").strip() or None
                if summary.saved_path:
                    archive_reports_written += 1
                if all_apps_compact_mode and total_artifacts > 0:
                    pulse_iv = 30.0
                    if now_mono - last_activity_pulse >= pulse_iv:
                        eta_pulse, eta_prelim_pulse = _eta_snapshot(now_mono)
                        apps_done_pulse = max(0, app_index - 1)
                        hb1, hb2 = format_scan_progress_heartbeat_lines(
                            apps_completed=apps_done_pulse,
                            total_apps=total_apps,
                            artifacts_done=completed_artifacts,
                            total_artifacts=total_artifacts,
                            current_app_label=str(display_name) if display_name else None,
                            current_package_name=group.package_name,
                            agg_checks=agg_checks,
                            eta_text=eta_pulse,
                            archive_reports_written=archive_reports_written,
                            eta_preliminary=eta_prelim_pulse,
                        )
                        hb_level = "error" if agg_checks.get("error", 0) > 0 else "info"
                        print(status_messages.status(hb1, level=hb_level))
                        print(
                            status_messages.status(
                                _HEARTBEAT_CONTINUATION_INDENT + hb2,
                                level=hb_level,
                                show_icon=False,
                                show_prefix=False,
                            )
                        )
                        last_activity_pulse = now_mono
            if warning_lines:
                progress.flush_line()
                render_resource_warnings(warning_lines, run_ctx=run_ctx)
            if _abort_state()[0]:
                progress.end(last_elapsed_for_progress)
                break
        app_result.duration_seconds = time.monotonic() - app_start
        last_elapsed_for_progress = app_result.duration_seconds
        base_report_for_app = app_result.base_report()
        if base_report_for_app is not None and app_result.base_string_data is None:
            report_metadata = getattr(base_report_for_app, "metadata", None)
            cached_payload = (
                report_metadata.get("post_run_string_payload")
                if isinstance(report_metadata, Mapping)
                else None
            )
            if isinstance(cached_payload, Mapping):
                app_result.base_string_data = cached_payload
            else:
                app_result.base_string_data = analyse_string_payload(
                    base_report_for_app.file_path,
                    params=params,
                    package_name=app_result.package_name,
                    warning_sink=warnings,
                )
        if not _abort_state()[0]:
            progress.flush_line()
            artifact_count = app_result.discovered_artifacts
            app_summary = _summarize_app_pipeline(app_result)
            pe_gate = bool(persistence_ready) and not params.dry_run
            app_result.final_status = compute_app_final_status(
                app_result,
                persistence_enabled=pe_gate,
                persist_attempted_this_run=pe_gate,
            )
            if isinstance(app_summary, dict):
                app_summary["final_app_status"] = app_result.final_status
            metadata = {"pipeline_summary": app_summary} if app_summary else (
                getattr(last_report_for_app, "metadata", {}) if last_report_for_app else None
            )
            render_app_completion(
                artifact_count=artifact_count,
                elapsed_seconds=app_result.duration_seconds or 0.0,
                report_metadata=metadata if isinstance(metadata, Mapping) else None,
                params=params,
                run_ctx=run_ctx,
                app_index=app_index,
                app_total=total_apps,
                app_title=str(display_name) if display_name else group.package_name,
                package_name=group.package_name,
                app_summary=app_summary,
            )
            warn = int(app_summary.get("warn_count", 0) or 0) if app_summary else 0
            last_completion = format_recent_completion_line(
                app_index=app_index,
                app_title=str(display_name) if display_name else group.package_name,
                package_name=group.package_name,
                elapsed_seconds=float(app_result.duration_seconds or 0.0),
                app_summary=app_summary,
            )
            recent_completions.append(last_completion)
            # PM/operator friendly line: one-row completion marker that can be pasted into updates.
            # Keep it stable and low-noise; detailed findings remain in the card output above.
            if all_apps_compact_mode and show_copy_markers(params):
                ok = int(app_summary.get("ok_count", 0) or 0) if app_summary else 0
                err = int(app_summary.get("error_count", 0) or 0) if app_summary else 0
                pf = int(app_summary.get("policy_fail_count", 0) or 0) if app_summary else 0
                ff = int(app_summary.get("finding_fail_count", 0) or 0) if app_summary else 0
                pe = int(app_summary.get("parse_fallback_events_est", 0) or 0) if app_summary else 0
                print(
                    status_messages.status(
                        (
                            "[COPY] static_app_done "
                            f"app_index={app_index} app_total={total_apps} "
                            f"package={group.package_name} "
                            f"label='{(display_name or group.package_name)}' "
                            f"artifacts={artifact_count} "
                            f"time_s={round(float(app_result.duration_seconds or 0.0), 3)} "
                            f"ok={ok} detector_warnings={warn} "
                            f"policy_gate_failures={pf} finding_gate_failures={ff} "
                            f"gate_failures_total={pf + ff} execution_errors={err} "
                            f"parse_signals_est={pe}"
                        ),
                        level="info",
                    )
                )
            progress.app_complete(artifact_count, app_result.duration_seconds or 0.0)
            apps_completed += 1
            if app_summary:
                pf = int(app_summary.get("policy_fail_count", 0) or 0)
                ff = int(app_summary.get("finding_fail_count", 0) or 0)
                agg_checks["ok"] += int(app_summary.get("ok_count", 0) or 0)
                agg_checks["warn"] += int(app_summary.get("warn_count", 0) or 0)
                agg_checks["fail"] += pf + ff
                agg_checks["policy_fail"] += pf
                agg_checks["finding_fail"] += ff
                agg_checks["error"] += int(app_summary.get("error_count", 0) or 0)
                agg_checks["skipped_stages"] += int(app_summary.get("detector_skipped", 0) or 0)
                agg_checks["parse_signals_est"] += int(app_summary.get("parse_fallback_events_est", 0) or 0)
            now = time.monotonic()
            progress_stride = 10
            banner_interval_s = 300.0
            should_emit_banner = (
                apps_completed == total_apps
                or apps_completed % progress_stride == 0
                or (now - banner_last_emit) >= banner_interval_s
            )
            if all_apps_compact_mode and should_emit_banner and total_apps > 0:
                elapsed = max(0.0, now - progress._start)  # noqa: SLF001 - local progress clock reuse
                eta_text, eta_prelim_banner = _eta_snapshot(now)
                next_group = selection.groups[app_index] if app_index < total_apps else None
                next_pkg = getattr(next_group, "package_name", None) if next_group is not None else None
                if next_pkg and next_group is not None:
                    next_meta = _artifact_group_metadata_mapping(next_group)
                    next_label = resolve_operator_app_label(
                        str(next_pkg), next_meta, v3_label_overrides, display_name_map
                    )
                else:
                    next_label = None
                split_note = None
                if bool(getattr(params, "scan_splits", True)) and artifact_count >= 6:
                    split_note = (
                        f"{str(display_name or group.package_name)} has {artifact_count} "
                        "APK artifacts; split scan is on."
                    )
                progress_text = format_scan_progress_checkpoint_card(
                    apps_completed=apps_completed,
                    total_apps=total_apps,
                    artifacts_done=completed_artifacts,
                    total_artifacts=total_artifacts,
                    current_app_label=str(next_label) if next_label else None,
                    current_package_name=str(next_pkg) if next_pkg else None,
                    agg_checks=agg_checks,
                    eta_text=eta_text,
                    archive_reports_written=archive_reports_written,
                    elapsed_text=format_elapsed_for_progress(float(elapsed)),
                    split_heavy_note=split_note,
                    verbose_metrics=bool(getattr(params, "verbose_output", False)),
                    eta_preliminary=eta_prelim_banner,
                )
                print()
                print(progress_text)
                print()
                banner_last_emit = now
                last_activity_pulse = now
            elif all_apps_compact_mode and total_apps > 0 and apps_completed < total_apps:
                eta_text, eta_prelim_hb = _eta_snapshot(now)
                next_group = selection.groups[apps_completed]
                next_pkg = getattr(next_group, "package_name", None)
                if next_pkg:
                    next_meta = _artifact_group_metadata_mapping(next_group)
                    next_label = resolve_operator_app_label(
                        str(next_pkg), next_meta, v3_label_overrides, display_name_map
                    )
                else:
                    next_label = None
                hb_line1, hb_line2 = format_scan_progress_heartbeat_lines(
                    apps_completed=apps_completed,
                    total_apps=total_apps,
                    artifacts_done=completed_artifacts,
                    total_artifacts=total_artifacts,
                    current_app_label=str(next_label) if next_label else None,
                    current_package_name=str(next_pkg) if next_pkg else None,
                    agg_checks=agg_checks,
                    eta_text=eta_text,
                    archive_reports_written=archive_reports_written,
                    eta_preliminary=eta_prelim_hb,
                )
                hb_level2 = "error" if agg_checks.get("error", 0) > 0 else "info"
                print(status_messages.status(hb_line1, level=hb_level2))
                print(
                    status_messages.status(
                        _HEARTBEAT_CONTINUATION_INDENT + hb_line2,
                        level=hb_level2,
                        show_icon=False,
                        show_prefix=False,
                    )
                )
                last_activity_pulse = now
        if _abort_state()[0]:
            break

    progress.end(last_elapsed_for_progress)

    finished_at = datetime.now(UTC)
    abort_requested, abort_reason, abort_signal = _abort_state()
    if params.dry_run:
        failures = []
    pe_gate = bool(persistence_ready) and not params.dry_run
    for pending in results:
        if getattr(pending, "final_status", None):
            continue
        pending.final_status = compute_app_final_status(
            pending,
            persistence_enabled=pe_gate,
            persist_attempted_this_run=pe_gate,
        )
    outcome = RunOutcome(
        results,
        started_at,
        finished_at,
        selection,
        base_dir,
        warnings,
        failures,
        aborted=abort_requested,
        abort_reason=abort_reason,
        abort_signal=abort_signal,
        completed_artifacts=completed_artifacts,
        total_artifacts=total_artifacts,
        dry_run_skipped=dry_run_skipped,
    )
    outcome.session_metrics["artifact_phase_timings_s"] = dict(artifact_phase_timings)
    outcome.session_metrics["resolved_worker_budget"] = getattr(run_ctx, "resolved_worker_count", None)
    outcome.session_metrics["artifact_concurrency_cap"] = max(1, int(session_parallel_peak_workers))
    outcome.run_aggregate_status = compute_run_aggregate_status(outcome)
    emit_post_scan_cohort_notes(outcome, params, run_ctx=run_ctx)
    if all_apps_compact_mode and not (run_ctx.quiet and run_ctx.batch):
        print()
        print(
            format_static_run_final_summary_block(
                outcome,
                session_display=compact_session_display,
                archive_reports_written=archive_reports_written,
                persistence_ready=persistence_ready,
                dry_run=bool(params.dry_run),
                agg_checks=agg_checks,
            )
        )
        print()
    return outcome


def _show_split_breakdown(run_ctx: StaticRunContext) -> bool:
    return bool(run_ctx.show_splits)


__all__ = [
    "execute_scan",
    "generate_report",
    "build_analysis_config",
    "format_duration",
]
