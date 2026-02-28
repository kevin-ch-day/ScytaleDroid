"""Scan execution helpers for static analysis CLI."""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from collections.abc import Mapping, MutableMapping
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import status_messages
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...core import (
    AnalysisConfig,
    SecretsSamplerConfig,
    StaticAnalysisError,
    StaticAnalysisReport,
    analyze_apk,
)
from ...core.findings import SeverityLevel
from ...core.repository import load_display_name_map
from ...modules import resolve_category
from ...persistence import ReportStorageError, save_report
from ..core.models import AppRunResult, ArtifactOutcome, RunOutcome, RunParameters, ScopeSelection
from ..core.run_context import StaticRunContext
from ..persistence.run_summary import finalize_open_static_runs
from .heartbeat_state import set_app as _hb_set_app
from .heartbeat_state import set_stage as _hb_set_stage
from .scan_identity_helpers import (
    _artifact_manifest_sha256,
    _compute_config_hash,
    _compute_run_identity,
    _dedupe_artifacts,
    _run_signature_sha256,
)
from .scan_progress_display import _PipelineProgress
from .scan_view import (
    is_compact_card_mode,
    render_app_completion,
    render_app_start,
    render_resource_warnings,
)

_abort_requested = False
_abort_reason: str | None = None
_abort_signal: str | None = None


def _load_v3_catalog_label_overrides(selection: ScopeSelection) -> dict[str, str]:
    """Return per-package display-name overrides for Profile v3 scans.

    We want cohort-facing labels (from the v3 catalog) to show up in pipeline output,
    even when APK metadata contains a different app label (e.g., Drive vs Docs).
    """
    if selection.scope != "profile":
        return {}
    if not str(selection.label or "").strip().lower().startswith("profile v3"):
        return {}
    catalog_path = Path("profiles") / "profile_v3_app_catalog.json"
    try:
        payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    overrides: dict[str, str] = {}
    for pkg, meta in payload.items():
        if not isinstance(pkg, str) or not pkg.strip():
            continue
        if not isinstance(meta, Mapping):
            continue
        label = meta.get("app")
        if isinstance(label, str) and label.strip():
            overrides[pkg.strip().lower()] = label.strip()
    return overrides


def request_abort(reason: str = "SIGINT", signal: str = "SIGINT") -> None:
    global _abort_requested, _abort_reason, _abort_signal
    if _abort_requested:
        return
    _abort_requested = True
    _abort_reason = reason
    _abort_signal = signal


def _abort_state() -> tuple[bool, str | None, str | None]:
    return _abort_requested, _abort_reason, _abort_signal


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
            session_stamp=getattr(params, "session_stamp", None),
            persistence_ready=bool(getattr(params, "persistence_ready", True)),
            paper_grade_requested=bool(getattr(params, "paper_grade_requested", True)),
        )

    global _abort_requested, _abort_reason, _abort_signal
    _abort_requested = False
    _abort_reason = None
    _abort_signal = None

    started_at = datetime.now(UTC)
    results: list[AppRunResult] = []
    warnings: list[str] = []
    failures: list[str] = []
    dry_run_skipped = 0
    completed_artifacts = 0
    total_artifacts = sum(len(_dedupe_artifacts(group.artifacts)) for group in selection.groups)
    show_splits = _show_split_breakdown(run_ctx)
    show_artifacts = (not params.dry_run) or bool(params.artifact_detail)
    if run_ctx.quiet and run_ctx.batch:
        show_artifacts = False
    display_name_map = load_display_name_map(selection.groups)
    v3_label_overrides = _load_v3_catalog_label_overrides(selection)
    compact_mode = is_compact_card_mode(params)
    progress = _PipelineProgress(
        total=total_artifacts,
        show_splits=show_splits,
        show_artifacts=show_artifacts,
        show_checkpoints=not params.dry_run and show_artifacts,
        run_ctx=run_ctx,
        progress_every=getattr(params, "progress_every", 5),
        show_app_completion=not compact_mode,
    )
    all_apps_compact_mode = compact_mode
    total_apps = len(selection.groups)
    apps_completed = 0
    banner_last_emit = time.monotonic()
    agg_checks: Counter[str] = Counter()
    agg_artifacts_done = 0
    agg_slowest: Counter[str] = Counter()
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
    if all_apps_compact_mode and total_apps > 0:
        print(
            status_messages.status(
                (
                    f"Progress: Apps 0/{total_apps}\n"
                    f"Artifacts 0/{total_artifacts} • ok=0 warn=0 fail=0 error=0\n"
                    "ETA ~ --\n"
                    "Slow avg: --"
                ),
                level="info",
            )
        )
    for app_index, group in enumerate(selection.groups, start=1):
        app_result = AppRunResult(group.package_name, getattr(group, "category", "Uncategorized"))
        identity = _compute_run_identity(group)
        manifest_sha256 = _artifact_manifest_sha256(group)
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
            display_name = metadata.get("app_label") or metadata.get("display_name")
            version_name = metadata.get("version_name")
            version_code_raw = metadata.get("version_code")
            min_sdk_raw = metadata.get("min_sdk")
            target_sdk_raw = metadata.get("target_sdk")
        else:
            display_name = None
            version_name = None
            version_code_raw = None
            min_sdk_raw = None
            target_sdk_raw = None

        override = v3_label_overrides.get(group.package_name.lower())
        if override:
            display_name = override

        if not display_name or str(display_name).strip().lower() == group.package_name.lower():
            display_name = display_name_map.get(group.package_name.lower()) or display_name

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
        if not params.dry_run and not persistence_ready:
            app_result.persistence_skipped += 1
        app_result.static_run_id = static_run_id
        results.append(app_result)
        abort_requested, _, _ = _abort_state()
        if abort_requested:
            break

        artifacts = _dedupe_artifacts(group.artifacts)
        if run_ctx.batch and run_ctx.quiet and not bool(getattr(params, "scan_splits", True)):
            # Batch dataset runs should be predictable and cheap: scan base only.
            base_artifact = getattr(group, "base_artifact", None)
            artifacts = [base_artifact] if base_artifact is not None else artifacts[:1]
        app_result.discovered_artifacts = len(artifacts)
        if not artifacts:
            message = f"No artifacts available for {group.package_name}; skipping."
            failures.append(message)
            log.warning(message, category="static")
            continue
        last_report_for_app: StaticAnalysisReport | None = None
        if display_name or group.package_name:
            progress.flush_line()
            if all_apps_compact_mode:
                # Keep visual separation between app cards in compact batch output.
                print()
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
                report, summary, timings, error_message, skipped = _execute_single_artifact(
                    artifact,
                    params,
                    selection,
                    base_dir,
                    extra_metadata={
                        "artifact_manifest_sha256": manifest_sha256,
                        "config_hash": config_hash,
                        "pipeline_version": pipeline_version,
                        "base_apk_sha256": identity["base_apk_sha256"],
                        "artifact_set_hash": identity["artifact_set_hash"],
                        "run_signature": run_signature,
                        "run_signature_version": identity["run_signature_version"],
                        "identity_valid": identity["identity_valid"],
                        "identity_error_reason": identity["identity_error_reason"],
                    },
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
            if report is not None:
                progress.finish(completed_artifacts, artifact_label)
                try:
                    _hb_set_stage(f"scan:{artifact_label}", done=artifact_index, total=len(artifacts))
                except Exception:
                    pass
            if warning_lines:
                progress.flush_line()
                render_resource_warnings(warning_lines, run_ctx=run_ctx)
            if _abort_state()[0]:
                progress.end(last_elapsed_for_progress)
                break
        app_result.duration_seconds = time.monotonic() - app_start
        last_elapsed_for_progress = app_result.duration_seconds
        if not _abort_state()[0]:
            progress.flush_line()
            artifact_count = app_result.discovered_artifacts
            app_summary = _summarize_app_pipeline(app_result)
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
            # PM/operator friendly line: one-row completion marker that can be pasted into updates.
            # Keep it stable and low-noise; detailed findings remain in the card output above.
            if all_apps_compact_mode:
                ok = int(app_summary.get("ok_count", 0) or 0) if app_summary else 0
                warn = int(app_summary.get("warn_count", 0) or 0) if app_summary else 0
                fail = int(app_summary.get("fail_count", 0) or 0) if app_summary else 0
                err = int(app_summary.get("error_count", 0) or 0) if app_summary else 0
                print(
                    status_messages.status(
                        (
                            "[COPY] static_app_done "
                            f"app_index={app_index} app_total={total_apps} "
                            f"package={group.package_name} "
                            f"label='{(display_name or group.package_name)}' "
                            f"artifacts={artifact_count} "
                            f"time_s={round(float(app_result.duration_seconds or 0.0), 3)} "
                            f"ok={ok} warn={warn} fail={fail} error={err}"
                        ),
                        level="info",
                    )
                )
            progress.app_complete(artifact_count, app_result.duration_seconds or 0.0)
            apps_completed += 1
            agg_artifacts_done += int(app_result.executed_artifacts or 0)
            if app_summary:
                agg_checks["ok"] += int(app_summary.get("ok_count", 0) or 0)
                agg_checks["warn"] += int(app_summary.get("warn_count", 0) or 0)
                agg_checks["fail"] += int(app_summary.get("fail_count", 0) or 0)
                agg_checks["error"] += int(app_summary.get("error_count", 0) or 0)
                slowest = app_summary.get("slowest_detectors")
                if isinstance(slowest, list):
                    for entry in slowest[:1]:
                        if isinstance(entry, Mapping):
                            det = str(entry.get("detector") or entry.get("section") or "").strip()
                            dur = entry.get("duration_sec")
                            if det and isinstance(dur, (int, float)):
                                agg_slowest[det] += float(dur)

            now = time.monotonic()
            should_emit_banner = (
                apps_completed == total_apps
                or apps_completed % 10 == 0
                or (now - banner_last_emit) >= 30.0
            )
            if all_apps_compact_mode and should_emit_banner and total_apps > 0:
                elapsed = max(0.0, now - progress._start)  # noqa: SLF001 - local progress clock reuse
                apps_per_sec = (apps_completed / elapsed) if elapsed > 0 else 0.0
                remaining_apps = max(0, total_apps - apps_completed)
                eta_sec = int(round((remaining_apps / apps_per_sec), 0)) if apps_per_sec > 0 else -1
                eta_text = format_duration(float(eta_sec)) if eta_sec >= 0 else "--"
                slow_label = "--"
                if agg_slowest:
                    det, total_dur = max(agg_slowest.items(), key=lambda kv: kv[1])
                    avg = total_dur / max(1, apps_completed)
                    slow_label = f"{det} {avg:.1f}s"
                progress_text = (
                    f"Progress: Apps {apps_completed}/{total_apps}\n"
                    f"Artifacts {agg_artifacts_done}/{total_artifacts} • "
                    f"ok={agg_checks['ok']} warn={agg_checks['warn']} fail={agg_checks['fail']} error={agg_checks['error']}\n"
                    f"ETA ~ {eta_text}\n"
                    f"Slow avg: {slow_label}"
                )
                print(status_messages.status(progress_text, level="info"))
                banner_last_emit = now
        if _abort_state()[0]:
            break

    progress.end(last_elapsed_for_progress)

    finished_at = datetime.now(UTC)
    abort_requested, abort_reason, abort_signal = _abort_state()
    if params.dry_run:
        failures = []
    return RunOutcome(
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


def _append_resource_warning(
    warnings: list[str],
    report: StaticAnalysisReport,
    package_name: str,
    artifact_label: str,
) -> list[str]:
    metadata = report.metadata
    if not isinstance(metadata, Mapping):
        return []
    fallback = metadata.get("resource_fallback")
    if isinstance(fallback, Mapping) and fallback.get("fallback_used"):
        reason = fallback.get("fallback_reason") or "aapt2"
        warnings.append(
            "Resource fallback used for APK parsing "
            f"(package={package_name}, artifact={artifact_label}, reason={reason})."
        )
    lines = metadata.get("resource_bounds_warnings")
    if not isinstance(lines, list) or not lines:
        return []
    counts: list[int] = []
    for line in lines:
        if not isinstance(line, str):
            continue
        match = re.search(r"Count:\\s*(\\d+)", line)
        if match:
            try:
                counts.append(int(match.group(1)))
            except ValueError:
                continue
    count_hint = f" counts={sorted(set(counts))}" if counts else ""
    warnings.append(
        "Resource table parser emitted bounds warnings "
        f"(package={package_name}, artifact={artifact_label}{count_hint}). "
        "String/resource results may be partial; re-run this APK if needed."
    )
    inline_lines = [
        "Resource table bounds warning (string/resource parsing).",
        f"Package: {package_name}",
    ]
    app_label = metadata.get("app_label")
    if isinstance(app_label, str) and app_label.strip() and app_label.strip() != package_name:
        inline_lines.append(f"App: {app_label.strip()}")
    inline_lines.append(f"Artifact: {artifact_label}")
    if counts:
        inline_lines.append(f"Count values: {', '.join(str(val) for val in sorted(set(counts)))}")
    inline_lines.append("String/resource results may be partial; re-run this APK if needed.")
    return inline_lines


def _summarize_app_pipeline(app_result: AppRunResult) -> dict[str, object]:
    status_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    policy_fail_detectors: list[dict[str, object]] = []
    finding_fail_detectors: list[dict[str, object]] = []
    error_detectors: list[dict[str, object]] = []
    slowest: list[dict[str, object]] = []
    detector_total = 0
    detector_executed = 0
    detector_skipped = 0
    total_duration_sec = 0.0
    for artifact in app_result.artifacts:
        report = artifact.report
        metadata = report.metadata if isinstance(getattr(report, "metadata", None), Mapping) else {}
        summary = metadata.get("pipeline_summary") if isinstance(metadata.get("pipeline_summary"), Mapping) else None
        if not isinstance(summary, Mapping):
            continue
        detector_total += int(summary.get("detector_total", 0) or 0)
        detector_executed += int(summary.get("detector_executed", 0) or 0)
        detector_skipped += int(summary.get("detector_skipped", 0) or 0)
        total_duration_sec += float(summary.get("total_duration_sec", 0.0) or 0.0)
        for key, value in (summary.get("status_counts") or {}).items():
            status_counts[str(key)] += int(value or 0)
        for key, value in (summary.get("severity_counts") or {}).items():
            severity_counts[str(key)] += int(value or 0)
        for key, target in (
            ("policy_fail_detectors", policy_fail_detectors),
            ("finding_fail_detectors", finding_fail_detectors),
            ("error_detectors", error_detectors),
        ):
            payload = summary.get(key)
            if isinstance(payload, list):
                target.extend([row for row in payload if isinstance(row, Mapping)])
        payload = summary.get("slowest_detectors")
        if isinstance(payload, list):
            slowest.extend([row for row in payload if isinstance(row, Mapping)])
    slowest_sorted = sorted(
        slowest,
        key=lambda row: float(row.get("duration_sec", 0.0) or 0.0),
        reverse=True,
    )
    policy_fail_count = len(policy_fail_detectors)
    finding_fail_count = len(finding_fail_detectors)
    return {
        "detector_total": detector_total,
        "detector_executed": detector_executed,
        "detector_skipped": detector_skipped,
        "total_duration_sec": total_duration_sec,
        "status_counts": {k: int(v) for k, v in status_counts.items()},
        "severity_counts": {k: int(v) for k, v in severity_counts.items()},
        "policy_fail_count": policy_fail_count,
        "finding_fail_count": finding_fail_count,
        "error_count": len(error_detectors),
        "policy_fail_detectors": policy_fail_detectors,
        "finding_fail_detectors": finding_fail_detectors,
        "error_detectors": error_detectors,
        "slowest_detectors": slowest_sorted[:3],
        "ok_count": int(status_counts.get("OK", 0)),
        "warn_count": int(status_counts.get("WARN", 0)),
        "fail_count": int(policy_fail_count + finding_fail_count),
    }


def _execute_single_artifact(
    artifact,
    params: RunParameters,
    selection: ScopeSelection,
    base_dir: Path,
    *,
    extra_metadata: Mapping[str, object] | None = None,
):
    report, json_path, error, skipped = generate_report(
        artifact,
        base_dir,
        params,
        extra_metadata=extra_metadata,
    )
    if skipped:
        return None, None, tuple(), error, True

    if error:
        return None, None, tuple(), error, False

    duration = report.metadata.get("duration_seconds", 0.0) if isinstance(report.metadata, Mapping) else 0.0
    timings = tuple(
        (result.detector_id or "detector", float(getattr(result, "duration_sec", 0.0) or 0.0))
        for result in getattr(report, "detector_results", [])
    )
    total_detector_time = sum(value for _, value in timings)
    if (duration or 0.0) <= 0.0 and total_detector_time > 0.0:
        duration = total_detector_time
    summary = _summarize_artifact(artifact, report, json_path, duration)
    return report, summary, timings, None, False


def _show_split_breakdown(run_ctx: StaticRunContext) -> bool:
    return bool(run_ctx.show_splits)




def _artifact_label(artifact, *, display_name: str | None = None) -> str:
    label = getattr(artifact, "artifact_label", None) or getattr(artifact, "display_path", None)
    if isinstance(label, str) and label.strip():
        split_label = label.strip()
    else:
        split_label = "base"

    package = getattr(artifact, "package_name", None)
    app_label = None
    metadata = getattr(artifact, "metadata", None)
    if isinstance(metadata, Mapping):
        app_label = metadata.get("app_label") or metadata.get("display_name")
    display = None
    if isinstance(app_label, str) and app_label.strip():
        display = app_label.strip()
    elif isinstance(display_name, str) and display_name.strip():
        display = display_name.strip()
    elif isinstance(package, str) and package.strip():
        display = package.strip()

    if display:
        return f"{display} • {split_label}"
    return split_label


def _summarize_artifact(artifact, report: StaticAnalysisReport, json_path: Path | None, duration: float) -> ArtifactOutcome:
    severity = Counter[str]()
    for result in report.detector_results:
        for finding in result.findings:
            severity[_severity_token(finding.severity_gate)] += 1

    return ArtifactOutcome(
        label=artifact.artifact_label or artifact.display_path,
        report=report,
        severity=severity,
        duration_seconds=duration,
        saved_path=str(json_path) if json_path else None,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        metadata=artifact.metadata,
    )

def generate_report(
    artifact,
    base_dir: Path,
    params: RunParameters,
    *,
    extra_metadata: Mapping[str, object] | None = None,
):
    metadata_payload: MutableMapping[str, object] = dict(artifact.metadata)
    metadata_payload["run_profile"] = params.profile
    metadata_payload["run_scope"] = params.scope
    metadata_payload["run_scope_label"] = params.scope_label
    metadata_payload["selected_tests"] = list(params.selected_tests)
    if params.session_stamp:
        metadata_payload["session_stamp"] = params.session_stamp
    if not metadata_payload.get("category"):
        package_name = getattr(artifact, "package_name", None)
        if not isinstance(package_name, str) or not package_name.strip():
            package_name = metadata_payload.get("package_name")
        if isinstance(package_name, str) and package_name.strip():
            metadata_payload["category"] = resolve_category(package_name, metadata_payload)
    if extra_metadata:
        metadata_payload.update(
            {
                key: value
                for key, value in extra_metadata.items()
                if value is not None
            }
        )

    # Batch quiet mode is deterministic and low-noise, but we still want meaningful
    # heartbeats. Use the core pipeline stage_observer to expose detector stage progress
    # without printing anything during the scan itself.
    def _stage_observer(evt: object) -> None:
        if not isinstance(evt, dict):
            return
        if evt.get("event") != "stage_start":
            return
        section = str(evt.get("section_key") or evt.get("detector_id") or "unknown")
        idx = evt.get("stage_index")
        total = evt.get("stage_total")
        try:
            _hb_set_stage(
                f"detector:{section}",
                stage_index=int(idx) if isinstance(idx, (int, float, str)) else None,
                stage_total=int(total) if isinstance(total, (int, float, str)) else None,
            )
        except Exception:
            return

    stage_observer = _stage_observer

    try:
        try:
            _hb_set_stage("prepare:analyze_apk")
        except Exception:
            pass
        report = analyze_apk(
            artifact.path,
            metadata=metadata_payload,
            storage_root=base_dir,
            config=build_analysis_config(params),
            stage_observer=stage_observer,
        )
    except StaticAnalysisError as exc:
        try:
            _hb_set_stage("error:analyze_apk")
        except Exception:
            pass
        return None, None, str(exc), True

    if params.dry_run:
        try:
            _hb_set_stage("dry_run:not_persisted")
        except Exception:
            pass
        return report, None, "dry-run (not persisted)", True

    persistence_ready = bool(getattr(params, "persistence_ready", True))
    if not persistence_ready:
        try:
            _hb_set_stage("persist:skipped")
        except Exception:
            pass
        return report, None, None, False

    try:
        try:
            _hb_set_stage("persist:save_report")
        except Exception:
            pass
        saved_paths = save_report(report)
        try:
            _hb_set_stage("persist:done")
        except Exception:
            pass
        return report, saved_paths.json_path, None, False
    except ReportStorageError as exc:
        log.error(str(exc), category="static_analysis")
        try:
            _hb_set_stage("error:persist")
        except Exception:
            pass
        return report, None, str(exc), False


def build_analysis_config(params: RunParameters) -> AnalysisConfig:
    profile_map = {
        "metadata": "quick",
        "permissions": "quick",
        "lightweight": "quick",
        "full": "full",
        "split": "quick",
        "strings": "quick",
        "webview": "quick",
        "nsc": "quick",
        "ipc": "quick",
        "crypto": "quick",
        "sdk": "quick",
    }
    profile = profile_map.get(params.profile, "full")
    enabled_detectors = _map_tests_to_detectors(params)
    enable_string_index = params.profile not in {"metadata", "permissions"}
    if params.profile == "custom" and any(test in params.selected_tests for test in ("secrets", "strings")):
        enable_string_index = True

    sampler = SecretsSamplerConfig(
        entropy_threshold=max(0.0, float(params.secrets_entropy)),
        hits_per_bucket=max(1, int(params.secrets_hits_per_bucket or 1)),
        scope=params.secrets_scope_canonical,
    )

    return AnalysisConfig(
        profile=profile,
        verbosity=params.log_level,
        enabled_detectors=enabled_detectors or None,
        enable_string_index=enable_string_index,
        secrets_sampler=sampler,
    )


def _map_tests_to_detectors(params: RunParameters) -> tuple[str, ...]:
    if params.profile == "metadata":
        return ("integrity_identity",)
    if params.profile == "permissions":
        return ("permissions_profile",)
    if params.profile == "strings":
        return ("secrets", "webview", "network_surface")
    if params.profile == "webview":
        return ("webview_hygiene",)
    if params.profile == "nsc":
        return ("network_surface",)
    if params.profile == "ipc":
        return ("ipc_components", "provider_acl")
    if params.profile == "crypto":
        return ("crypto_hygiene",)
    if params.profile == "sdk":
        return ("sdk_inventory",)
    if params.profile != "custom":
        return tuple()

    mapping = {
        "manifest": ("integrity_identity", "manifest_baseline", "ipc_components", "provider_acl"),
        "provider_acl": ("provider_acl",),
        "nsc": ("network_surface",),
        "webview": ("webview",),
        "secrets": ("secrets",),
    }
    detectors: list[str] = []
    for test_key in params.selected_tests:
        value = mapping.get(test_key)
        if value:
            if isinstance(value, tuple):
                detectors.extend(value)
            else:
                detectors.append(value)
    return tuple(dict.fromkeys(detectors))


def format_duration(seconds: float) -> str:
    if seconds <= 0:
        return "0 ms"
    if seconds < 1:
        millis = max(1, int(round(seconds * 1000)))
        return f"{millis} ms"
    if seconds < 60:
        return f"{seconds:.2f} sec"
    minutes = int(seconds // 60)
    remaining = int(round(seconds - minutes * 60))
    if remaining == 60:
        minutes += 1
        remaining = 0
    if minutes < 60:
        min_label = "min" if minutes == 1 else "mins"
        sec_label = "sec" if remaining == 1 else "secs"
        return f"{minutes} {min_label} {remaining} {sec_label}"
    hours = minutes // 60
    minutes = minutes % 60
    hr_label = "hr" if hours == 1 else "hrs"
    min_label = "min" if minutes == 1 else "mins"
    return f"{hours} {hr_label} {minutes} {min_label}"


def _severity_token(level: SeverityLevel) -> str:
    return {
        SeverityLevel.P0: "H",
        SeverityLevel.P1: "M",
        SeverityLevel.P2: "L",
        SeverityLevel.NOTE: "I",
    }.get(level, "I")


__all__ = [
    "execute_scan",
    "generate_report",
    "build_analysis_config",
    "format_duration",
]
