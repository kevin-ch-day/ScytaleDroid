"""Result rendering helpers for static analysis CLI."""

from __future__ import annotations

from pathlib import Path
import os

from collections import Counter, defaultdict
import math
import statistics
from typing import Mapping, MutableMapping, Sequence, Optional, Dict, Iterable

from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Database.db_core import db_queries as core_q

from scytaledroid.Utils.DisplayUtils import (
    prompt_utils,
    severity,
    status_messages,
    summary_cards,
    table_utils,
    colors,
)

from ...core import StaticAnalysisReport
from ...engine.strings import analyse_strings
from ..core.run_persistence import persist_run_summary, update_static_run_status
from ..core.run_lifecycle import finalize_static_run
from ...persistence.snapshots import SNAPSHOT_PREFIX, write_permission_snapshot
from ..views.run_detail_view import (
    SEVERITY_TOKEN_ORDER,
    app_detail_loop,
    render_app_detail,
)
from ..reports.masvs_summary_report import fetch_db_masvs_summary
from ..core.models import RunOutcome, RunParameters
from ..views.view_renderers import (
    render_app_result,
    write_baseline_json,
    build_dynamic_plan,
    write_dynamic_plan_json,
)
from ...persistence.ingest import ingest_baseline_payload
from .scan_flow import format_duration
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_scripts.static_run_audit import collect_static_run_counts
from scytaledroid.StaticAnalysis.modules.permissions.permission_console_rendering import (
    render_permission_matrix,
    _classify_permissions as _perm_classify,
)
from scytaledroid.StaticAnalysis.modules.permissions.permission_protection_lookup import (
    _fetch_protections as _perm_fetch_protections,
)
from scytaledroid.StaticAnalysis.risk.permission import (
    permission_risk_score_detail,
    permission_risk_grade,
    permission_points_0_20,
)



def _derive_highlight_stats(outcome: RunOutcome) -> dict[str, int]:
    stats = {"providers": 0, "nsc_guard": 0, "secrets_suppressed": 0}
    for app_result in outcome.results:
        base_report = app_result.base_report()
        if base_report is None:
            continue
        try:
            providers = getattr(base_report.exported_components, "providers", ())
            stats["providers"] += len(providers)
        except Exception:
            pass

        metadata = base_report.metadata if isinstance(base_report.metadata, Mapping) else {}
        nsc_payload: Mapping[str, object] | None = None
        if isinstance(metadata, Mapping):
            candidate = metadata.get("network_security_config")
            if isinstance(candidate, Mapping):
                nsc_payload = candidate
            else:
                repro = metadata.get("repro_bundle")
                if isinstance(repro, Mapping):
                    repro_candidate = repro.get("network_security_config")
                    if isinstance(repro_candidate, Mapping):
                        nsc_payload = repro_candidate

        base_flag = base_report.manifest_flags.uses_cleartext_traffic
        if isinstance(nsc_payload, Mapping):
            base_cleartext = nsc_payload.get("base_cleartext")
            domain_policies = nsc_payload.get("domain_policies")
            has_domains = bool(domain_policies)
            if base_cleartext is False or (base_flag is False and not has_domains):
                stats["nsc_guard"] += 1
        elif base_flag is False:
            stats["nsc_guard"] += 1

        for result in getattr(base_report, "detector_results", ()):  # type: ignore[attr-defined]
            if getattr(result, "detector_id", "") == "secrets_credentials":
                metrics = getattr(result, "metrics", {})
                if isinstance(metrics, Mapping):
                    secret_types = metrics.get("secret_types")
                    if isinstance(secret_types, Mapping):
                        for data in secret_types.values():
                            if isinstance(data, Mapping):
                                stats["secrets_suppressed"] += int(data.get("validator_dropped") or 0)
                break
    return stats


def _dedupe_profile_entries(entries: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    deduped: list[dict[str, object]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            deduped.append(entry)
            continue
        key_token = (
            entry.get("package")
            or entry.get("label")
            or entry.get("package_name")
        )
        label = str(key_token or "").strip()
        if not label:
            deduped.append(entry)
            continue
        if label in seen:
            continue
        seen.add(label)
        deduped.append(entry)
    return deduped


def _apply_display_names(entries: Sequence[dict[str, object]]) -> None:
    packages: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        package = str(entry.get("package") or entry.get("package_name") or "").strip()
        if not package:
            continue
        lowered = package.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        packages.append(lowered)

    if not packages:
        return

    placeholders = ", ".join(["%s"] * len(packages))
    try:
        rows = core_q.run_sql(
            f"SELECT package_name, display_name FROM apps WHERE package_name IN ({placeholders})",
            tuple(packages),
            fetch="all",
            dictionary=True,
        )
    except Exception:
        return

    display_map: dict[str, str] = {}
    for row in rows or []:
        pkg = str(row.get("package_name") or "").strip().lower()
        label = str(row.get("display_name") or "").strip()
        if pkg and label:
            display_map[pkg] = label

    if not display_map:
        return

    for entry in entries:
        if not isinstance(entry, MutableMapping):
            continue
        package = str(entry.get("package") or entry.get("package_name") or "").strip()
        if not package:
            continue
        label = display_map.get(package.lower())
        if not label:
            continue
        entry["display_name"] = label
        entry["label"] = label


def _format_highlight_tokens(
    stats: Mapping[str, int], totals: Mapping[str, int], app_count: int
) -> list[str]:
    tokens: list[str] = []
    providers = stats.get("providers", 0)
    if providers:
        tokens.append(
            f"{providers} exported provider{'s' if providers != 1 else ''} lacking strong guards"
        )
    guard = stats.get("nsc_guard", 0)
    if guard:
        tokens.append(
            f"NSC blocks cleartext in {guard}/{app_count} app{'s' if guard != 1 else ''}"
        )
    suppressed = stats.get("secrets_suppressed", 0)
    if suppressed:
        tokens.append(
            f"{suppressed} secret hit{'s' if suppressed != 1 else ''} auto-suppressed"
        )
    if not tokens:
        high = totals.get("high", 0) + totals.get("critical", 0)
        if high:
            tokens.append(
                f"{high} high-severity finding{'s' if high != 1 else ''} require review"
            )
        else:
            tokens.append("No high-severity findings detected")
    return tokens


def _warn_legacy_running_rows() -> None:
    try:
        row = core_q.run_sql(
            """
            SELECT COUNT(*)
            FROM static_analysis_runs
            WHERE status='RUNNING'
              AND ended_at_utc IS NULL
              AND TIMESTAMPDIFF(HOUR, created_at, UTC_TIMESTAMP()) > 24
            """,
            fetch="one",
        )
    except Exception:
        return
    if not row:
        return
    value = row[0] if not isinstance(row, dict) else next(iter(row.values()), 0)
    try:
        count = int(value or 0)
    except (TypeError, ValueError):
        return
    if count <= 0:
        return
    print(
        status_messages.status(
            f"Detected {count} legacy RUNNING rows older than 24h (pre-finalization). No action required.",
            level="warn",
        )
    )


def render_run_results(outcome: RunOutcome, params: RunParameters) -> None:
    """Pretty-print run results and optionally drill into per-app details."""

    aggregated: Counter[str] = Counter()
    artifact_count = 0
    permission_profiles: list[dict[str, object]] = []
    masvs_matrix: dict[str, dict[str, object]] = {}
    static_risk_rows: list[dict[str, object]] = []
    component_profiles: list[dict[str, object]] = []
    secret_profiles: list[dict[str, object]] = []
    finding_profiles: list[dict[str, object]] = []
    trend_deltas: list[dict[str, object]] = []
    for app_result in outcome.results:
        aggregated.update(app_result.severity_totals())
        artifact_count += len(app_result.artifacts)

    permission_profiles = _dedupe_profile_entries(permission_profiles)
    component_profiles = _dedupe_profile_entries(component_profiles)
    secret_profiles = _dedupe_profile_entries(secret_profiles)
    finding_profiles = _dedupe_profile_entries(finding_profiles)
    trend_deltas = _dedupe_profile_entries(trend_deltas)
    static_risk_rows = _dedupe_profile_entries(static_risk_rows)
    _apply_display_names(permission_profiles)

    totals = severity.normalise_counts(aggregated)
    highlight_stats = _derive_highlight_stats(outcome)
    runtime_findings_total = sum(totals.values())
    run_status = "COMPLETED"
    if outcome.aborted:
        run_status = "ABORTED"
    elif outcome.failures:
        run_status = "FAILED"
    ended_at_utc = outcome.finished_at.isoformat(timespec="seconds") + "Z"
    abort_reason = outcome.abort_reason
    abort_signal = outcome.abort_signal
    normalized_findings_total = 0
    baseline_summary_total = 0
    string_samples_persisted_total = 0
    overview_items = [
        summary_cards.summary_item("Duration", format_duration(outcome.duration_seconds), value_style="emphasis"),
        summary_cards.summary_item("Applications", len(outcome.results)),
        summary_cards.summary_item("Artifacts", artifact_count),
        summary_cards.summary_item(
            "Findings (runtime)",
            runtime_findings_total,
            value_style="severity_high" if totals.get("high") or totals.get("critical") else "emphasis",
        ),
    ]
    overview_items.extend(severity.severity_summary_items(totals))
    subtitle_parts = [params.profile_label]
    if params.scope_label:
        subtitle_parts.append(f"Scope: {params.scope_label}")
    if params.session_stamp:
        subtitle_parts.append(f"Session: {params.session_stamp}")
    subtitle = " • ".join(subtitle_parts)
    print(
        summary_cards.format_summary_card(
            "Static analysis summary",
            overview_items,
            subtitle=subtitle,
            footer="Use the prompts below to drill into per-app findings.",
            width=90,
        )
    )
    highlight_tokens = _format_highlight_tokens(
        highlight_stats,
        totals,
        len(outcome.results),
    )
    if highlight_tokens:
        print(status_messages.highlight("; ".join(highlight_tokens), show_icon=True))
    print()

    _warn_legacy_running_rows()

    persistence_errors: list[str] = []
    canonical_failures: list[str] = []
    canonical_skips: list[str] = []
    persist_enabled = not params.dry_run
    # Default to compact output unless the user explicitly asked for verbose.
    compact_mode = not params.verbose_output

    for index, app_result in enumerate(outcome.results, start=1):
        base_report = app_result.base_report()
        if base_report is None:
            warning = f"No report generated for {app_result.package_name}."
            print(status_messages.status(warning, level="warn"))
            if app_result.static_run_id and persist_enabled:
                if outcome.aborted:
                    update_static_run_status(
                        static_run_id=app_result.static_run_id,
                        status="ABORTED",
                        ended_at_utc=ended_at_utc,
                        abort_reason=abort_reason,
                        abort_signal=abort_signal,
                    )
                else:
                    update_static_run_status(
                        static_run_id=app_result.static_run_id,
                        status="FAILED",
                        ended_at_utc=ended_at_utc,
                        abort_reason="missing_report",
                        abort_signal=abort_signal,
                    )
            continue

        string_data = analyse_strings(
            base_report.file_path,
            mode=params.strings_mode,
            min_entropy=params.string_min_entropy,
            max_samples=params.string_max_samples,
            cleartext_only=params.string_cleartext_only,
            include_https_risk=params.string_include_https_risk,
        )
        manifest = base_report.manifest

        permission_profile = _build_permission_profile(base_report, app_result)
        if permission_profile:
            permission_profiles.append(permission_profile)
        component_profiles.append(_collect_component_stats(base_report))
        risk_row = _build_static_risk_row(base_report, string_data, permission_profile, app_result)
        if risk_row:
            static_risk_rows.append(risk_row)
        secret_profiles.append(_collect_secret_stats(string_data, base_report))
        masvs_profile = _collect_masvs_profile(base_report)
        if masvs_profile:
            app_label = manifest.app_label if manifest and manifest.app_label else app_result.package_name
            masvs_profile["label"] = app_label
            masvs_profile["package"] = manifest.package_name if manifest and manifest.package_name else app_result.package_name
            masvs_matrix[app_result.package_name] = masvs_profile
        finding_profiles.append(_collect_finding_signatures(base_report))

        total_duration = sum(artifact.duration_seconds for artifact in app_result.artifacts)
        lines, payload, finding_totals = render_app_result(
            base_report,
            signer=app_result.signer,
            split_count=len(app_result.artifacts),
            string_data=string_data,
            duration_seconds=total_duration,
        )
        trend_delta = _compute_trend_delta(app_result.package_name, params.session_stamp, finding_totals)
        if trend_delta:
            trend_deltas.append(trend_delta)

        if compact_mode:
            if manifest and manifest.app_label:
                display_name = manifest.app_label
            elif manifest and manifest.package_name:
                display_name = manifest.package_name
            else:
                display_name = app_result.package_name
            compact_block = [
                f"• {display_name} (runtime {format_duration(total_duration)})",
                (
                    f"  Findings: H{finding_totals.get('High', 0)} "
                    f"M{finding_totals.get('Medium', 0)} L{finding_totals.get('Low', 0)} "
                    f"I{finding_totals.get('Info', 0)}"
                ),
            ]
            for line in compact_block:
                print(line)

        if persist_enabled:
            try:
                outcome_status = persist_run_summary(
                    base_report,
                    string_data,
                    app_result.package_name,
                    session_stamp=params.session_stamp,
                    scope_label=params.scope_label,
                    finding_totals=finding_totals,
                    baseline_payload=payload,
                    static_run_id=app_result.static_run_id,
                    run_status=run_status,
                    ended_at_utc=ended_at_utc,
                    abort_reason=abort_reason,
                    abort_signal=abort_signal,
                    dry_run=params.dry_run,
                )
                if outcome_status:
                    normalized_findings_total += int(outcome_status.persisted_findings)
                    if outcome_status.baseline_written:
                        baseline_summary_total += 1
                    string_samples_persisted_total += int(outcome_status.string_samples_persisted)
                if outcome_status and not outcome_status.success:
                    persistence_errors.extend(outcome_status.errors)
                    if app_result.static_run_id and persist_enabled:
                        finalize_static_run(
                            static_run_id=app_result.static_run_id,
                            status="FAILED",
                            ended_at_utc=ended_at_utc,
                            abort_reason="persist_error",
                            abort_signal=abort_signal,
                        )
            except Exception as exc:
                warning = (
                    f"Failed to persist run summary for {app_result.package_name}: {exc}"
                )
                print(status_messages.status(warning, level="warn"))
                persistence_errors.append(str(exc))
                if app_result.static_run_id and persist_enabled:
                    fail_status = "ABORTED" if outcome.aborted else "FAILED"
                    finalize_static_run(
                        static_run_id=app_result.static_run_id,
                        status=fail_status,
                        ended_at_utc=ended_at_utc,
                        abort_reason=exc.__class__.__name__,
                        abort_signal=abort_signal,
                    )

            try:
                if outcome.aborted:
                    canonical_skips.append(app_result.package_name)
                else:
                    ingest_payload = _build_ingest_payload(payload, base_report, params)
                    if not ingest_baseline_payload(ingest_payload):
                        canonical_skips.append(app_result.package_name)
                        warning = (
                            f"Canonical ingest skipped or unavailable for {app_result.package_name}."
                        )
                        print(status_messages.status(warning, level="warn"))
            except Exception as exc:
                warning = (
                    f"Failed to ingest baseline snapshot for {app_result.package_name}: {exc}"
                )
                print(status_messages.status(warning, level="warn"))
                persistence_errors.append(str(exc))

        report_reference = None
        base_artifact = app_result.base_artifact_outcome()
        if base_artifact and base_artifact.saved_path:
            try:
                report_reference = f"report://{Path(base_artifact.saved_path).name}"
            except Exception:
                report_reference = None

        if not compact_mode:
            for line in lines:
                print(line)

        saved_path = None
        dynamic_plan_path = None
        if persist_enabled:
            try:
                saved_path = write_baseline_json(
                    payload,
                    package=app_result.package_name,
                    profile=params.profile,
                    scope=params.scope,
                )
            except Exception as exc:
                warning = (
                    f"Failed to write baseline JSON for {app_result.package_name}: {exc}"
                )
                print(status_messages.status(warning, level="warn"))
            try:
                plan_payload = build_dynamic_plan(base_report, payload)
                dynamic_plan_path = write_dynamic_plan_json(
                    plan_payload,
                    package=app_result.package_name,
                    profile=params.profile,
                    scope=params.scope,
                )
            except Exception as exc:
                warning = (
                    f"Failed to write dynamic plan for {app_result.package_name}: {exc}"
                )
                print(status_messages.status(warning, level="warn"))

        if saved_path:
            message = f"Saved baseline JSON → {saved_path.name}"
            if compact_mode:
                print(status_messages.status(message, level="info"))
            else:
                print(message)
        if dynamic_plan_path:
            message = f"Saved dynamic plan → {dynamic_plan_path.name}"
            if compact_mode:
                print(status_messages.status(message, level="info"))
            else:
                print(message)

        if report_reference:
            message = f"Report reference    → {report_reference}"
            if compact_mode:
                print(status_messages.status(message, level="info"))
            else:
                print(message)

        if index < len(outcome.results):
            print()

    if persist_enabled:
        print(
            status_messages.status(
                f"findings (normalized): {normalized_findings_total}",
                level="info",
            )
        )
        print(
            status_messages.status(
                f"static_findings (baseline): {baseline_summary_total}",
                level="info",
            )
        )
        print(
            status_messages.status(
                (
                    "String samples captured (pre-cap): "
                    f"{string_samples_persisted_total} "
                    f"(cap={params.string_max_samples} per bucket; entropy ≥ {params.string_min_entropy:.2f})"
                ),
                level="info",
            )
        )
        if canonical_failures:
            preview_limit = 5
            unique_failures = sorted(set(canonical_failures))
            preview = ", ".join(unique_failures[:preview_limit])
            remaining = len(unique_failures) - preview_limit
            if remaining > 0:
                preview += f", +{remaining} more"
            print(
                status_messages.status(
                    f"Status: WARN – canonical snapshot failed for {len(unique_failures)} package(s): {preview}",
                    level="warn",
                )
            )
        elif canonical_skips:
            reason = "packages=" + ",".join(sorted(set(canonical_skips)))
            if outcome.aborted:
                reason += ";reason=aborted"
            else:
                reason += ";reason=capability_unavailable"
            print(
                status_messages.status(
                    f"Status: OK (with skips) – optional canonical ingest skipped ({reason})",
                    level="info",
                )
            )
        if outcome.aborted:
            print(
                status_messages.status(
                    "Status: ABORTED (SIGINT) — counts may be partial",
                    level="warn",
                )
            )
    else:
        print(
            status_messages.status(
                "findings (normalized) not persisted during dry run.",
                level="info",
            )
        )
    print()

    session_stamp = params.session_stamp
    if outcome.results:
        if canonical_failures:
            unique_failures = sorted(set(canonical_failures))
            preview_limit = 5
            preview = ", ".join(unique_failures[:preview_limit])
            remaining = len(unique_failures) - preview_limit
            if remaining > 0:
                preview += f", +{remaining} more"
            failure_message = (
                "Canonical snapshot failed for "
                f"{len(unique_failures)} package{'s' if len(unique_failures) != 1 else ''}: "
                + preview
            )
            if failure_message not in persistence_errors:
                persistence_errors.append(failure_message)
        printed_db_table = False
        if session_stamp and persist_enabled:
            try:
                static_ids = [res.static_run_id for res in outcome.results if res.static_run_id]
                snapshot_static_id = max(static_ids) if static_ids else None
                if snapshot_static_id is None:
                    try:
                        row = core_q.run_sql(
                            """
                            SELECT id
                            FROM static_analysis_runs
                            WHERE session_stamp=%s
                            ORDER BY id DESC
                            LIMIT 1
                            """,
                            (session_stamp,),
                            fetch="one",
                        )
                        if row and row[0]:
                            snapshot_static_id = int(row[0])
                    except Exception as exc:
                        log.warning(
                            f"Failed to resolve static_run_id for permission snapshot: {exc}",
                            category="static_analysis",
                        )
                if snapshot_static_id is None:
                    warning = "Permission snapshot skipped: static_run_id missing for session."
                    print(status_messages.status(warning, level="warn"))
                    persistence_errors.append(warning)
                else:
                    write_permission_snapshot(
                        session_stamp,
                        scope_label=params.scope_label,
                        static_run_id=snapshot_static_id,
                    )
            except Exception as exc:
                warning = f"Failed to write permission snapshot: {exc}"
                print(status_messages.status(warning, level="warn"))
                persistence_errors.append(str(exc))
            printed_db_table = _render_db_severity_table(session_stamp)
        if not printed_db_table:
            from ..views.run_detail_view import render_app_table  # local import to avoid cycle

            render_app_table(outcome.results)
        if compact_mode:
            print(
                status_messages.status(
                    "Per-app details hidden. Re-run with --verbose-output for full reports.",
                    level="info",
                )
            )
        if session_stamp and persist_enabled:
            _render_persistence_footer(
                session_stamp,
                had_errors=bool(persistence_errors),
                canonical_failures=canonical_failures,
                run_status=run_status,
                abort_reason=abort_reason,
                abort_signal=abort_signal,
            )
            if persistence_errors:
                level = "warn"
                print(status_messages.status("Persistence issues detected:", level=level))
                for message in persistence_errors:
                    print(f"  - {message}")
            if outcome.results:
                _persist_cohort_rollup(session_stamp, params.scope_label)

        _render_post_run_views(
            permission_profiles,
            masvs_matrix,
            static_risk_rows,
            scope_label=params.scope_label,
        )
        if len(outcome.results) > 1:
            _render_cross_app_insights(
                permission_profiles,
                component_profiles,
                masvs_matrix,
                secret_profiles,
                finding_profiles,
                trend_deltas,
                scope_label=params.scope_label,
            )
        if params.verbose_output and len(outcome.results) <= 5:
            _interactive_detail_loop(outcome, params)

    if outcome.aborted:
        completed = outcome.completed_artifacts
        total = outcome.total_artifacts
        completion = f"{completed}/{total}" if total else str(completed)
        reason_token = abort_reason or abort_signal or "SIGINT"
        static_ids = [res.static_run_id for res in outcome.results if res.static_run_id]
        static_hint = f" static_run_id={static_ids[-1]}" if static_ids else ""
        footer = [
            "────────────────────────────────────────────────────────",
            "STATIC ANALYSIS — ABORTED",
            f"Reason : {reason_token} (Ctrl+C)",
            f"Ended  : {ended_at_utc}",
            f"Run    : session={params.session_stamp}{static_hint}",
            f"Scope  : artifacts_completed={completion}",
            "Note   : Partial results may exist. Re-run with a NEW session label.",
            "────────────────────────────────────────────────────────",
        ]
        print("\n".join(footer))

    if outcome.warnings:
        for message in sorted(set(outcome.warnings)):
            print(status_messages.status(message, level="warn"))
    if outcome.failures:
        for message in sorted(set(outcome.failures)):
            print(status_messages.status(message, level="error"))

    if persist_enabled:
        _render_db_masvs_summary()


def _persist_cohort_rollup(session_stamp: str | None, scope_label: str | None) -> None:
    if not session_stamp:
        return
    scope_label = scope_label or ""
    try:
        row = core_q.run_sql(
            """
            SELECT
              COUNT(*) AS total,
              SUM(status='COMPLETED') AS completed,
              SUM(status='FAILED') AS failed,
              SUM(status='ABORTED') AS aborted,
              SUM(status='RUNNING') AS running
            FROM static_analysis_runs
            WHERE session_stamp=%s AND scope_label=%s
            """,
            (session_stamp, scope_label),
            fetch="one",
            dictionary=True,
        )
    except Exception as exc:
        log.warning(
            f"Failed to compute cohort rollup for session={session_stamp}: {exc}",
            category="static_analysis",
        )
        return

    if not row:
        return

    total = int(row.get("total") or 0)
    completed = int(row.get("completed") or 0)
    failed = int(row.get("failed") or 0)
    aborted = int(row.get("aborted") or 0)
    running = int(row.get("running") or 0)
    try:
        core_q.run_sql(
            """
            INSERT INTO static_session_rollups (
              session_stamp, scope_label, apps_total, completed, failed, aborted, running
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
              apps_total=VALUES(apps_total),
              completed=VALUES(completed),
              failed=VALUES(failed),
              aborted=VALUES(aborted),
              running=VALUES(running)
            """,
            (
                session_stamp,
                scope_label,
                total,
                completed,
                failed,
                aborted,
                running,
            ),
        )
    except Exception as exc:
        log.warning(
            f"Failed to persist cohort rollup for session={session_stamp}: {exc}",
            category="static_analysis",
        )
        return

    level = "info" if failed == 0 and aborted == 0 else "warn"
    print(
        status_messages.status(
            f"Apps: {total} | Completed: {completed} | Failed: {failed} | Aborted: {aborted}",
            level=level,
        )
    )


def _build_ingest_payload(
    payload: Mapping[str, object],
    report: StaticAnalysisReport,
    params: RunParameters,
) -> Mapping[str, object]:
    app_section = payload.get("app")
    app_copy: MutableMapping[str, object]
    if isinstance(app_section, Mapping):
        app_copy = dict(app_section)
    else:
        app_copy = {}

    baseline_section = payload.get("baseline")
    baseline_copy: MutableMapping[str, object] = {}
    findings_list: list[Mapping[str, object]] = []
    if isinstance(baseline_section, Mapping):
        baseline_copy.update(baseline_section)
        findings_raw = baseline_section.get("findings")
        if isinstance(findings_raw, Sequence) and not isinstance(
            findings_raw, (str, bytes)
        ):
            findings_list = [
                dict(entry)
                for entry in findings_raw
                if isinstance(entry, Mapping)
            ]

    app_copy.setdefault("package", report.manifest.package_name or app_copy.get("package"))
    if report.manifest.version_name and not app_copy.get("version_name"):
        app_copy["version_name"] = report.manifest.version_name
    if report.manifest.version_code and not app_copy.get("version_code"):
        app_copy["version_code"] = report.manifest.version_code
    if report.manifest.min_sdk and not app_copy.get("min_sdk"):
        app_copy["min_sdk"] = report.manifest.min_sdk
    if report.manifest.target_sdk and not app_copy.get("target_sdk"):
        app_copy["target_sdk"] = report.manifest.target_sdk

    metadata_map: MutableMapping[str, object] = {}
    if isinstance(report.metadata, Mapping):
        metadata_map.update(report.metadata)
    if params.session_stamp and not metadata_map.get("session_stamp"):
        metadata_map["session_stamp"] = params.session_stamp
    if params.scope_label and not metadata_map.get("run_scope_label"):
        metadata_map["run_scope_label"] = params.scope_label
    if params.scope and not metadata_map.get("run_scope"):
        metadata_map["run_scope"] = params.scope
    # Enrich metadata with reproducibility tags when available.
    if not metadata_map.get("pipeline_version"):
        metadata_map["pipeline_version"] = getattr(params, "analysis_version", None) or os.getenv("SCYTALEDROID_PIPELINE_VERSION")
    if not metadata_map.get("catalog_versions"):
        metadata_map["catalog_versions"] = os.getenv("SCYTALEDROID_CATALOG_VERSIONS")
    if not metadata_map.get("config_hash"):
        metadata_map["config_hash"] = os.getenv("SCYTALEDROID_CONFIG_HASH")
    if not metadata_map.get("study_tag"):
        metadata_map["study_tag"] = getattr(params, "study_tag", None) or os.getenv("SCYTALEDROID_STUDY_TAG")
    if payload.get("generated_at") and not metadata_map.get("run_started_utc"):
        metadata_map["run_started_utc"] = payload.get("generated_at")

    ingest_payload: MutableMapping[str, object] = {}
    ingest_payload["generated_at"] = payload.get("generated_at")
    ingest_payload["app"] = app_copy
    ingest_payload["baseline"] = baseline_copy
    ingest_payload["findings"] = findings_list
    ingest_payload["hashes"] = dict(report.hashes)
    ingest_payload["analysis_version"] = report.analysis_version
    ingest_payload["scan_profile"] = params.profile
    ingest_payload["detector_metrics"] = dict(report.detector_metrics)
    ingest_payload["metadata"] = metadata_map
    analytics_section = payload.get("analytics")
    if isinstance(analytics_section, Mapping):
        ingest_payload["analytics"] = dict(analytics_section)

    return ingest_payload


def _interactive_detail_loop(outcome: RunOutcome, params: RunParameters) -> None:
    while True:
        resp = prompt_utils.prompt_text(
            "View details for app # (Enter to skip)", default="", required=False
        ).strip()
        if not resp:
            break
        if not resp.isdigit():
            print(status_messages.status("Invalid selection.", level="warn"))
            continue
        idx = int(resp)
        if idx < 1 or idx > len(outcome.results):
            print(status_messages.status("Selection out of range.", level="warn"))
            continue
        selected = outcome.results[idx - 1]
        app_detail_loop(
            selected,
            params.evidence_lines,
            set(SEVERITY_TOKEN_ORDER),
            params.finding_limit,
            render_app_detail,
        )


def _render_db_masvs_summary() -> None:
    try:
        summary = fetch_db_masvs_summary()
        if not summary:
            return
        run_id, rows = summary
        print()
        print(f"DB MASVS Summary (run_id={run_id})")
        print("Area       High  Med   Low   Info  Status  Worst CVSS                Avg  Bands")
        for area in ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE"):
            entry = next((row for row in rows if row["area"] == area), None)
            if entry is None:
                print(f"{area.title():<9}  0     0     0     0     NO DATA —                        —    —")
            else:
                high = entry.get("high", 0)
                medium = entry.get("medium", 0)
                quality = entry.get("quality") if isinstance(entry, dict) else None
                coverage_status = quality.get("coverage_status") if isinstance(quality, dict) else None
                if coverage_status == "no_data":
                    status = "NO DATA"
                elif high:
                    status = "FAIL"
                elif medium:
                    status = "WARN"
                else:
                    status = "PASS"
                cvss = entry.get("cvss") or {}
                worst_score = cvss.get("worst_score")
                worst_band = cvss.get("worst_severity") or ""
                worst_identifier = cvss.get("worst_identifier") or ""
                if worst_score is None:
                    worst_display = "—"
                else:
                    worst_display = f"{worst_score:.1f} {worst_band} ({worst_identifier})"
                avg_score = cvss.get("average_score")
                avg_display = f"{avg_score:.1f}" if isinstance(avg_score, (int, float)) else "—"
                band_counts = cvss.get("band_counts") or {}
                order = ("Critical", "High", "Medium", "Low", "None")
                band_display_parts = [
                    f"{label[0]}:{int(band_counts[label])}"
                    for label in order
                    if band_counts.get(label)
                ]
                band_display = ", ".join(band_display_parts) if band_display_parts else "—"
                print(
                    f"{area.title():<9}  {high:<5} {medium:<5} {entry['low']:<5} {entry['info']:<6}"
                    f"{status:<6} {worst_display:<24} {avg_display:<4} {band_display}"
                )
    except Exception:
        pass


def _build_permission_profile(report, app_result) -> Optional[dict[str, object]]:
    try:
        declared = list(report.permissions.declared or ())
    except Exception:
        declared = []
    declared_pairs = [(name, "uses-permission") for name in declared]
    try:
        target_sdk = int(report.manifest.target_sdk) if report.manifest.target_sdk else None
    except Exception:
        target_sdk = None
    shorts_only = [
        name.split(".")[-1].upper() for name in declared if isinstance(name, str) and name.startswith("android.")
    ]
    try:
        protection_map = _perm_fetch_protections(shorts_only, target_sdk)
    except Exception:
        protection_map = {}
    try:
        risk_counts, groups, oem_counts, fw_ds, oem_names = _perm_classify(declared_pairs, protection_map)
    except Exception:
        risk_counts, groups, oem_counts, fw_ds, oem_names = ({}, {}, {}, set(), set())

    detector_metrics = getattr(report, "detector_metrics", None)
    permissions_metrics: Mapping[str, object] | None = None
    if isinstance(detector_metrics, Mapping):
        permissions_metrics = detector_metrics.get("permissions_profile")

    profiles_section = {}
    if isinstance(permissions_metrics, Mapping):
        raw_profiles = permissions_metrics.get("permission_profiles")
        if isinstance(raw_profiles, Mapping):
            profiles_section = raw_profiles

    flagged_normals_set: set[str] = set()
    weak_guard_count = 0
    if profiles_section:
        for perm_name, data in profiles_section.items():
            if not isinstance(data, Mapping):
                continue
            if data.get("is_flagged_normal"):
                flagged_normals_set.add(str(perm_name))
            guard_strength = str(data.get("guard_strength") or "").lower()
            if guard_strength in {"weak", "unknown"} and data.get("is_runtime_dangerous"):
                weak_guard_count += 1
    elif isinstance(permissions_metrics, Mapping):
        flagged_list = permissions_metrics.get("flagged_normal_permissions")
        if isinstance(flagged_list, (list, tuple, set)):
            flagged_normals_set.update(str(item) for item in flagged_list)

    flagged_normals = len(flagged_normals_set)

    flags = getattr(report, "manifest_flags", None)
    allow_backup = bool(getattr(flags, "allow_backup", False)) if flags else False
    legacy_storage = bool(getattr(flags, "request_legacy_external_storage", False)) if flags else False

    d = int(risk_counts.get("dangerous", 0))
    s = int(risk_counts.get("signature", 0))
    v = int(oem_counts.get("ADS", 0))

    try:
        detail = permission_risk_score_detail(
            dangerous=d,
            signature=s,
            vendor=v,
            groups=groups,
            target_sdk=target_sdk,
            allow_backup=allow_backup,
            legacy_external_storage=legacy_storage,
            flagged_normals=flagged_normals,
            weak_guards=weak_guard_count,
        )
    except Exception:
        detail = {
            "score_3dp": 0.0,
            "score_capped": 0.0,
            "score_raw": 0.0,
        }
    score = float(detail.get("score_3dp") or detail.get("score_capped") or detail.get("score_raw") or 0.0)
    score = round(score, 3)
    try:
        grade = permission_risk_grade(score)
    except Exception:
        grade = "N/A"

    manifest = getattr(report, "manifest", None)
    package_name = getattr(manifest, "package_name", None) or app_result.package_name
    app_label = getattr(manifest, "app_label", None) if manifest else None
    label = app_label or package_name

    return {
        "package": package_name,
        "label": label,
        "risk": score,
        "grade": grade,
        "D": d,
        "S": s,
        "V": v,
        "O": v,
        "groups": groups,
        "fw_ds": set(fw_ds),
        "vendor_names": set(oem_names),
        "risk_counts": risk_counts,
        "score_detail": detail,
        "flagged_normals": flagged_normals,
        "weak_guard_count": weak_guard_count,
        "flagged_permissions": sorted(flagged_normals_set),
    }


def _collect_masvs_profile(report) -> dict[str, object]:
    severity_map = {"P0": "High", "P1": "Medium", "P2": "Low", "NOTE": "Info"}
    counts: Dict[str, Dict[str, int]] = {area: {"High": 0, "Medium": 0, "Low": 0, "Info": 0} for area in ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")}
    highlights: Dict[str, Counter[str]] = {area: Counter() for area in counts}
    has_values = False
    for result in getattr(report, "detector_results", []) or []:
        for finding in getattr(result, "findings", []) or []:
            area_obj = getattr(finding, "category_masvs", None)
            area_value = None
            if hasattr(area_obj, "value"):
                area_value = getattr(area_obj, "value")
            elif area_obj is not None:
                area_value = str(area_obj)
            if not area_value:
                continue
            area_key = str(area_value).upper()
            if area_key not in counts:
                continue
            sev_gate = getattr(getattr(finding, "severity_gate", None), "value", None)
            severity_label = severity_map.get(str(sev_gate), None)
            if severity_label is None:
                continue
            counts[area_key][severity_label] += 1
            if severity_label in {"High", "Medium"}:
                descriptor = finding.title or finding.finding_id or result.detector_id or "Unknown"
                highlights[area_key][descriptor] += 1
            has_values = True
    if not has_values:
        return {}
    return {
        "counts": counts,
        "highlights": {area: counter for area, counter in highlights.items() if counter},
    }


def _code_http_counts(string_data: Mapping[str, object]) -> tuple[int, int]:
    try:
        samples = string_data.get("samples", {}) if isinstance(string_data, Mapping) else {}
        http_samples = (samples.get("http_cleartext") or []) + (samples.get("endpoints") or [])
        code_hosts: set[str] = set()
        asset_hosts: set[str] = set()
        options = string_data.get("options") if isinstance(string_data, Mapping) else {}
        include_https = False
        if isinstance(options, Mapping):
            include_https = bool(options.get("https_in_risk"))
        for sample in http_samples:
            st = str(sample.get("source_type") or "").lower()
            scheme = str(sample.get("scheme") or "").lower()
            root = str(sample.get("root_domain") or "")
            if scheme not in {"http"} and not (include_https and scheme == "https"):
                continue
            if st in {"code", "dex", "native"}:
                if root:
                    code_hosts.add(root)
            else:
                if root:
                    asset_hosts.add(root)
        return len(code_hosts), len(asset_hosts)
    except Exception:
        return (0, 0)


def _build_static_risk_row(report, string_data: Mapping[str, object], permission_profile: Optional[dict], app_result) -> Optional[dict[str, object]]:
    try:
        total_exports = report.exported_components.total()
    except Exception:
        total_exports = 0
    flags = getattr(report, "manifest_flags", None)
    uses_cleartext = bool(getattr(flags, "uses_cleartext_traffic", False)) if flags else False
    legacy_storage = bool(getattr(flags, "request_legacy_external_storage", False)) if flags else False

    code_http_hosts, _asset_http_hosts = _code_http_counts(string_data)
    has_code_http = code_http_hosts > 0
    try:
        declared = list(report.permissions.declared or ())
    except Exception:
        declared = []

    net_points = 12.0 if (uses_cleartext and has_code_http) else (4.0 if has_code_http else 0.0)
    sto_points = 8.0 if legacy_storage else 0.0
    comp_points = float(min(12, total_exports * 1.5))

    aggregates = string_data.get("aggregates", {}) if isinstance(string_data, Mapping) else {}
    validated = len(aggregates.get("api_keys_high") or [])
    counts_section = string_data.get("counts", {}) if isinstance(string_data, Mapping) else {}
    entropy_hits = int(counts_section.get("high_entropy", 0) or 0) if isinstance(counts_section, Mapping) else 0
    secrets_points = float(min(20, validated * 2)) + (3.0 if entropy_hits >= 10 else (1.5 if entropy_hits else 0.0))
    webssl_points = 0.0
    corr_points = 0.0
    if has_code_http and "android.permission.INTERNET" in declared:
        corr_points += 1.0
    if any(str(name).endswith("READ_CONTACTS") for name in declared) and aggregates.get("endpoint_roots"):
        corr_points += 1.0
    corr_points = min(3.0, corr_points)

    risk_score = float(permission_profile.get("risk", 0.0)) if permission_profile else 0.0
    try:
        perm_points = permission_points_0_20(risk_score) * 0.75
    except Exception:
        perm_points = risk_score * 2
    perm_points = min(15.0, perm_points)
    grade = permission_profile.get("grade") if permission_profile else "N/A"

    total_score = perm_points + net_points + sto_points + comp_points + secrets_points + webssl_points + corr_points
    package = getattr(report.manifest, "package_name", None) or app_result.package_name
    label = permission_profile.get("label") if permission_profile else package

    return {
        "package": package,
        "label": label,
        "permission": round(perm_points, 2),
        "network": round(net_points, 2),
        "storage": round(sto_points, 2),
        "components": round(comp_points, 2),
        "secrets": round(secrets_points, 2),
        "webssl": round(webssl_points, 2),
        "correlation": round(corr_points, 2),
        "total": round(total_score, 2),
        "grade": grade,
    }


def _collect_component_stats(report: StaticAnalysisReport) -> dict[str, object]:
    manifest = getattr(report, "manifest", None)
    app_label = manifest.app_label if manifest and manifest.app_label else manifest.package_name if manifest else "unknown"
    exports = getattr(report, "exported_components", None)
    activities = len(getattr(exports, "activities", []) or []) if exports else 0
    services = len(getattr(exports, "services", []) or []) if exports else 0
    receivers = len(getattr(exports, "receivers", []) or []) if exports else 0
    providers = len(getattr(exports, "providers", []) or []) if exports else 0
    return {
        "package": getattr(manifest, "package_name", None) if manifest else None,
        "label": app_label,
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "providers": providers,
    }


def _collect_secret_stats(string_payload: Mapping[str, object], report: StaticAnalysisReport) -> dict[str, object]:
    counts = string_payload.get("counts", {}) if isinstance(string_payload, Mapping) else {}
    api_keys = int(counts.get("api_keys", 0) or 0)
    high_entropy = int(counts.get("high_entropy", 0) or 0)
    samples = string_payload.get("samples", {}) if isinstance(string_payload, Mapping) else {}
    risk_counter: Counter[str] = Counter()
    for bucket in ("api_keys", "high_entropy"):
        entries = samples.get(bucket) if isinstance(samples, Mapping) else None
        if not isinstance(entries, Sequence):
            continue
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            tag = entry.get("risk_tag") or entry.get("provider") or entry.get("tag")
            if tag:
                risk_counter[str(tag)] += 1
    manifest = getattr(report, "manifest", None)
    app_label = manifest.app_label if manifest and manifest.app_label else manifest.package_name if manifest else "unknown"
    return {
        "package": getattr(manifest, "package_name", None) if manifest else None,
        "label": app_label,
        "api_keys": api_keys,
        "high_entropy": high_entropy,
        "risk_tags": risk_counter,
    }


def _collect_finding_signatures(report: StaticAnalysisReport) -> dict[str, object]:
    counter: Counter[tuple[str, str]] = Counter()
    severity_map = {"P0": "High", "P1": "Medium"}
    for result in getattr(report, "detector_results", []) or []:
        for finding in getattr(result, "findings", []) or []:
            sev = getattr(getattr(finding, "severity_gate", None), "value", None)
            label = severity_map.get(str(sev))
            if not label:
                continue
            descriptor = finding.title or finding.finding_id or result.detector_id or "Unknown"
            counter[(label, descriptor)] += 1
    manifest = getattr(report, "manifest", None)
    app_label = manifest.app_label if manifest and manifest.app_label else manifest.package_name if manifest else "unknown"
    return {
        "package": getattr(manifest, "package_name", None) if manifest else None,
        "label": app_label,
        "counter": counter,
    }


def _compute_trend_delta(package_name: str, session_stamp: str | None, finding_totals: Counter[str]) -> Optional[dict[str, object]]:
    if not session_stamp:
        return None
    try:
        row = core_q.run_sql(
            """
            SELECT session_stamp, high, med, low, info
            FROM static_findings_summary
            WHERE package_name = %s AND session_stamp < %s
            ORDER BY session_stamp DESC
            LIMIT 1
            """,
            (package_name, session_stamp),
            fetch="one",
            dictionary=True,
        )
    except Exception:
        return None
    if not row:
        return None
    try:
        deltas = {
            "delta_high": int(finding_totals.get("High", 0)) - int(row.get("high") or 0),
            "delta_medium": int(finding_totals.get("Medium", 0)) - int(row.get("med") or 0),
            "delta_low": int(finding_totals.get("Low", 0)) - int(row.get("low") or 0),
        }
    except Exception:
        return None
    return {
        "package": package_name,
        "previous_session": row.get("session_stamp"),
        **deltas,
    }


def _render_post_run_views(
    permission_profiles: Sequence[dict[str, object]],
    masvs_matrix: Mapping[str, Mapping[str, object]],
    static_risk_rows: Sequence[dict[str, object]],
    *,
    scope_label: str,
) -> None:
    rendered_any = False
    if permission_profiles:
        limit = min(15, len(permission_profiles))
        try:
            render_permission_matrix(permission_profiles, scope_label=scope_label, show=limit)
            rendered_any = True
        except Exception:
            pass
    if masvs_matrix:
        if _render_masvs_matrix_local(masvs_matrix, limit=15):
            rendered_any = True
    if static_risk_rows:
        if _render_static_risk_table(static_risk_rows, limit=15):
            rendered_any = True
    if rendered_any:
        print()


def _format_masvs_cell(area_counts: Mapping[str, int]) -> str:
    high = int(area_counts.get("High", 0))
    medium = int(area_counts.get("Medium", 0))
    low = int(area_counts.get("Low", 0))
    info = int(area_counts.get("Info", 0))
    if high > 0:
        status = "FAIL"
        palette = colors.style("error")
    elif medium > 0:
        status = "WARN"
        palette = colors.style("warning")
    else:
        status = "PASS"
        palette = colors.style("success")
    summary = f"{status} H{high}/M{medium}"
    if colors.colors_enabled():
        return colors.apply(summary, palette, bold=True)
    return summary


def _render_masvs_matrix_local(
    matrix: Mapping[str, Mapping[str, object]],
    *,
    limit: int = 15,
) -> bool:
    if not matrix:
        return False
    areas = ("NETWORK", "PLATFORM", "PRIVACY", "STORAGE")

    prepared: list[tuple[str, Mapping[str, object] | object]] = []
    for _, entry in matrix.items():
        label = str((entry.get("label") if isinstance(entry, Mapping) else "") or "")
        package = str((entry.get("package") if isinstance(entry, Mapping) else "") or "")
        display = label or package or "—"
        prepared.append((display, entry))

    ordered = sorted(
        prepared,
        key=lambda item: item[0].lower(),
    )[:limit]
    if not ordered:
        return False

    print("\nMASVS Matrix — Current run snapshot")
    headers = ["App", "Network", "Platform", "Privacy", "Storage", "Totals"]
    table_payload: list[list[str]] = []
    for display, entry in ordered:
        counts = entry.get("counts") if isinstance(entry, Mapping) else {}
        if not isinstance(counts, Mapping):
            counts = {}
        row = [display]
        total_high = total_medium = total_low = total_info = 0
        for area in areas:
            area_counts = counts.get(area, {"High": 0, "Medium": 0, "Low": 0, "Info": 0}) if isinstance(counts, Mapping) else {}
            if not isinstance(area_counts, Mapping):
                area_counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
            row.append(_format_masvs_cell(area_counts))
            total_high += int(area_counts.get("High", 0))
            total_medium += int(area_counts.get("Medium", 0))
            total_low += int(area_counts.get("Low", 0))
            total_info += int(area_counts.get("Info", 0))
        totals_text = f"H{total_high} M{total_medium} L{total_low} I{total_info}"
        if colors.colors_enabled():
            if total_high:
                totals_text = colors.apply(totals_text, colors.style("error"), bold=True)
            elif total_medium:
                totals_text = colors.apply(totals_text, colors.style("warning"), bold=True)
        row.append(totals_text)
        table_payload.append(row)
    table_utils.render_table(headers, table_payload)
    return True


def _render_static_risk_table(rows: Sequence[dict[str, object]], *, limit: int = 15) -> bool:
    if not rows:
        return False
    ordered = sorted(
        rows,
        key=lambda item: str(item.get("label") or item.get("package") or "").lower(),
    )[:limit]
    if not ordered:
        return False
    print("\nStatic Risk Scores — Composite buckets")
    headers = [
        "App",
        "Grade",
        "Total",
        "Perm",
        "Network",
        "Storage",
        "Components",
        "Secrets",
        "Web/SSL",
        "Corr",
    ]
    table_rows: list[list[str]] = []
    for entry in ordered:
        label = str(entry.get("label") or entry.get("package") or "—")
        table_rows.append(
            [
                label,
                str(entry.get("grade") or "N/A"),
                f"{float(entry.get('total', 0.0)):.1f}",
                f"{float(entry.get('permission', 0.0)):.1f}",
                f"{float(entry.get('network', 0.0)):.1f}",
                f"{float(entry.get('storage', 0.0)):.1f}",
                f"{float(entry.get('components', 0.0)):.1f}",
                f"{float(entry.get('secrets', 0.0)):.1f}",
                f"{float(entry.get('webssl', 0.0)):.1f}",
                f"{float(entry.get('correlation', 0.0)):.1f}",
            ]
        )
    table_utils.render_table(headers, table_rows)
    return True


def _percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    k = (len(ordered) - 1) * pct
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(ordered[int(k)])
    d0 = ordered[f] * (c - k)
    d1 = ordered[c] * (k - f)
    return float(d0 + d1)


def _render_cross_app_insights(
    permission_profiles: Sequence[dict[str, object]],
    component_profiles: Sequence[dict[str, object]],
    masvs_matrix: Mapping[str, Mapping[str, object]],
    secret_profiles: Sequence[dict[str, object]],
    finding_profiles: Sequence[dict[str, object]],
    trend_deltas: Sequence[dict[str, object]],
    *,
    scope_label: str,
) -> None:
    app_count = len(permission_profiles)
    if app_count < 2:
        return

    print("\nAggregate Insights")
    print("-------------------")

    dangerous_counts = [profile.get("D", 0) for profile in permission_profiles if profile.get("D") is not None]
    signature_counts = [profile.get("S", 0) for profile in permission_profiles if profile.get("S") is not None]
    if dangerous_counts or signature_counts:
        med_d = statistics.median(dangerous_counts) if dangerous_counts else 0
        p90_d = _percentile(dangerous_counts, 0.9) if dangerous_counts else 0
        med_s = statistics.median(signature_counts) if signature_counts else 0
        print(f"• Permissions: median dangerous={med_d:.1f}, 90th percentile dangerous={p90_d:.1f}, median signature={med_s:.1f}")

    if component_profiles:
        component_totals = [stats["activities"] + stats["services"] + stats["receivers"] + stats["providers"] for stats in component_profiles]
        top_components = sorted(component_profiles, key=lambda item: item["activities"] + item["services"] + item["receivers"] + item["providers"], reverse=True)[:5]
        if component_totals:
            med_components = statistics.median(component_totals)
            formatted = ", ".join(
                f"{item['label']} ({item['activities']}/{item['services']}/{item['receivers']}/{item['providers']})"
                for item in top_components
            )
            print(f"• Exported components: median total={med_components:.1f}; top apps: {formatted}")

    if masvs_matrix:
        area_failures: dict[str, int] = defaultdict(int)
        area_top_rules: dict[str, Counter[str]] = defaultdict(Counter)
        for entry in masvs_matrix.values():
            counts = entry.get("counts", {}) if isinstance(entry, Mapping) else {}
            highlights = entry.get("highlights", {}) if isinstance(entry, Mapping) else {}
            for area, stats in counts.items() if isinstance(counts, Mapping) else []:
                high = int(stats.get("High", 0))
                medium = int(stats.get("Medium", 0))
                if high or medium:
                    area_failures[area] += 1
            for area, counter in highlights.items() if isinstance(highlights, Mapping) else []:
                if isinstance(counter, Counter):
                    area_top_rules[area].update(counter)
        if area_failures:
            summary = ", ".join(f"{area.title()} fails={count}" for area, count in sorted(area_failures.items()))
            print(f"• MASVS coverage: {summary}")
            for area, counter in area_top_rules.items():
                most_common = counter.most_common(2)
                if most_common:
                    formatted = ", ".join(f"{name}×{occ}" for name, occ in most_common)
                    print(f"    - {area.title()} top findings: {formatted}")

    if secret_profiles:
        total_api = sum(profile.get("api_keys", 0) for profile in secret_profiles)
        total_entropy = sum(profile.get("high_entropy", 0) for profile in secret_profiles)
        tag_counter: Counter[str] = Counter()
        for profile in secret_profiles:
            tag_counter.update(profile.get("risk_tags", Counter()))
        top_tags = ", ".join(f"{tag}×{count}" for tag, count in tag_counter.most_common(5)) if tag_counter else "none"
        print(f"• Secrets: total API keys={total_api}, high-entropy samples={total_entropy}, top tags: {top_tags}")

    if finding_profiles:
        combined = Counter()
        for profile in finding_profiles:
            combined.update(profile.get("counter", Counter()))
        if combined:
            top_findings = ", ".join(f"{sev} {name}×{count}" for (sev, name), count in combined.most_common(5))
            print(f"• Recurring findings: {top_findings}")

    if trend_deltas:
        changes = [delta for delta in trend_deltas if any(delta.get(key) for key in ("delta_high", "delta_medium", "delta_low"))]
        if changes:
            summary = []
            for delta in changes[:5]:
                parts = []
                for label, key in (("H", "delta_high"), ("M", "delta_medium"), ("L", "delta_low")):
                    value = delta.get(key)
                    if value:
                        parts.append(f"{label}{value:+d}")
                if parts:
                    summary.append(f"{delta['package']} ({', '.join(parts)})")
            if summary:
                print("• Trend vs previous session: " + ", ".join(summary))

    print(f"• Scope reviewed: {scope_label or 'n/a'} across {app_count} apps")


def _table_has_column(table: str, column: str) -> bool:
    try:
        row = core_q.run_sql(
            f"SHOW COLUMNS FROM {table} LIKE %s",
            (column,),
            fetch="one",
        )
    except Exception:
        return False
    return bool(row)


def _resolve_static_run_ids(session_stamp: str) -> list[int]:
    try:
        rows = core_q.run_sql(
            "SELECT id FROM static_analysis_runs WHERE session_stamp=%s",
            (session_stamp,),
            fetch="all",
        )
    except Exception:
        return []
    ids: list[int] = []
    for row in rows or []:
        value = row[0] if not isinstance(row, dict) else next(iter(row.values()), None)
        try:
            if value is not None:
                ids.append(int(value))
        except (TypeError, ValueError):
            continue
    return ids


def _per_app_severity_from_findings(
    static_run_ids: Sequence[int], session_stamp: str | None = None
) -> list[tuple[str, str, int]]:
    if not static_run_ids:
        return []
    has_static = _table_has_column("findings", "static_run_id")
    placeholders = ",".join(["%s"] * len(static_run_ids))
    try:
        if has_static:
            rows = core_q.run_sql(
                f"""
                SELECT a.package_name, f.severity, COUNT(*) as cnt
                FROM findings f
                JOIN static_analysis_runs r ON r.id = f.static_run_id
                JOIN app_versions av ON av.id = r.app_version_id
                JOIN apps a ON a.id = av.app_id
                WHERE f.static_run_id IN ({placeholders})
                GROUP BY a.package_name, f.severity
                ORDER BY a.package_name, f.severity
                """,
                tuple(static_run_ids),
                fetch="all",
            )
        elif session_stamp:
            rows = core_q.run_sql(
                """
                SELECT r.package, f.severity, COUNT(*) as cnt
                FROM findings f
                JOIN runs r ON r.run_id = f.run_id
                WHERE r.session_stamp=%s
                GROUP BY r.package, f.severity
                ORDER BY r.package, f.severity
                """,
                (session_stamp,),
                fetch="all",
            )
        else:
            return []
    except Exception:
        return []

    results: list[tuple[str, str, int]] = []
    for row in rows or []:
        if isinstance(row, dict):
            pkg = row.get("package_name") or row.get("package")
            sev = row.get("severity")
            cnt = row.get("cnt")
        else:
            pkg, sev, cnt = row
        if pkg is None or sev is None:
            continue
        try:
            results.append((str(pkg), str(sev), int(cnt)))
        except (TypeError, ValueError):
            continue
    return results


def _render_db_severity_table(session_stamp: str) -> bool:
    static_run_ids = _resolve_static_run_ids(session_stamp)
    severity_rows = _per_app_severity_from_findings(static_run_ids, session_stamp)
    if not severity_rows:
        return False

    counts: MutableMapping[str, MutableMapping[str, int]] = defaultdict(
        lambda: {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    )
    for pkg, sev, cnt in severity_rows:
        counts[pkg][sev] = cnt

    target_map: Mapping[str, object] = {}
    try:
        target_rows = core_q.run_sql(
            "SELECT package, target_sdk FROM runs WHERE session_stamp=%s",
            (session_stamp,),
            fetch="all",
            dictionary=True,
        )
        target_map = {str(row.get("package")): row.get("target_sdk") for row in target_rows or []}
    except Exception:
        target_map = {}

    table_rows = []
    for idx, pkg in enumerate(sorted(counts.keys()), start=1):
        pkg_counts = counts[pkg]
        target_sdk = target_map.get(pkg, "—")
        try:
            target_sdk = int(target_sdk) if target_sdk not in (None, "") else "—"
        except Exception:
            target_sdk = target_map.get(pkg, "—")
        table_rows.append(
            [
                str(idx),
                pkg,
                str(target_sdk),
                str(int(pkg_counts.get("High", 0))),
                str(int(pkg_counts.get("Medium", 0))),
                str(int(pkg_counts.get("Low", 0))),
                str(int(pkg_counts.get("Info", 0))),
            ]
        )

    print()
    table_utils.render_table(
        ["#", "Package", "targetSdk", "High", "Medium", "Low", "Information"],
        table_rows,
    )
    return True


def _render_persistence_footer(
    session_stamp: str,
    *,
    had_errors: bool = False,
    canonical_failures: Optional[list[str]] = None,
    run_status: str | None = None,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
) -> None:
    try:
        run_rows = core_q.run_sql(
            "SELECT run_id FROM runs WHERE session_stamp = %s",
            (session_stamp,),
            fetch="all",
        ) or []
    except Exception:
        return

    run_ids = sorted(int(row[0]) for row in run_rows if row and row[0] is not None)
    latest_run_ids = run_ids[-1:] if run_ids else []
    static_run_ids = sorted(_resolve_static_run_ids(session_stamp))
    latest_static_run_ids = static_run_ids[-1:] if static_run_ids else []
    audit = collect_static_run_counts(session_stamp=session_stamp) if static_run_ids else None
    audit_counts = audit.counts if audit else {}

    def _count(sql: str, params: tuple[object, ...]) -> int:
        try:
            row = core_q.run_sql(sql, params, fetch="one")
        except Exception:
            return 0
        if not row:
            return 0
        value = row[0] if not isinstance(row, dict) else next(iter(row.values()), 0)
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    def _count_total(sql: str) -> int:
        try:
            row = core_q.run_sql(sql, fetch="one")
        except Exception:
            return 0
        if not row:
            return 0
        value = row[0] if not isinstance(row, dict) else next(iter(row.values()), 0)
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    print()
    header = f"Diagnostics for session {session_stamp}"
    print(header)
    print("=" * len(header))

    snapshot_key = f"{SNAPSHOT_PREFIX}{session_stamp}"
    snapshot_row = core_q.run_sql(
        "SELECT snapshot_id FROM permission_audit_snapshots WHERE snapshot_key=%s",
        (snapshot_key,),
        fetch="one",
    )
    snapshot_id = int(snapshot_row[0]) if snapshot_row and snapshot_row[0] is not None else None

    def _from_audit(table: str) -> Optional[int]:
        if table in audit_counts:
            value, status = audit_counts[table]
            if isinstance(status, str) and status.startswith("SKIP"):
                return None
            try:
                return int(value) if value is not None else 0
            except (TypeError, ValueError):
                return 0
        return None

    def _audit_or(table: str, fallback_sql: str | None = None, params: tuple[object, ...] = ()) -> int:
        value = _from_audit(table)
        if value is not None:
            return value
        if fallback_sql is None:
            return 0
        return _count(fallback_sql, params)

    def _count_by_run(table: str) -> int:
        # Group scopes should aggregate across all static runs; single-app uses the latest run.
        static_ids = static_run_ids if (audit and audit.is_group_scope) else latest_static_run_ids
        if static_ids and _table_has_column(table, "static_run_id"):
            placeholders = ",".join(["%s"] * len(static_ids))
            params = tuple(static_ids)
            return _count(
                f"SELECT COUNT(*) FROM {table} WHERE static_run_id IN ({placeholders})",
                params,
            )
        if latest_run_ids:
            placeholders = ",".join(["%s"] * len(latest_run_ids))
            params = tuple(latest_run_ids)
            return _count(
                f"SELECT COUNT(*) FROM {table} WHERE run_id IN ({placeholders})",
                params,
            )
        return 0

    findings_summary = _audit_or(
        "static_findings_summary",
        "SELECT COUNT(*) FROM static_findings_summary WHERE session_stamp = %s",
        (session_stamp,),
    )
    findings_detail = _audit_or(
        "static_findings",
        """
        SELECT COUNT(*)
        FROM static_findings f
        JOIN static_findings_summary s ON s.id = f.summary_id
        WHERE s.session_stamp = %s
        """,
        (session_stamp,),
    )
    strings_summary = _audit_or(
        "static_string_summary",
        "SELECT COUNT(*) FROM static_string_summary WHERE session_stamp = %s",
        (session_stamp,),
    )
    string_samples_raw = _audit_or(
        "static_string_samples",
        """
        SELECT COUNT(*)
        FROM static_string_samples x
        JOIN static_findings_summary s ON s.id = x.summary_id
        WHERE s.session_stamp = %s
        """,
        (session_stamp,),
    )

    buckets = _audit_or("buckets") or _count_by_run("buckets")
    metrics = _audit_or("metrics") or _count_by_run("metrics")
    findings = _audit_or("findings") or _count_by_run("findings")

    contributors = 0
    if run_ids:
        placeholders = ",".join(["%s"] * len(run_ids))
        params = tuple(run_ids)
        contributors = _count(
            f"SELECT COUNT(*) FROM contributors WHERE run_id IN ({placeholders})",
            params,
        )

    snapshot_count = _audit_or(
        "permission_audit_snapshots",
        "SELECT COUNT(*) FROM permission_audit_snapshots WHERE snapshot_key = %s",
        (snapshot_key,),
    )
    snapshot_apps = _audit_or("permission_audit_apps")
    if snapshot_apps == 0 and snapshot_id is not None:
        snapshot_apps = _count(
            "SELECT COUNT(*) FROM permission_audit_apps WHERE snapshot_id = %s",
            (snapshot_id,),
        )

    runs_total = _count_total("SELECT COUNT(*) FROM runs")
    buckets_total = _count_total("SELECT COUNT(*) FROM buckets")
    metrics_total = _count_total("SELECT COUNT(*) FROM metrics")
    findings_total = _count_total("SELECT COUNT(*) FROM findings")
    contributors_total = _count_total("SELECT COUNT(*) FROM contributors")
    strings_summary_total = _count_total("SELECT COUNT(*) FROM static_string_summary")
    string_samples_raw_total = _count_total("SELECT COUNT(*) FROM static_string_samples")
    findings_summary_total = _count_total("SELECT COUNT(*) FROM static_findings_summary")
    findings_detail_total = _count_total("SELECT COUNT(*) FROM static_findings")
    snapshot_total = _count_total("SELECT COUNT(*) FROM permission_audit_snapshots")
    snapshot_apps_total = _count_total("SELECT COUNT(*) FROM permission_audit_apps")

    def _governance_status() -> str | None:
        try:
            row = core_q.run_sql(
                """
                SELECT s.governance_version, s.snapshot_sha256, COUNT(r.permission_string) AS row_count
                FROM permission_governance_snapshots s
                LEFT JOIN permission_governance_snapshot_rows r
                  ON r.governance_version = s.governance_version
                GROUP BY s.governance_version, s.snapshot_sha256
                ORDER BY s.loaded_at_utc DESC
                LIMIT 1
                """,
                fetch="one",
            )
            if row and row[0] and int(row[2] or 0) > 0:
                return f"OK ({row[0]})"
            rows_only = core_q.run_sql(
                "SELECT COUNT(*) FROM permission_governance_snapshot_rows",
                fetch="one",
            )
            if rows_only and int(rows_only[0] or 0) > 0:
                return "ERROR (governance rows missing header)"
            return "SKIPPED_GOVERNANCE_MISSING"
        except Exception:
            return None

    print("Persisted (authoritative)")
    print("------------------------")
    if audit and audit.is_group_scope:
        scope_note = f"run_id={len(run_ids)} static_run_id={len(static_run_ids)}"
    else:
        scope_note = "run_id=" + ",".join(str(r) for r in latest_run_ids) if latest_run_ids else "run_id=<none>"
        if latest_static_run_ids:
            scope_note += f" static_run_id=" + ",".join(str(r) for r in latest_static_run_ids)
    run_count = len(run_ids) if (audit and audit.is_group_scope) else len(latest_run_ids)
    lines = [
        ("run_scope", scope_note),
        ("runs", f"this_run={run_count}  db_total={runs_total}"),
        ("findings", f"this_run={findings}  db_total={findings_total}"),
        (
            "static_findings_summary",
            f"this_run={findings_summary}  db_total={findings_summary_total}",
        ),
        (
            "static_findings",
            f"this_run={findings_detail}  db_total={findings_detail_total}",
        ),
        (
            "static_string_summary",
            f"this_run={strings_summary}  db_total={strings_summary_total}",
        ),
        (
            "static_string_samples",
            f"this_run={string_samples_raw}  db_total={string_samples_raw_total}",
        ),
        ("buckets", f"this_run={buckets}  db_total={buckets_total}"),
        ("metrics", f"this_run={metrics}  db_total={metrics_total}"),
        (
            "permission_audit_snapshots",
            f"this_run={snapshot_count}  db_total={snapshot_total}",
        ),
        (
            "permission_audit_apps",
            f"this_run={snapshot_apps}  db_total={snapshot_apps_total}",
        ),
    ]
    governance_status = _governance_status()
    if governance_status:
        lines.append(("governance", governance_status))
    if audit and audit.is_group_scope:
        lines.append(
            (
                "scope_note",
                "Group scope detected; per-package mapping not applicable.",
            )
        )
    if audit and audit.run_id is None:
        if audit.is_group_scope:
            lines.append(("run_linkage", "Group scope (run_id not required)"))
        elif audit.is_orphan:
            lines.append(("run_linkage", "ORPHAN (run_id missing)"))
        elif audit.is_legacy:
            lines.append(("run_linkage", "LEGACY (run_id missing)"))
        else:
            lines.append(("run_linkage", "run_id missing"))
    if run_status == "ABORTED":
        reason_token = abort_reason or abort_signal or "SIGINT"
        lines.append(("abort_reason", reason_token))
    if len(run_ids) > 1 or len(static_run_ids) > 1:
        note = "Multiple runs for session; this_run aggregates group scope." if audit and audit.is_group_scope else "Multiple runs for session; this_run reflects latest run only."
        lines.append(("note", note))
    width = max(len(name) for name, _ in lines) if lines else 0
    for name, detail in lines:
        print(f"  {name.ljust(width)} : {detail}")

    stale_runs = _count_total(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status='RUNNING'
          AND TIMESTAMPDIFF(HOUR, created_at, UTC_TIMESTAMP()) > 24
        """
    )
    if stale_runs:
        print(
            status_messages.status(
                f"Legacy RUNNING rows >24h: {stale_runs} (pre-Phase-B legacy run)",
                level="warn",
            )
        )

    required_counts = {
        "findings": findings,
        "static_string_summary": strings_summary,
        "static_string_samples": string_samples_raw,
        "buckets": buckets,
        "metrics": metrics,
        "permission_audit_snapshots": snapshot_count,
        "permission_audit_apps": snapshot_apps,
    }
    missing = [name for name, value in required_counts.items() if not value]

    if run_status == "ABORTED":
        reason_token = abort_reason or abort_signal or "SIGINT"
        print(f"  {'status'.ljust(width)} : ABORTED ({reason_token}) — counts may be partial")
    elif audit and audit.run_id is None and not audit.is_group_scope:
        if audit.is_orphan:
            print(f"  {'status'.ljust(width)} : WARN (orphan run_id missing)")
        elif audit.is_legacy:
            print(f"  {'status'.ljust(width)} : WARN (legacy run_id missing)")
        else:
            print(f"  {'status'.ljust(width)} : WARN (run_id missing)")
    elif canonical_failures:
        preview_limit = 5
        unique_failures = sorted(set(canonical_failures))
        preview = ", ".join(unique_failures[:preview_limit])
        remaining = len(unique_failures) - preview_limit
        if remaining > 0:
            preview += f", +{remaining} more"
        print(f"  {'status'.ljust(width)} : WARN (canonical snapshots failed)")
        print(f"  {'canonical_failures'.ljust(width)} : {len(unique_failures)} ({preview})")
    elif had_errors or missing:
        reason = "missing canonical tables" if missing else "see logs"
        print(f"  {'status'.ljust(width)} : ERROR ({reason})")
    else:
        if audit and audit.is_group_scope:
            print(f"  {'status'.ljust(width)} : OK (group scope)")
        else:
            print(f"  {'status'.ljust(width)} : OK")

    if audit:
        audit_static_run_id = audit.static_run_id if hasattr(audit, "static_run_id") else None
        if audit.is_group_scope:
            status_text = "OK (group scope)" if not missing else "ERROR (missing " + ", ".join(sorted(missing)) + ")"
        elif audit.run_id is None:
            if audit.is_orphan:
                status_text = "ORPHAN (run_id missing)"
            elif audit.is_legacy:
                status_text = "LEGACY (run_id missing)"
            else:
                status_text = "SKIPPED (run_id missing)"
        elif missing:
            status_text = (
                "ERROR (missing " + ", ".join(sorted(missing)) + ")"
            )
        else:
            status_text = "OK (canonical tables populated)"
        prefix = (
            f"static_run_id={audit_static_run_id} "
            if audit_static_run_id is not None
            else ""
        )
        if run_status == "ABORTED":
            status_text = "ABORTED (counts may be partial)"
        print(f"  {'db_verification'.ljust(width)} : {status_text} {prefix}".rstrip())

    high_downgraded = 0
    if run_ids:
        placeholders = ",".join(["%s"] * len(run_ids))
        params = tuple(run_ids)
        query = (
            f"SELECT COALESCE(SUM(value_num),0) FROM metrics "
            f"WHERE feature_key='findings.high_downgraded' AND run_id IN ({placeholders})"
        )
        high_downgraded = _count(query, params)
    if high_downgraded:
        print(f"  {'metrics.high_downgraded'.ljust(width)} : {high_downgraded}")


__all__ = ["render_run_results"]
