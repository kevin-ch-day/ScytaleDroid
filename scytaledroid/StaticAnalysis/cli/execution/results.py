"""Result rendering helpers for static analysis CLI."""

from __future__ import annotations

import os
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import (
    prompt_utils,
    severity,
    status_messages,
    summary_cards,
)

from ...engine.strings import analyse_strings
from ...persistence.ingest import ingest_baseline_payload
from ..core.models import RunOutcome, RunParameters
from ..core.run_lifecycle import finalize_static_run
from ..core.run_persistence import persist_run_summary, update_static_run_status
from ..views.run_detail_view import (
    SEVERITY_TOKEN_ORDER,
    app_detail_loop,
    render_app_detail,
)
from ..views.view_renderers import (
    build_dynamic_plan,
    render_app_result,
    write_baseline_json,
    write_dynamic_plan_json,
)
from .analytics import (
    _build_permission_profile,
    _build_static_risk_row,
    _bulk_trend_deltas,
    _collect_component_stats,
    _collect_finding_signatures,
    _collect_masvs_profile,
    _collect_secret_stats,
    _derive_highlight_stats,
    _render_cross_app_insights,
    _render_post_run_views,
)
from .db_verification import (
    _render_db_masvs_summary,
    _render_db_severity_table,
    _render_persistence_footer,
)
from .diagnostics import (
    _group_diagnostic_warnings,
    _plan_provenance_lines,
    _render_diagnostic_app_summary,
    _schema_guard_status,
)
from .results_formatters import _format_highlight_tokens
from .results_persist import _build_ingest_payload, _persist_cohort_rollup
from .run_db_queries import _apply_display_names, _warn_legacy_running_rows
from .scan_flow import format_duration


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
    finding_totals_by_package: dict[str, Counter[str]] = {}
    for app_result in outcome.results:
        aggregated.update(app_result.severity_totals())
        artifact_count += len(app_result.artifacts)
    if params.dry_run:
        artifact_count = outcome.completed_artifacts

    totals = severity.normalise_counts(aggregated)
    highlight_stats = _derive_highlight_stats(outcome)
    runtime_findings_total = sum(totals.values())
    run_status = "COMPLETED"
    if outcome.aborted:
        run_status = "ABORTED"
    elif outcome.failures and not params.dry_run:
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
    ]
    if params.dry_run:
        overview_items.append(
            summary_cards.summary_item("Findings", "computed (not stored)")
        )
    else:
        overview_items.append(
            summary_cards.summary_item(
                "Findings (runtime)",
                runtime_findings_total,
                value_style="severity_high" if totals.get("high") or totals.get("critical") else "emphasis",
            )
        )
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
    if params.dry_run:
        executed = outcome.completed_artifacts
        discovered = outcome.total_artifacts
        persisted = sum(app.persisted_artifacts for app in outcome.results)
        failed = sum(app.failed_artifacts for app in outcome.results)
        print(
            status_messages.status(
                "Diagnostic dry-run — no persistence; "
                f"discovered={discovered} executed={executed} persisted={persisted} "
                f"failed={failed} persistence_skipped={outcome.dry_run_skipped}",
                level="info",
            )
        )
    print()

    _warn_legacy_running_rows()

    persistence_errors: list[str] = []
    canonical_failures: list[str] = []
    canonical_skips: list[str] = []
    baseline_written_count = 0
    plan_written_count = 0
    report_reference_count = 0
    persist_enabled = not params.dry_run
    compact_mode = not params.verbose_output

    for index, app_result in enumerate(outcome.results, start=1):
        base_report = app_result.base_report()
        if base_report is None:
            if not params.dry_run:
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
            masvs_profile["package"] = (
                manifest.package_name if manifest and manifest.package_name else app_result.package_name
            )
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
        finding_totals_by_package[app_result.package_name] = finding_totals

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
                warning = f"Failed to persist run summary for {app_result.package_name}: {exc}"
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
                        if not compact_mode:
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
                warning = f"Failed to write baseline JSON for {app_result.package_name}: {exc}"
                print(status_messages.status(warning, level="warn"))
            try:
                identity_valid = None
                metadata_map = base_report.metadata if isinstance(base_report.metadata, Mapping) else {}
                if isinstance(metadata_map, Mapping):
                    identity_valid = metadata_map.get("identity_valid")
                if identity_valid is False:
                    print(
                        status_messages.status(
                            (
                                "Skipping dynamic plan generation for "
                                f"{app_result.package_name}: run identity invalid."
                            ),
                            level="warn",
                        )
                    )
                else:
                    plan_payload = build_dynamic_plan(
                        base_report,
                        payload,
                        static_run_id=app_result.static_run_id,
                    )
                    dynamic_plan_path = write_dynamic_plan_json(
                        plan_payload,
                        package=app_result.package_name,
                        profile=params.profile,
                        scope=params.scope,
                        static_run_id=app_result.static_run_id,
                    )
            except Exception as exc:
                warning = f"Failed to write dynamic plan for {app_result.package_name}: {exc}"
                print(status_messages.status(warning, level="warn"))

        if saved_path:
            baseline_written_count += 1
            message = f"Saved baseline JSON → {saved_path.name}"
            if not compact_mode:
                print(message)
        if dynamic_plan_path:
            plan_written_count += 1
            message = f"Saved dynamic plan → {dynamic_plan_path.name}"
            if not compact_mode:
                print(message)

        if report_reference:
            report_reference_count += 1
            message = f"Report reference    → {report_reference}"
            if not compact_mode:
                print(message)

        if index < len(outcome.results):
            print()

    permission_profiles = _dedupe_profile_entries(permission_profiles)
    component_profiles = _dedupe_profile_entries(component_profiles)
    secret_profiles = _dedupe_profile_entries(secret_profiles)
    finding_profiles = _dedupe_profile_entries(finding_profiles)
    trend_deltas = _bulk_trend_deltas(params.session_stamp, finding_totals_by_package)
    static_risk_rows = _dedupe_profile_entries(static_risk_rows)
    _apply_display_names(permission_profiles)

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
        if compact_mode:
            print(
                status_messages.status(
                    "Artifacts saved: "
                    f"baseline={baseline_written_count} plan={plan_written_count} "
                    f"report={report_reference_count}",
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
            unique_skips = sorted(set(canonical_skips))
            preview_limit = 5 if compact_mode else len(unique_skips)
            preview = ", ".join(unique_skips[:preview_limit])
            remaining = len(unique_skips) - preview_limit
            if remaining > 0:
                preview += f", +{remaining} more"
            reason = f"packages={len(unique_skips)} ({preview})"
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
            printed_db_table = _render_db_severity_table(session_stamp)
        if not printed_db_table:
            if params.dry_run and compact_mode:
                print(
                    status_messages.status(
                        "Diagnostic metadata table suppressed in compact mode. "
                        "Use --verbose-output to show full metadata.",
                        level="info",
                    )
                )
            else:
                from ..views.run_detail_view import render_app_table

                render_app_table(outcome.results, diagnostic=params.dry_run, compact=compact_mode)
            if params.dry_run:
                metadata_partial = any(app.target_sdk is None or not app.signer for app in outcome.results)
                if metadata_partial:
                    print(
                        status_messages.status(
                            "Diagnostic metadata mode: partial (targetSdk/signers suppressed).",
                            level="info",
                        )
                    )
                else:
                    print(
                        status_messages.status(
                            "Diagnostic metadata mode: full.",
                            level="info",
                        )
                    )
        diagnostic_warnings: list[tuple[str, str, str]] = []
        linkage_states: list[str] = []
        run_id_states: list[bool] = []
        if params.dry_run and outcome.results:
            diagnostic_warnings, linkage_states, run_id_states = _render_diagnostic_app_summary(
                outcome,
                session_stamp=session_stamp,
                compact_mode=compact_mode,
                verbose_mode=params.verbose_output,
            )
        if compact_mode:
            print(
                status_messages.status(
                    "Per-app details hidden. Re-run with --verbose-output for full reports.",
                    level="info",
                )
            )
        if params.dry_run:
            grouped_warnings = _group_diagnostic_warnings(diagnostic_warnings)
            if grouped_warnings:
                print("\nTop warnings/anomalies")
                for line in grouped_warnings[:5]:
                    print(status_messages.status(line, level="warn"))
            guard_ok, guard_detail = _schema_guard_status()
            guard_label = f"Schema guard: {'OK' if guard_ok else 'FAIL'}"
            if guard_detail:
                guard_label += f" ({guard_detail})"
            print("\n" + guard_label)
            pipeline_version = os.getenv("SCYTALEDROID_PIPELINE_VERSION") or getattr(
                params, "analysis_version", None
            )
            identity_ok = all(app.identity_valid for app in outcome.results)
            linkage_ok = all(state.startswith("VALID") for state in linkage_states) if linkage_states else False
            print("\nDYNAMIC-READY CHECKS (diagnostic)")
            print(f"{'OK' if pipeline_version else 'FAIL'} pipeline_version present")
            print(f"{'OK' if linkage_ok else 'FAIL'} linkage resolvable (run_map/session links)")
            if not linkage_ok:
                print("    Fix: ensure run_map.json is written or static_session_run_links rows exist.")
            print(f"{'OK' if identity_ok else 'FAIL'} identity valid (artifact_set_hash computed)")
            ready = pipeline_version and linkage_ok and identity_ok
            print(f"Result: {'READY' if ready else 'NOT READY'}")
            run_signature_ok = all(bool(app.run_signature) for app in outcome.results)
            artifact_set_ok = all(bool(app.artifact_set_hash) for app in outcome.results)
            print("\nPLAN PROVENANCE (preview)")
            for line in _plan_provenance_lines(run_id_states, run_signature_ok, artifact_set_ok):
                print(line)
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
                if params.verbose_output:
                    print(status_messages.status("Persistence issues detected:", level=level))
                    for message in persistence_errors:
                        print(f"  - {message}")
                else:
                    preview_limit = 5
                    unique_errors = list(dict.fromkeys(persistence_errors))
                    preview = unique_errors[:preview_limit]
                    remaining = len(unique_errors) - len(preview)
                    summary = ", ".join(preview)
                    if remaining > 0:
                        summary += f", +{remaining} more"
                    print(
                        status_messages.status(
                            f"Persistence issues: {len(unique_errors)} item(s) — {summary}",
                            level=level,
                        )
                    )
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
    if outcome.failures and not params.dry_run:
        for message in sorted(set(outcome.failures)):
            print(status_messages.status(message, level="error"))

    if persist_enabled:
        _render_db_masvs_summary()


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


def _dedupe_profile_entries(entries: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    deduped: list[dict[str, object]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            deduped.append(entry)
            continue
        key_token = entry.get("package") or entry.get("label") or entry.get("package_name")
        label = str(key_token or "").strip()
        if not label:
            deduped.append(entry)
            continue
        if label in seen:
            continue
        seen.add(label)
        deduped.append(entry)
    return deduped


__all__ = ["render_run_results"]