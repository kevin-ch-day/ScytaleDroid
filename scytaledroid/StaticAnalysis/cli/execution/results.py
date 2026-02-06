"""Result rendering helpers for static analysis CLI."""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Database.db_utils.artifact_registry import record_artifacts
from scytaledroid.Utils.DisplayUtils import (
    prompt_utils,
    severity,
    status_messages,
    summary_cards,
)
from scytaledroid.Database.db_core import db_queries as core_q

from ...engine.strings import analyse_strings
from ...persistence.ingest import ingest_baseline_payload
from ..core.models import RunOutcome, RunParameters
from ..core.run_lifecycle import finalize_static_run
from ..core.run_persistence import persist_run_summary, update_static_run_status
from ..persistence.run_summary import refresh_static_run_manifest
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
from .run_db_queries import _apply_display_names
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
    baseline_rule_hits_total = 0
    string_samples_persisted_total = 0
    string_samples_selected_total = 0
    detail_output: list[str] = []
    def _emit_detail(line: str = "") -> None:
        detail_output.append(line)
    overview_items = [
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
    session_label = params.session_label or params.session_stamp
    session_meta: dict[str, int | None] = {"attempts": None, "canonical": None, "latest": None}
    if session_label and not params.dry_run:
        try:
            row = core_q.run_sql(
                "SELECT COUNT(*) FROM static_analysis_runs WHERE session_label=%s",
                (session_label,),
                fetch="one",
            )
            session_meta["attempts"] = int(row[0]) if row and row[0] is not None else None
        except Exception:
            session_meta["attempts"] = None
        try:
            row = core_q.run_sql(
                """
                SELECT id
                FROM static_analysis_runs
                WHERE session_label=%s AND is_canonical=1
                ORDER BY canonical_set_at_utc DESC
                LIMIT 1
                """,
                (session_label,),
                fetch="one",
            )
            session_meta["canonical"] = int(row[0]) if row and row[0] is not None else None
        except Exception:
            session_meta["canonical"] = None
        try:
            row = core_q.run_sql(
                """
                SELECT id
                FROM static_analysis_runs
                WHERE session_label=%s
                ORDER BY id DESC
                LIMIT 1
                """,
                (session_label,),
                fetch="one",
            )
            session_meta["latest"] = int(row[0]) if row and row[0] is not None else None
        except Exception:
            session_meta["latest"] = None
    if session_label:
        session_note = f"Session: {session_label}"
        canonical_id = session_meta.get("canonical")
        latest_id = session_meta.get("latest")
        if canonical_id or latest_id:
            parts: list[str] = []
            if canonical_id:
                parts.append(f"canonical: {canonical_id}")
            if latest_id:
                parts.append(f"latest: {latest_id}")
            session_note += f" ({', '.join(parts)})"
        subtitle_parts.append(session_note)
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
    if len(outcome.results) == 1:
        app = outcome.results[0]
        version_name = app.version_name or "?"
        version_code = app.version_code if app.version_code is not None else "?"
        sha256 = app.base_apk_sha256 or "?"
        print(
            status_messages.status(
                f"Version: {version_name} ({version_code}) • SHA-256: {sha256}",
                level="info",
            )
        )
    show_details = True
    if not params.dry_run:
        persistence_ready = os.getenv("SCYTALEDROID_PERSISTENCE_READY", "1").strip() != "0"
        if not persistence_ready:
            print(
                status_messages.status(
                    "Run grade: EXPERIMENTAL (persistence gate failed).",
                    level="warn",
                )
            )
        missing_ids = [res.package_name for res in outcome.results if not res.static_run_id]
        if missing_ids:
            preview = ", ".join(missing_ids[:5])
            if len(missing_ids) > 5:
                preview += f", +{len(missing_ids) - 5} more"
            print(
                status_messages.status(
                    f"Run grade: EXPERIMENTAL (static_run_id missing for: {preview}).",
                    level="warn",
                )
            )
        if params.canonical_action == "replace" and params.session_label and len(outcome.results) == 1:
            current_static_run_id = outcome.results[0].static_run_id
            if current_static_run_id:
                try:
                    row = core_q.run_sql(
                        """
                        SELECT id, base_apk_sha256, sha256
                        FROM static_analysis_runs
                        WHERE session_label=%s AND id<>%s
                        ORDER BY id DESC
                        LIMIT 1
                        """,
                        (params.session_label, current_static_run_id),
                        fetch="one",
                    )
                    if row and row[0]:
                        prev_id = int(row[0])
                        prev_sha = row[1] or row[2] or "?"
                        curr_sha = outcome.results[0].base_apk_sha256 or "?"
                        def _counts(run_id: int) -> dict[str, int]:
                            rows = core_q.run_sql(
                                """
                                SELECT severity, COUNT(*)
                                FROM findings
                                WHERE static_run_id=%s
                                GROUP BY severity
                                """,
                                (run_id,),
                                fetch="all",
                            )
                            totals = {"high": 0, "medium": 0, "low": 0}
                            for sev, cnt in rows or []:
                                key = (sev or "").lower()
                                if key in totals:
                                    totals[key] = int(cnt)
                            return totals
                        prev_counts = _counts(prev_id)
                        curr_counts = _counts(current_static_run_id)
                        print(
                            status_messages.status(
                                "Daily rerun compare (previous canonical → new canonical)",
                                level="info",
                            )
                        )
                        print(f"  APK SHA-256: {prev_sha} → {curr_sha}")
                        print(
                            "  Findings: High "
                            f"{prev_counts['high']} → {curr_counts['high']}, "
                            "Medium "
                            f"{prev_counts['medium']} → {curr_counts['medium']}, "
                            "Low "
                            f"{prev_counts['low']} → {curr_counts['low']}"
                        )
                except Exception:
                    pass
    p0_count = 0
    example_provider = None
    for app_result in outcome.results:
        base_report = app_result.base_report()
        if base_report is None:
            continue
        if example_provider is None:
            providers = getattr(base_report.exported_components, "providers", ())
            if providers:
                example_provider = str(providers[0])
        for result in getattr(base_report, "detector_results", ()) or []:
            for finding in getattr(result, "findings", ()) or []:
                sev = getattr(getattr(finding, "severity_gate", None), "value", None)
                if str(sev) == "P0":
                    p0_count += 1

    highlight_tokens = _format_highlight_tokens(
        highlight_stats,
        totals,
        len(outcome.results),
    )
    if highlight_tokens:
        print(status_messages.highlight("; ".join(highlight_tokens), show_icon=True))
    if p0_count and example_provider:
        print()
        print("Top issue (P0)")
        providers_count = highlight_stats.get("providers", 0)
        print(f"  Exported providers without strong guards: {providers_count}")
        print(f"  Example: {example_provider} (exported, no read/write permission)")
        print("  Next: View options → [1] Summary details → Exported components")
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


    persistence_errors: list[str] = []
    canonical_failures: list[str] = []
    canonical_skips: list[str] = []
    baseline_written_count = 0
    plan_written_count = 0
    report_reference_count = 0
    persistence_ready = os.getenv("SCYTALEDROID_PERSISTENCE_READY", "1").strip() != "0"
    persist_enabled = (not params.dry_run) and persistence_ready
    compact_mode = not params.verbose_output
    if not persistence_ready and not params.dry_run:
        print(
            status_messages.status(
                "Persistence gate failed; evidence outputs will be suppressed for this run.",
                level="warn",
            )
        )

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
        if isinstance(string_data, Mapping):
            selected_payload = string_data.get("selected_samples")
            if isinstance(selected_payload, Mapping):
                selected_count = 0
                for values in selected_payload.values():
                    if isinstance(values, Sequence) and not isinstance(values, (str, bytes)):
                        selected_count += len(values)
                string_samples_selected_total += selected_count
        finding_totals_by_package[app_result.package_name] = finding_totals
        baseline_hits = 0
        if isinstance(payload, Mapping):
            baseline_payload = payload.get("baseline")
            if isinstance(baseline_payload, Mapping):
                findings_payload = baseline_payload.get("findings")
                if isinstance(findings_payload, Sequence) and not isinstance(
                    findings_payload, (str, bytes)
                ):
                    baseline_hits = len(findings_payload)
        baseline_rule_hits_total += baseline_hits

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
                _emit_detail(line)

        if persist_enabled and not app_result.static_run_id:
            print(
                status_messages.status(
                    f"Skipping persistence for {app_result.package_name}: static_run_id missing.",
                    level="warn",
                )
            )
        if persist_enabled and app_result.static_run_id:
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
                _emit_detail(line)

        saved_path = None
        dynamic_plan_path = None
        if persist_enabled and not app_result.static_run_id:
            print(
                status_messages.status(
                    f"Skipping evidence outputs for {app_result.package_name}: static_run_id missing.",
                    level="warn",
                )
            )
        if persist_enabled and app_result.static_run_id:
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
                _emit_detail(message)
        if dynamic_plan_path:
            plan_written_count += 1
            message = f"Saved dynamic plan → {dynamic_plan_path.name}"
            if not compact_mode:
                _emit_detail(message)

        if persist_enabled and app_result.static_run_id:
            artifacts: list[dict[str, object]] = []
            now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
            manifest_evidence_path = None
            try:
                metadata_map = base_report.metadata if isinstance(base_report.metadata, Mapping) else {}
                repro_bundle = (
                    metadata_map.get("repro_bundle")
                    if isinstance(metadata_map, Mapping)
                    else None
                )
                manifest_evidence = (
                    repro_bundle.get("manifest_evidence")
                    if isinstance(repro_bundle, Mapping)
                    else None
                )
                components = (
                    manifest_evidence.get("components")
                    if isinstance(manifest_evidence, Mapping)
                    else manifest_evidence
                )
                if isinstance(components, list):
                    evidence_dir = Path("evidence") / "static_runs" / str(app_result.static_run_id)
                    evidence_dir.mkdir(parents=True, exist_ok=True)
                    manifest_evidence_path = evidence_dir / "manifest_evidence.json"
                    manifest_payload = {
                        "schema": "manifest_evidence_v1",
                        "generated_at_utc": now,
                        "package_name": app_result.package_name,
                        "components": components,
                    }
                    manifest_evidence_path.write_text(
                        json.dumps(manifest_payload, indent=2, sort_keys=True)
                    )
            except Exception:
                manifest_evidence_path = None
            for path, artifact_type in (
                (saved_path, "static_baseline_json"),
                (dynamic_plan_path, "static_dynamic_plan_json"),
            ):
                if not path:
                    continue
                try:
                    digest = hashlib.sha256(path.read_bytes()).hexdigest()
                    artifacts.append(
                        {
                            "path": str(path),
                            "type": artifact_type,
                            "sha256": digest,
                            "size_bytes": path.stat().st_size,
                            "created_at_utc": now,
                            "origin": "host",
                            "pull_status": "n/a",
                        }
                    )
                except Exception:
                    continue
            if manifest_evidence_path and manifest_evidence_path.exists():
                try:
                    digest = hashlib.sha256(manifest_evidence_path.read_bytes()).hexdigest()
                    artifacts.append(
                        {
                            "path": str(manifest_evidence_path),
                            "type": "manifest_evidence",
                            "sha256": digest,
                            "size_bytes": manifest_evidence_path.stat().st_size,
                            "created_at_utc": now,
                            "origin": "host",
                            "pull_status": "n/a",
                        }
                    )
                except Exception:
                    pass
            if base_artifact and base_artifact.saved_path:
                report_path = Path(base_artifact.saved_path)
                if report_path.exists():
                    try:
                        digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
                        artifacts.append(
                            {
                                "path": str(report_path),
                                "type": "static_report",
                                "sha256": digest,
                                "size_bytes": report_path.stat().st_size,
                                "created_at_utc": now,
                                "origin": "host",
                                "pull_status": "n/a",
                            }
                        )
                    except Exception:
                        pass
            if artifacts:
                record_artifacts(
                    run_id=str(app_result.static_run_id),
                    run_type="static",
                    artifacts=artifacts,
                    origin="host",
                    pull_status="n/a",
                )
                refresh_static_run_manifest(app_result.static_run_id)

        if report_reference:
            report_reference_count += 1
            message = f"Report reference    → {report_reference}"
            if not compact_mode:
                _emit_detail(message)

        canonical_change = params.canonical_action in {"replace", "first_run"}
        if (
            canonical_change
            and params.session_label
            and len(outcome.results) == 1
            and (saved_path or dynamic_plan_path)
        ):
            alias_base = params.session_label
            try:
                if saved_path:
                    alias = saved_path.parent / f"{alias_base}_baseline.json"
                    alias.write_bytes(saved_path.read_bytes())
                    latest_alias = saved_path.parent / "latest_baseline.json"
                    latest_alias.write_bytes(saved_path.read_bytes())
                if dynamic_plan_path:
                    alias = dynamic_plan_path.parent / f"{alias_base}_plan.json"
                    alias.write_bytes(dynamic_plan_path.read_bytes())
                    latest_alias = dynamic_plan_path.parent / "latest_plan.json"
                    latest_alias.write_bytes(dynamic_plan_path.read_bytes())
                if params.canonical_action == "replace":
                    prior = session_meta.get("canonical")
                    if prior and app_result.static_run_id:
                        print(
                            status_messages.status(
                                f"Canonical updated: static_run_id={prior} → {app_result.static_run_id}",
                                level="info",
                            )
                        )
                print(
                    status_messages.status(
                        "Daily aliases updated (baseline/plan).",
                        level="info",
                    )
                )
            except Exception:
                pass

        if index < len(outcome.results):
            _emit_detail("")

    permission_profiles = _dedupe_profile_entries(permission_profiles)
    component_profiles = _dedupe_profile_entries(component_profiles)
    secret_profiles = _dedupe_profile_entries(secret_profiles)
    finding_profiles = _dedupe_profile_entries(finding_profiles)
    trend_deltas = _bulk_trend_deltas(params.session_stamp, finding_totals_by_package)
    static_risk_rows = _dedupe_profile_entries(static_risk_rows)
    _apply_display_names(permission_profiles)

    if persist_enabled:
        print("Findings accounting")
        print(f"  Raw detector hits (runtime): {runtime_findings_total}")
        print(f"  Normalized (deduped):        {normalized_findings_total}")
        print(f"  Baseline rule hits:          {baseline_rule_hits_total}")
        print(
            "  MASVS totals:               "
            f"H{totals.get('high', 0)} "
            f"M{totals.get('medium', 0)} "
            f"L{totals.get('low', 0)} "
            f"I{totals.get('info', 0)}"
        )
        print(
            status_messages.status(
                (
                    "String samples stored (full): "
                    f"{string_samples_persisted_total} "
                    f"(selected={string_samples_selected_total}) "
                    f"(selected cap={params.string_max_samples} per bucket; entropy ≥ {params.string_min_entropy:.2f})"
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
    if not params.dry_run:
        print()
        print("Next view")
        print("---------")
        print("[1] Continue to tables/diagnostics")
        print("[2] Return to main menu")
        resp = prompt_utils.prompt_text("Choice", default="1", required=False).strip()
        if resp in {"2", "0"}:
            show_details = False

    if show_details:
        for line in detail_output:
            print(line)

    if outcome.results and show_details:
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
