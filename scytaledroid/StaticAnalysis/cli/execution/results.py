"""Result rendering helpers for static analysis CLI."""

from __future__ import annotations

import json
import os
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils.artifact_registry import record_artifacts
from scytaledroid.Utils.DisplayUtils import (
    prompt_utils,
    severity,
    status_messages,
    summary_cards,
)
from scytaledroid.Utils.LoggingUtils import logging_events
from scytaledroid.Utils.LoggingUtils import logging_engine

from ...engine.strings import analyse_strings
from ...persistence.ingest import ingest_baseline_payload
from ..core.models import RunOutcome, RunParameters
from ..core.run_context import StaticRunContext
from ..core.run_lifecycle import finalize_static_run
from ..persistence.run_summary import refresh_static_run_manifest
from ..persistence.run_summary import persist_run_summary, update_static_run_status
from ..persistence.run_writers import export_dep_snapshot

from ..views.view_renderers import render_app_result
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
from .artifacts import (
    build_artifact_registry_entries,
    update_static_aliases,
    write_baseline_json_artifact,
    write_manifest_evidence,
)
from .artifact_publication import publish_persisted_artifacts
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
from .pipeline import REQUIRED_PAPER_ARTIFACTS, governance_ready
from .plan import build_dynamic_plan_artifact
from .results_dedupe import dedupe_profile_entries
from .results_formatters import _format_highlight_tokens
from .results_persistence import (
    apply_persistence_outcome,
    collect_persistence_errors,
    merge_persistence_metadata,
)
from .results_persist import _build_ingest_payload, _persist_cohort_rollup
from .results_sections import (
    render_artifact_completeness,
    render_export_all_tables_section,
    render_permission_snapshot_summary_section,
    render_persistence_audit_summary_section,
    render_post_run_diagnostics_menu,
    render_session_meta_details,
    render_static_interpretation_footer,
    render_static_output_context,
    render_static_output_context_compact,
)
from .run_db_queries import _apply_display_names
from .scan_flow import format_duration
from .string_analysis_payload import analyse_string_payload
from .view import DetailBuffer


@dataclass(frozen=True, slots=True)
class RunResultsSessionMeta:
    session_label: str | None
    attempts: int | None
    canonical_id: int | None
    latest_id: int | None


@dataclass(frozen=True, slots=True)
class RunResultsViewModel:
    title: str
    overview_items: list[dict[str, object]]
    subtitle: str | None
    footer: str | None
    static_output_context: Mapping[str, object]
    planned_artifacts: int
    observed_artifacts: int
    version_line: str | None
    session_meta: RunResultsSessionMeta


def _first_text(*values: object) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _first_int(*values: object) -> int | None:
    for value in values:
        if value is None:
            continue
        try:
            return int(value)
        except Exception:
            continue
    return None


def _is_large_compact_batch(params: RunParameters, outcome: RunOutcome) -> bool:
    return bool(
        not params.verbose_output
        and params.scope in {"all", "profile"}
        and len(outcome.results) > 20
    )


def _emit_static_persistence_event(
    *,
    event: str,
    message: str,
    params: RunParameters,
    extra: Mapping[str, object] | None = None,
) -> None:
    payload = {
        "event": event,
        "session_stamp": params.session_stamp,
        "run_id": params.session_stamp,
        "execution_id": getattr(params, "execution_id", None),
        "scope_label": params.scope_label,
        "scope": params.scope,
        "profile": params.profile_label,
    }
    if extra:
        payload.update({key: value for key, value in extra.items() if value is not None})
    logging_engine.get_static_logger().info(
        message,
        extra=logging_engine.ensure_trace(payload),
    )


def _format_persistence_progress_text(
    *,
    index: int,
    total_results: int,
    package_name: str,
    app_label: str | None,
    elapsed_text: str,
    eta_text: str,
    persistence_error_count: int,
) -> str:
    current = app_label or package_name
    lines = [f"Persisting app: {current}"]
    if package_name and package_name.strip() != current.strip():
        lines.append(f"Package: {package_name}")
    lines.extend(
        [
        f"Progress: {index}/{total_results} app(s)",
        f"Elapsed : {elapsed_text}",
        f"ETA     : ~{eta_text}",
        f"Health  : persistence_errors={persistence_error_count}",
        ]
    )
    return "\n".join(lines)


def _render_compact_persistence_summary(
    *,
    params: RunParameters,
    total_results: int,
    normalized_findings_total: int,
    string_samples_persisted_total: int,
    baseline_written_count: int,
    plan_written_count: int,
    report_reference_count: int,
    persistence_errors: Sequence[str],
    canonical_failures: Sequence[str],
    compat_export_errors: Sequence[str],
    run_status: str,
) -> None:
    print()
    print("Persistence summary")
    print("-------------------")
    print(f"Session : {params.session_stamp or params.session_label or 'unspecified'}")
    print(f"Apps    : {total_results}")
    print(f"Findings: {normalized_findings_total}")
    print(f"Strings : {string_samples_persisted_total}")
    print(
        "Artifacts: "
        f"baseline={baseline_written_count} "
        f"plan={plan_written_count} "
        f"report={report_reference_count}"
    )
    print(
        "Status  : "
        f"{run_status} "
        f"(persistence_errors={len(list(dict.fromkeys(str(x) for x in persistence_errors)))} "
        f"canonical_failures={len(list(dict.fromkeys(str(x) for x in canonical_failures if x)) )} "
        f"compat_export_errors={len(list(dict.fromkeys(str(x) for x in compat_export_errors if x)) )})"
    )
    print("Details : Database tools / Web view for full diagnostics")


def _load_json_mapping(path_value: str | None) -> Mapping[str, object]:
    if not path_value:
        return {}
    try:
        path = Path(path_value)
        if not path.exists():
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, Mapping) else {}
    except Exception:
        return {}


def _collect_static_output_context(
    outcome: RunOutcome,
    params: RunParameters,
    *,
    artifact_count: int,
) -> dict[str, object]:
    session_id = params.session_label or params.session_stamp or "n/a"
    analyzed_apps = len(outcome.results)
    planned_artifacts = int(outcome.total_artifacts or artifact_count)
    observed_artifacts = int(artifact_count)
    first_group = outcome.scope.groups[0] if getattr(outcome.scope, "groups", ()) else None
    group_manifest = (
        first_group.harvest_manifest
        if first_group is not None and isinstance(getattr(first_group, "harvest_manifest", None), Mapping)
        else {}
    )
    first_manifest_path = (
        getattr(first_group, "harvest_manifest_path", None)
        if first_group is not None
        else None
    )
    result_manifest = _load_json_mapping(getattr(outcome.results[0], "harvest_manifest_path", None)) if outcome.results else {}
    manifest = group_manifest or result_manifest
    package_payload = manifest.get("package") if isinstance(manifest, Mapping) else {}
    device_serial = _first_text(
        package_payload.get("device_serial") if isinstance(package_payload, Mapping) else None,
    )
    snapshot_id = _first_int(
        package_payload.get("snapshot_id") if isinstance(package_payload, Mapping) else None,
    )
    snapshot_captured_at = _first_text(
        package_payload.get("snapshot_captured_at") if isinstance(package_payload, Mapping) else None,
    )

    harvested_packages = analyzed_apps
    persisted_packages = sum(
        1
        for app in outcome.results
        if str(getattr(app, "harvest_persistence_status", "") or "").strip().lower()
        not in {"", "not_requested"}
    )
    if persisted_packages == 0 and analyzed_apps:
        persisted_packages = analyzed_apps

    acquisition = {
        "inventoried": None,
        "in_scope": None,
        "policy_eligible": None,
        "scheduled": None,
        "harvested": harvested_packages,
        "persisted": persisted_packages,
        "blocked_policy": None,
        "blocked_scope": None,
    }

    non_root = False
    if device_serial and params.scope == "all":
        try:
            from scytaledroid.DeviceAnalysis import harvest
            from scytaledroid.DeviceAnalysis.inventory.snapshot_io import load_latest_inventory

            inventory_snapshot = load_latest_inventory(device_serial)
            inventory_snapshot_id = _first_int(
                inventory_snapshot.get("snapshot_id") if isinstance(inventory_snapshot, Mapping) else None,
            )
            if inventory_snapshot_id is not None and snapshot_id is not None and inventory_snapshot_id == snapshot_id:
                packages = inventory_snapshot.get("packages") if isinstance(inventory_snapshot, Mapping) else None
                if isinstance(packages, Sequence) and not isinstance(packages, (str, bytes)):
                    rows = harvest.build_inventory_rows(packages)
                    plan = harvest.build_harvest_plan(rows, include_system_partitions=False)
                    scheduled = sum(1 for pkg in plan.packages if not pkg.skip_reason)
                    blocked_policy = sum(1 for pkg in plan.packages if pkg.skip_reason == "policy_non_root")
                    blocked_scope = sum(
                        1 for pkg in plan.packages if pkg.skip_reason and pkg.skip_reason != "policy_non_root"
                    )
                    acquisition.update(
                        {
                            "inventoried": len(rows),
                            "in_scope": len(plan.packages),
                            "policy_eligible": scheduled,
                            "scheduled": scheduled,
                            "blocked_policy": blocked_policy,
                            "blocked_scope": blocked_scope,
                        }
                    )
                    non_root = blocked_policy > 0
        except Exception:
            pass

    mode_tokens = ["Canonical"]
    if non_root:
        mode_tokens.append("non-root")

    return {
        "session_id": session_id,
        "device_serial": device_serial,
        "snapshot_id": snapshot_id,
        "snapshot_captured_at": snapshot_captured_at,
        "scope_analyzed": "Harvested APK artifacts only",
        "mode_label": " / ".join(mode_tokens),
        "analyzed_apps": analyzed_apps,
        "planned_artifacts": planned_artifacts,
        "observed_artifacts": observed_artifacts,
        "acquisition": acquisition,
        "has_group_manifest": bool(manifest or first_manifest_path),
    }

def _load_run_results_session_meta(
    *,
    params: RunParameters,
) -> RunResultsSessionMeta:
    session_label = params.session_label or params.session_stamp
    if not session_label or params.dry_run:
        return RunResultsSessionMeta(
            session_label=session_label,
            attempts=None,
            canonical_id=None,
            latest_id=None,
        )

    attempts: int | None = None
    canonical_id: int | None = None
    latest_id: int | None = None
    try:
        row = core_q.run_sql(
            "SELECT COUNT(*) FROM static_analysis_runs WHERE session_label=%s",
            (session_label,),
            fetch="one",
        )
        attempts = int(row[0]) if row and row[0] is not None else None
    except Exception:
        attempts = None
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
        canonical_id = int(row[0]) if row and row[0] is not None else None
    except Exception:
        canonical_id = None
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
        latest_id = int(row[0]) if row and row[0] is not None else None
    except Exception:
        latest_id = None
    return RunResultsSessionMeta(
        session_label=session_label,
        attempts=attempts,
        canonical_id=canonical_id,
        latest_id=latest_id,
    )


def build_run_results_view_model(
    outcome: RunOutcome,
    params: RunParameters,
    *,
    totals: Mapping[str, int],
    artifact_count: int,
) -> RunResultsViewModel:
    runtime_findings_total = sum(int(value or 0) for value in totals.values())
    overview_items = [
        summary_cards.summary_item("Applications", len(outcome.results)),
        summary_cards.summary_item("Artifacts", artifact_count),
    ]
    if params.dry_run:
        overview_items.append(summary_cards.summary_item("Findings", "computed (not stored)"))
    else:
        overview_items.append(
            summary_cards.summary_item(
                "Detector hits (raw)",
                runtime_findings_total,
                value_style="severity_high" if totals.get("high") or totals.get("critical") else "emphasis",
            )
        )

    session_meta = _load_run_results_session_meta(params=params)
    subtitle_parts = [params.profile_label]
    if params.scope_label:
        subtitle_parts.append(f"Scope: {params.scope_label}")
    if session_meta.session_label:
        subtitle_parts.append(f"Session: {session_meta.session_label}")

    result_label = "Canonical"
    result_reasons: list[str] = []
    if not params.dry_run:
        if not bool(params.persistence_ready):
            result_label = "Experimental"
            result_reasons.append("persistence gate failed")
        if outcome.failures:
            result_label = "Experimental"
            result_reasons.append("run failures present")
    result_text = f"Result set: {result_label}"
    if result_reasons:
        result_text += f" ({'; '.join(result_reasons)})"
    footer = f"{result_text}  |  Use Review, Database tools, or the Web view for deeper drilldown."

    static_output_context = _collect_static_output_context(
        outcome,
        params,
        artifact_count=artifact_count,
    )
    planned_artifacts = int(static_output_context.get("planned_artifacts") or artifact_count)
    observed_artifacts = int(static_output_context.get("observed_artifacts") or artifact_count)

    version_line = None
    if len(outcome.results) == 1:
        app = outcome.results[0]
        version_name = app.version_name or "?"
        version_code = app.version_code if app.version_code is not None else "?"
        sha256 = app.base_apk_sha256 or "?"
        version_line = f"Version: {version_name} ({version_code}) • SHA-256: {sha256}"

    return RunResultsViewModel(
        title="Static analysis summary",
        overview_items=overview_items,
        subtitle=" • ".join(subtitle_parts),
        footer=footer,
        static_output_context=static_output_context,
        planned_artifacts=planned_artifacts,
        observed_artifacts=observed_artifacts,
        version_line=version_line,
        session_meta=session_meta,
    )


def write_baseline_json(payload: dict[str, object], *, package: str, profile: str, scope: str) -> Path:
    """Delegate to artifact writer (tests commonly patch ``results.write_baseline_json``)."""
    return write_baseline_json_artifact(
        payload,
        package_name=package,
        profile=profile,
        scope=scope,
    )


def write_dynamic_plan_json(
    base_report,
    payload: dict[str, object],
    *,
    package: str,
    profile: str,
    scope: str,
    static_run_id: int,
) -> Path | None:
    """Delegate to plan builder (tests commonly patch ``results.write_dynamic_plan_json``)."""
    return build_dynamic_plan_artifact(
        base_report,
        payload,
        package_name=package,
        profile=profile,
        scope=scope,
        static_run_id=static_run_id,
    )

def _analyse_strings_for_results(
    apk_path: str,
    *,
    params: RunParameters,
    package_name: str,
    warning_sink: list[str] | None = None,
) -> Mapping[str, object]:
    return analyse_string_payload(
        apk_path,
        params=params,
        package_name=package_name,
        warning_sink=warning_sink,
        analyse_fn=analyse_strings,
    )


def render_run_results(
    outcome: RunOutcome,
    params: RunParameters,
    *,
    run_ctx: StaticRunContext | None = None,
    defer_persistence_footer: bool = False,
    defer_post_run_menu: bool = False,
) -> None:
    """Persist and (optionally) render run results.

    Batch mode must remain deterministic and non-interactive:
    we still write required artifacts (baseline JSON, dynamic plan, registry),
    but suppress all console rendering in quiet batch.
    """

    silent_output = bool(run_ctx.quiet and run_ctx.batch) if isinstance(run_ctx, StaticRunContext) else False
    if silent_output:
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            _render_run_results_impl(
                outcome,
                params,
                run_ctx=run_ctx,
                defer_persistence_footer=defer_persistence_footer,
                defer_post_run_menu=defer_post_run_menu,
            )
        return

    _render_run_results_impl(
        outcome,
        params,
        run_ctx=run_ctx,
        defer_persistence_footer=defer_persistence_footer,
        defer_post_run_menu=defer_post_run_menu,
    )


def _render_run_results_impl(
    outcome: RunOutcome,
    params: RunParameters,
    *,
    run_ctx: StaticRunContext | None,
    defer_persistence_footer: bool,
    defer_post_run_menu: bool,
) -> None:
    """Internal implementation for render_run_results (may print)."""
    # Keep verbose flag owned by callers; this function reads params directly.

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
    interrupted_compact = outcome.aborted and not params.dry_run
    run_status = "COMPLETED"
    if outcome.aborted:
        run_status = "FAILED"
    elif outcome.failures and not params.dry_run:
        run_status = "FAILED"
    ended_at_utc = outcome.finished_at.isoformat(timespec="seconds") + "Z"
    abort_reason = outcome.abort_reason
    abort_signal = outcome.abort_signal
    normalized_findings_total = 0
    baseline_rule_hits_total = 0
    string_samples_persisted_total = 0
    string_samples_selected_total = 0
    detail_output = DetailBuffer()

    def _emit_detail(line: str = "") -> None:
        detail_output.add(line)
    view_model = build_run_results_view_model(
        outcome,
        params,
        totals=totals,
        artifact_count=artifact_count,
    )
    large_compact_batch = _is_large_compact_batch(params, outcome)
    if large_compact_batch:
        view_model = replace(
            view_model,
            footer=view_model.footer.replace(
                "Use the prompts below to drill into per-app findings.",
                "Use Review, Database tools, or the Web view for deeper drilldown.",
            ),
        )
    if interrupted_compact:
        print(
            status_messages.status(
                (
                    "Static analysis interrupted — finalizing partial persistence "
                    f"for session {params.session_stamp}."
                ),
                level="warn",
            )
        )
        print(
            status_messages.status(
                (
                    f"Artifacts completed: {outcome.completed_artifacts}/{outcome.total_artifacts or outcome.completed_artifacts} "
                    f"| apps={len(outcome.results)} | detector_hits={runtime_findings_total}"
                ),
                level="info",
            )
        )
    else:
        print(
            summary_cards.format_summary_card(
                view_model.title,
                view_model.overview_items,
                subtitle=view_model.subtitle,
                footer=view_model.footer,
                width=90,
            )
        )
        if large_compact_batch:
            render_static_output_context_compact(
                view_model.static_output_context,
                planned_artifacts=view_model.planned_artifacts,
                observed_artifacts=view_model.observed_artifacts,
            )
        else:
            render_static_output_context(view_model.static_output_context)
            render_artifact_completeness(
                planned_artifacts=view_model.planned_artifacts,
                observed_artifacts=view_model.observed_artifacts,
            )
        render_session_meta_details(view_model.session_meta)
        if view_model.version_line:
            print(
                status_messages.status(
                    view_model.version_line,
                    level="info",
                )
            )
    show_details = params.dry_run and not outcome.aborted
    run_notes: list[str] = []
    if not params.dry_run:
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
                                FROM static_analysis_findings
                                WHERE run_id=%s
                                GROUP BY severity
                                """,
                                (run_id,),
                                fetch="all",
                            )
                            totals = {"high": 0, "medium": 0, "low": 0}
                            for sev, cnt in rows or []:
                                label = severity.format_severity_label(sev, default="")
                                key = label.lower()
                                if key in totals:
                                    totals[key] = int(cnt)
                            return totals
                        prev_counts = _counts(prev_id)
                        curr_counts = _counts(current_static_run_id)
                        # If DB counts are missing for the current run, fall back to runtime totals.
                        if sum(curr_counts.values()) == 0 and totals:
                            curr_counts = {
                                "high": int(totals.get("high", 0)),
                                "medium": int(totals.get("medium", 0)),
                                "low": int(totals.get("low", 0)),
                            }
                        has_diff = (prev_sha != curr_sha) or (prev_counts != curr_counts)
                        if has_diff:
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
    p0_apps = 0
    example_provider = None
    example_provider_package = None
    for app_result in outcome.results:
        base_report = app_result.base_report()
        if base_report is None:
            continue
        app_has_p0 = False
        if example_provider is None:
            providers = getattr(base_report.exported_components, "providers", ())
            if providers:
                example_provider = str(providers[0])
                example_provider_package = app_result.app_label or app_result.package_name
        for result in getattr(base_report, "detector_results", ()) or []:
            for finding in getattr(result, "findings", ()) or []:
                sev = getattr(getattr(finding, "severity_gate", None), "value", None)
                if str(sev) == "P0":
                    p0_count += 1
                    app_has_p0 = True
        if app_has_p0:
            p0_apps += 1

    highlight_tokens = _format_highlight_tokens(
        highlight_stats,
        totals,
        len(outcome.results),
    )
    if highlight_tokens and not interrupted_compact:
        print(status_messages.highlight("; ".join(highlight_tokens), show_icon=True))
    risk_posture_line = None
    if p0_count:
        risk_posture_line = (
            f"Risk posture: High exposure detected ({p0_count} P0 findings across "
            f"{p0_apps}/{len(outcome.results)} apps)"
        )
    elif (totals.get("high", 0) or totals.get("critical", 0)) and not interrupted_compact:
        high_total = int(totals.get("high", 0) or 0) + int(totals.get("critical", 0) or 0)
        risk_posture_line = f"Risk posture: Elevated ({high_total} high-severity findings require review)"
    if risk_posture_line and not interrupted_compact:
        print(status_messages.status(risk_posture_line, level="warn"))
    if p0_count and example_provider and not interrupted_compact:
        print()
        print("Top Risk Driver")
        print("----------------")
        providers_count = highlight_stats.get("providers", 0)
        print("Issue              : Exported providers without strong guards")
        print(f"Count              : {providers_count}")
        print(
            "Why it matters     : Unprotected exported providers increase cross-app access risk "
            "and weaken component isolation."
        )
        if example_provider_package:
            print(f"Example package    : {example_provider_package}")
        print(f"Example component  : {example_provider}")
        if large_compact_batch:
            print("Recommended next action: Review / Database tools / Web view → Exported components")
        else:
            print("Recommended next action: View options → [1] Summary details → Exported components")
    if params.dry_run:
        executed = outcome.completed_artifacts
        discovered = outcome.total_artifacts
        persisted = sum(app.persisted_artifacts for app in outcome.results)
        failed = sum(app.failed_artifacts for app in outcome.results)
        print(
            status_messages.status(
                "Diagnostic dry-run — no persistence; "
                f"discovered={discovered} executed={executed} persisted={persisted} "
                f"failed={failed} skipped={outcome.dry_run_skipped}",
                level="info",
            )
        )
    elif outcome.results:
        print(
            status_messages.status(
                f"Finalizing persistence and evidence artifacts for {len(outcome.results)} app(s)…",
                level="info",
            )
        )
    print()


    persistence_errors: list[str] = []
    canonical_failures: list[str] = []
    compat_export_errors: list[str] = []
    canonical_skips: list[str] = []
    baseline_written_count = 0
    noncanonical_baseline_written_count = 0
    plan_written_count = 0
    report_reference_count = 0
    persistence_ready = bool(params.persistence_ready)
    persist_enabled = (not params.dry_run) and persistence_ready
    total_apps = max(1, len(outcome.results))
    default_failfast_threshold = min(3, total_apps)
    try:
        missing_runid_failfast_threshold = max(
            1,
            int(
                os.environ.get(
                    "SCYTALEDROID_STATIC_RUNID_FAILFAST_THRESHOLD",
                    str(default_failfast_threshold),
                )
            ),
        )
    except Exception:
        missing_runid_failfast_threshold = default_failfast_threshold
    consecutive_missing_run_ids = 0
    compact_mode = not params.verbose_output
    if not persistence_ready and not params.dry_run:
        print(
            status_messages.status(
                "Persistence gate failed; evidence outputs will be suppressed for this run.",
                level="warn",
            )
        )
    total_results = len(outcome.results)
    detailed_finalization_logs = total_results <= 20
    checkpoint_stride = 10 if total_results >= 50 else 5
    persistence_started_monotonic = time.monotonic()
    if persist_enabled:
        _emit_static_persistence_event(
            event=logging_events.PERSIST_START,
            message="Static persistence started",
            params=params,
            extra={
                "applications": total_results,
                "artifacts": outcome.total_artifacts,
                "large_compact_batch": large_compact_batch,
            },
        )

    for index, app_result in enumerate(outcome.results, start=1):
        if persist_enabled and compact_mode:
            if large_compact_batch:
                if index == 1 or index == total_results or index % checkpoint_stride == 0:
                    elapsed_s = max(0.0, time.monotonic() - persistence_started_monotonic)
                    finalized = max(0, index - 1)
                    rate = (finalized / elapsed_s) if elapsed_s > 0 else 0.0
                    remaining = max(0, total_results - finalized)
                    eta_s = int(round((remaining / rate), 0)) if rate > 0 else -1
                    print(
                        status_messages.status(
                            _format_persistence_progress_text(
                                index=index,
                                total_results=total_results,
                                package_name=app_result.package_name,
                                app_label=app_result.app_label,
                                elapsed_text=format_duration(elapsed_s),
                                eta_text=format_duration(float(eta_s)) if eta_s >= 0 else "--",
                                persistence_error_count=len(
                                    list(dict.fromkeys(str(x) for x in persistence_errors))
                                ),
                            ),
                            level="info",
                        )
                    )
            elif detailed_finalization_logs:
                print(
                    status_messages.status(
                        f"Finalizing [{index}/{total_results}] {app_result.package_name}…",
                        level="info",
                    )
                )
            else:
                if index == 1 or index == total_results or index % checkpoint_stride == 0:
                    pct = int(round((index / max(1, total_results)) * 100.0))
                    print(
                        status_messages.status(
                            f"Finalizing persistence: {index}/{total_results} ({pct}%)",
                            level="info",
                        )
                    )
        base_report = app_result.base_report()
        if base_report is None:
            if not params.dry_run:
                warning = f"No report generated for {app_result.package_name}."
                print(status_messages.status(warning, level="warn"))
            if app_result.static_run_id and persist_enabled:
                if outcome.aborted:
                    update_static_run_status(
                        static_run_id=app_result.static_run_id,
                        status="FAILED",
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

        string_data = (
            app_result.base_string_data
            if isinstance(app_result.base_string_data, Mapping)
            else _analyse_strings_for_results(
                base_report.file_path,
                params=params,
                package_name=app_result.package_name,
                warning_sink=outcome.warnings,
            )
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
            verbose_output=bool(params.verbose_output),
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

        show_compact_pipeline_lines = not (
            compact_mode and params.scope in {"all", "profile"} and len(outcome.results) > 5
        )
        if compact_mode and show_compact_pipeline_lines:
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

        if persist_enabled:
            try:
                merge_persistence_metadata(
                    base_report=base_report,
                    app_result=app_result,
                    params=params,
                )
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
                    paper_grade_requested=params.paper_grade_requested,
                    canonical_action=params.canonical_action,
                    dry_run=params.dry_run,
                )
                findings_delta, sample_delta = apply_persistence_outcome(
                    app_result=app_result,
                    outcome_status=outcome_status,
                )
                normalized_findings_total += findings_delta
                string_samples_persisted_total += sample_delta
                _emit_static_persistence_event(
                    event=logging_events.PERSIST_APP,
                    message="Static persistence app finalized",
                    params=params,
                    extra={
                        "package_name": app_result.package_name,
                        "app_label": app_result.app_label,
                        "app_index": index,
                        "app_total": total_results,
                        "run_id_db": outcome_status.run_id if outcome_status else None,
                        "static_run_id": outcome_status.static_run_id if outcome_status else None,
                        "persisted_findings_delta": findings_delta,
                        "string_samples_delta": sample_delta,
                        "persistence_retry_count": (
                            outcome_status.persistence_retry_count if outcome_status else None
                        ),
                        "persistence_failed": (
                            bool(getattr(outcome_status, "persistence_failed", False))
                            if outcome_status is not None
                            else None
                        ),
                        "compat_export_failed": (
                            bool(getattr(outcome_status, "compat_export_failed", False))
                            if outcome_status is not None
                            else None
                        ),
                        "compat_export_stage": (
                            getattr(outcome_status, "compat_export_stage", None)
                            if outcome_status is not None
                            else None
                        ),
                    },
                )
                if outcome_status and not outcome_status.success:
                    canon_errs, persist_errs, compat_errs = collect_persistence_errors(
                        outcome_status=outcome_status
                    )
                    canonical_failures.extend(canon_errs)
                    persistence_errors.extend(persist_errs)
                    compat_export_errors.extend(compat_errs)
                    if app_result.static_run_id and persist_enabled:
                        finalize_static_run(
                            static_run_id=app_result.static_run_id,
                            status="FAILED",
                            ended_at_utc=ended_at_utc,
                            abort_reason="persist_error",
                            abort_signal=abort_signal,
                        )
                    issue_label = (
                        "compat export issue"
                        if compat_errs and not persist_errs and not canon_errs
                        else "persistence error"
                    )
                    warning = (
                        f"Aborting post-processing: {issue_label} "
                        f"(package={app_result.package_name})."
                    )
                    print(status_messages.status(warning, level="error"))
                    if "PERSISTENCE_ERROR" not in outcome.failures:
                        outcome.failures.append("PERSISTENCE_ERROR")
                    break
            except Exception as exc:
                warning = f"Failed to persist run summary for {app_result.package_name}: {exc}"
                print(status_messages.status(warning, level="warn"))
                _emit_static_persistence_event(
                    event=logging_events.PERSIST_APP,
                    message="Static persistence app failed",
                    params=params,
                    extra={
                        "package_name": app_result.package_name,
                        "app_label": app_result.app_label,
                        "app_index": index,
                        "app_total": total_results,
                        "static_run_id": app_result.static_run_id,
                        "error_class": exc.__class__.__name__,
                        "error_message": str(exc),
                    },
                )
                logging_engine.get_error_logger().exception(
                    "Run summary persistence failed",
                    extra=logging_engine.ensure_trace(
                        {
                            "event": "static.persist_run_summary_failed",
                            "package": app_result.package_name,
                            "session_stamp": params.session_stamp,
                            "static_run_id": app_result.static_run_id,
                        }
                    ),
                )
                persistence_errors.append(str(exc))
                if app_result.static_run_id and persist_enabled:
                    fail_status = "FAILED"
                    finalize_static_run(
                        static_run_id=app_result.static_run_id,
                        status=fail_status,
                        ended_at_utc=ended_at_utc,
                        abort_reason=exc.__class__.__name__,
                        abort_signal=abort_signal,
                    )
                failfast = (
                    "Aborting post-processing: persistence exception "
                    f"(package={app_result.package_name})."
                )
                print(status_messages.status(failfast, level="error"))
                if "PERSISTENCE_ERROR" not in outcome.failures:
                    outcome.failures.append("PERSISTENCE_ERROR")
                break

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
        if app_result.static_handoff_hash and isinstance(payload, dict):
            app_section = payload.get("app")
            if isinstance(app_section, dict):
                app_section["static_handoff_hash"] = app_result.static_handoff_hash
        if app_result.static_handoff_hash and isinstance(base_report.metadata, dict):
            base_report.metadata["static_handoff_hash"] = app_result.static_handoff_hash
        if persist_enabled and not app_result.static_run_id:
            warning = (
                "Aborting post-processing: missing static_run_id "
                f"(package={app_result.package_name})."
            )
            print(status_messages.status(warning, level="error"))
            persistence_errors.append("missing_static_run_id")
            if "PERSISTENCE_ERROR" not in outcome.failures:
                outcome.failures.append("PERSISTENCE_ERROR")
            break
        elif persist_enabled:
            consecutive_missing_run_ids = 0
        if persist_enabled and app_result.static_run_id:
            publication = publish_persisted_artifacts(
                base_report=base_report,
                payload=payload,
                package_name=app_result.package_name,
                static_run_id=app_result.static_run_id,
                profile=params.profile,
                scope=params.scope,
                report_path=Path(base_artifact.saved_path) if base_artifact and base_artifact.saved_path else None,
                paper_grade_requested=bool(params.paper_grade_requested),
                required_paper_artifacts=REQUIRED_PAPER_ARTIFACTS,
                ended_at_utc=ended_at_utc,
                abort_signal=abort_signal,
                write_baseline_json_fn=write_baseline_json,
                write_dynamic_plan_json_fn=write_dynamic_plan_json,
                governance_ready_fn=governance_ready,
                write_manifest_evidence_fn=write_manifest_evidence,
                build_artifact_registry_entries_fn=build_artifact_registry_entries,
                record_artifacts_fn=record_artifacts,
                prepare_required_artifacts_fn=export_dep_snapshot,
                run_sql_fn=core_q.run_sql,
                refresh_static_run_manifest_fn=refresh_static_run_manifest,
                finalize_static_run_fn=finalize_static_run,
            )
            saved_path = publication.saved_path
            dynamic_plan_path = publication.dynamic_plan_path
            persistence_errors.extend(publication.warnings)

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
            try:
                app_result.dynamic_plan_path = str(dynamic_plan_path)
            except Exception:
                app_result.dynamic_plan_path = None

        if (
            persist_enabled
            and app_result.static_run_id
            and publication is not None
            and publication.skip_remaining_processing
        ):
            continue

        if report_reference:
            report_reference_count += 1
            message = f"Report reference    → {report_reference}"
            if not compact_mode:
                _emit_detail(message)

        canonical_change = params.canonical_action in {"replace", "first_run"}
        if (
            canonical_change
            and not persistence_errors
            and params.session_label
            and len(outcome.results) == 1
            and (saved_path or dynamic_plan_path)
        ):
            alias_base = params.session_label
            run_notes.extend(
                update_static_aliases(
                    saved_path=saved_path,
                    dynamic_plan_path=dynamic_plan_path,
                    alias_base=alias_base,
                    canonical_action=params.canonical_action,
                    prior_canonical_id=view_model.session_meta.canonical_id,
                    static_run_id=app_result.static_run_id,
                )
            )

        if index < len(outcome.results) and not (compact_mode and large_compact_batch):
            _emit_detail("")

    permission_profiles = dedupe_profile_entries(permission_profiles)
    component_profiles = dedupe_profile_entries(component_profiles)
    secret_profiles = dedupe_profile_entries(secret_profiles)
    finding_profiles = dedupe_profile_entries(finding_profiles)
    trend_deltas = _bulk_trend_deltas(params.session_stamp, finding_totals_by_package)
    static_risk_rows = dedupe_profile_entries(static_risk_rows)
    _apply_display_names(permission_profiles)

    if run_notes and not interrupted_compact:
        print(status_messages.status("Run notes", level="info"))
        for note in run_notes:
            print(f"  - {note}")

        if persist_enabled and not interrupted_compact and not large_compact_batch:
            print("Accounting (raw vs normalized)")
            print(f"  Detector hits (raw):           {runtime_findings_total}")
            print(f"  Normalized findings (deduped): {normalized_findings_total}")
        print(f"  Baseline rule hits:          {baseline_rule_hits_total}")
        print(
            "  MASVS totals (severity across all detectors): "
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
                    f"baseline={baseline_written_count} "
                    f"baseline_noncanonical={noncanonical_baseline_written_count} "
                    f"plan={plan_written_count} "
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
                    "Status: FAILED (SIGINT) — counts may be partial",
                    level="warn",
                )
            )
    elif params.dry_run:
        print(
            status_messages.status(
                "findings (normalized) not persisted during dry run.",
                level="info",
            )
        )
    if not interrupted_compact and (persist_enabled or params.dry_run):
        render_static_interpretation_footer()
        print()

    session_stamp = params.session_stamp
    batch_or_noninteractive = bool(
        isinstance(run_ctx, StaticRunContext) and (run_ctx.batch or run_ctx.noninteractive)
    )
    postprocessing_failed = (
        bool(persistence_errors)
        or bool(compat_export_errors)
        or "PERSISTENCE_ERROR" in outcome.failures
    )
    if session_stamp and persist_enabled and not defer_persistence_footer:
        _emit_static_persistence_event(
            event=logging_events.PERSIST_END,
            message="Static persistence finished",
            params=params,
            extra={
                "applications": total_results,
                "findings_persisted_total": normalized_findings_total,
                "string_samples_persisted_total": string_samples_persisted_total,
                "persistence_error_count": len(list(dict.fromkeys(persistence_errors))),
                "canonical_failure_count": len(list(dict.fromkeys(canonical_failures))),
                "compat_export_error_count": len(list(dict.fromkeys(compat_export_errors))),
                "status": (
                    "failed"
                    if persistence_errors or canonical_failures or compat_export_errors
                    else "completed"
                ),
            },
        )
        if large_compact_batch:
            _render_compact_persistence_summary(
                params=params,
                total_results=total_results,
                normalized_findings_total=normalized_findings_total,
                string_samples_persisted_total=string_samples_persisted_total,
                baseline_written_count=baseline_written_count,
                plan_written_count=plan_written_count,
                report_reference_count=report_reference_count,
                persistence_errors=persistence_errors,
                canonical_failures=canonical_failures,
                compat_export_errors=compat_export_errors,
                run_status=run_status,
            )
        else:
            _render_persistence_footer(
                session_stamp,
                had_errors=bool(persistence_errors or compat_export_errors),
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
            if compat_export_errors:
                level = "warn"
                if params.verbose_output:
                    print(status_messages.status("Compat export issues detected:", level=level))
                    for message in compat_export_errors:
                        print(f"  - {message}")
                else:
                    preview_limit = 5
                    unique_errors = list(dict.fromkeys(compat_export_errors))
                    preview = unique_errors[:preview_limit]
                    remaining = len(unique_errors) - len(preview)
                    summary = ", ".join(preview)
                    if remaining > 0:
                        summary += f", +{remaining} more"
                    print(
                        status_messages.status(
                            f"Compat export issues: {len(unique_errors)} item(s) — {summary}",
                            level=level,
                        )
                    )
        if outcome.results:
            _persist_cohort_rollup(session_stamp, params.scope_label)

    if defer_post_run_menu:
        outcome.deferred_diagnostics = {
            "permission_profiles": list(permission_profiles),
            "component_profiles": list(component_profiles),
            "masvs_matrix": dict(masvs_matrix),
            "static_risk_rows": list(static_risk_rows),
            "secret_profiles": list(secret_profiles),
            "finding_profiles": list(finding_profiles),
            "trend_deltas": list(trend_deltas),
            "persist_enabled": persist_enabled,
            "compact_mode": compact_mode,
        }

    if not params.dry_run and not defer_post_run_menu:
        print()
        if outcome.aborted or batch_or_noninteractive or postprocessing_failed:
            show_details = False
            if postprocessing_failed:
                outcome.return_to_main_menu = True
        else:
            print("Post-run diagnostics")
            print("--------------------")
            print("[1] Open diagnostics menu")
            print("[2] Return to main menu")
            default_choice = "2"
            resp = prompt_utils.prompt_text(
                "Choice",
                default=default_choice,
                required=False,
            ).strip()
            if resp in {"1"}:
                show_details = True
            else:
                show_details = False
                outcome.return_to_main_menu = True

    if show_details:
        for line in detail_output.compact_lines():
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
            print(status_messages.status(failure_message, level="warn"))
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
                    "Per-app pipeline diagnostics hidden in default output. "
                    "Re-run with --verbose-output for full reports.",
                    level="info",
                )
            )
        if params.dry_run:
            grouped_warnings = _group_diagnostic_warnings(diagnostic_warnings)
            if grouped_warnings:
                print("\nTop warnings/anomalies")
                for line in grouped_warnings[:5]:
                    print(status_messages.status(line, level="warn"))
            actionable: list[str] = []
            pipeline_version = getattr(params, "analysis_version", None)
            guard_ok, guard_detail = _schema_guard_status()
            guard_label = f"Schema guard: {'OK' if guard_ok else 'FAIL'}"
            if guard_detail:
                guard_label += f" ({guard_detail})"
            print("\n" + guard_label)
            identity_ok = all(app.identity_valid for app in outcome.results)
            linkage_ok = all(state.startswith("VALID") for state in linkage_states) if linkage_states else False
            print("\nDYNAMIC-READY CHECKS (diagnostic)")
            print(f"{'OK' if pipeline_version else 'FAIL'} pipeline_version present")
            print(f"{'OK' if linkage_ok else 'FAIL'} linkage resolvable (run_map/session links)")
            if not linkage_ok:
                print("    Fix: ensure run_map.json is written or static_session_run_links rows exist.")
                actionable.append("Ensure run_map.json is written or session links exist (rerun Run Static Pipeline (Full) once).")
            print(f"{'OK' if identity_ok else 'FAIL'} identity valid (artifact_set_hash computed)")
            ready = pipeline_version and linkage_ok and identity_ok
            print(f"Result: {'READY' if ready else 'NOT READY'}")
            run_signature_ok = all(bool(app.run_signature) for app in outcome.results)
            artifact_set_ok = all(bool(app.artifact_set_hash) for app in outcome.results)
            print("\nPLAN PROVENANCE (preview)")
            for line in _plan_provenance_lines(run_id_states, run_signature_ok, artifact_set_ok):
                print(line)
            if not pipeline_version:
                actionable.append("Set analysis_version to enable linkage checks.")
            if not identity_ok:
                actionable.append("Identity invalid: verify artifact_set_hash/run_signature generation and rerun.")
            if run_id_states and not all(run_id_states):
                actionable.append("Run a persisting scan to establish static_run_id for plan provenance.")
            if grouped_warnings:
                if any("run_map" in line or "static_run_id/pipeline_version" in line for line in grouped_warnings):
                    actionable.append("Rebuild run_map.json (missing static_run_id/pipeline_version).")
            if actionable:
                print("\nActionable fixes")
                for item in actionable[:5]:
                    print(f"  - {item}")
            if session_stamp:
                try:
                    report_dir = Path("evidence") / "diagnostics"
                    report_dir.mkdir(parents=True, exist_ok=True)
                    report_path = report_dir / f"{session_stamp}.json"
                    report_payload = {
                        "session": session_stamp,
                        "package_count": len(outcome.results),
                        "schema_guard_ok": guard_ok,
                        "schema_guard_detail": guard_detail,
                        "pipeline_version": pipeline_version or None,
                        "identity_ok": identity_ok,
                        "linkage_ok": linkage_ok,
                        "run_id_ok": all(run_id_states) if run_id_states else False,
                        "dynamic_ready": bool(ready),
                        "warnings": grouped_warnings,
                        "actionable_fixes": actionable[:5],
                        "generated_at_utc": datetime.now(UTC)
                        .isoformat()
                        .replace("+00:00", "Z"),
                    }
                    report_path.write_text(
                        json.dumps(report_payload, indent=2, sort_keys=True, default=str),
                        encoding="utf-8",
                    )
                    print(
                        status_messages.status(
                            f"Diagnostic report saved: {report_path}",
                            level="info",
                        )
                    )
                except Exception as exc:
                    print(
                        status_messages.status(
                            f"Failed to write diagnostic report: {exc}",
                            level="warn",
                        )
                    )
        if not params.dry_run:
            render_post_run_diagnostics_menu(
                outcome=outcome,
                params=params,
                permission_profiles=permission_profiles,
                component_profiles=component_profiles,
                masvs_matrix=masvs_matrix,
                static_risk_rows=static_risk_rows,
                secret_profiles=secret_profiles,
                finding_profiles=finding_profiles,
                trend_deltas=trend_deltas,
                persist_enabled=persist_enabled,
                compact_mode=compact_mode,
            )

    if persistence_errors and not params.dry_run:
        if not any("persistence" in str(item).lower() for item in outcome.failures):
            outcome.failures.append("persistence_failed")

    if not params.dry_run:
        outcome.persistence_failed = bool(persistence_errors)
        outcome.compat_export_failed = bool(compat_export_errors)
        outcome.canonical_failed = bool(canonical_failures)
        if outcome.persistence_failed or outcome.canonical_failed or outcome.compat_export_failed:
            outcome.paper_grade_status = "fail"
        elif outcome.aborted:
            outcome.paper_grade_status = "warn"
        else:
            outcome.paper_grade_status = "ok"
        audit_notes: list[dict[str, str]] = []
        for message in persistence_errors:
            audit_notes.append({"code": "persistence_error", "message": str(message)})
        for message in compat_export_errors:
            audit_notes.append({"code": "compat_export_error", "message": str(message)})
        for message in canonical_failures:
            audit_notes.append({"code": "canonical_error", "message": str(message)})
        outcome.audit_notes = audit_notes

    if outcome.results:
        from .run_health import (
            attach_run_health_outputs_on_document,
            build_run_health_document,
            compact_run_health_stdout_line,
            compute_run_aggregate_status,
            reconcile_app_final_status_after_persistence,
            sanitize_session_stamp_for_filename,
            write_run_health_json,
        )

        for res in outcome.results:
            reconcile_app_final_status_after_persistence(res, persistence_enabled=bool(persist_enabled))
        outcome.run_aggregate_status = compute_run_aggregate_status(outcome)

        health_doc = build_run_health_document(
            outcome,
            params,
            persistence_enabled=bool(persist_enabled),
            persist_attempted=bool(persist_enabled and not params.dry_run),
        )
        health_doc["final_run_status"] = outcome.run_aggregate_status or health_doc.get("final_run_status")
        stamp_name = sanitize_session_stamp_for_filename(getattr(params, "session_stamp", None))
        health_target = outcome.base_dir / f"{stamp_name}_run_health.json"
        attach_run_health_outputs_on_document(
            health_doc,
            path=health_target.resolve(),
            base_dir=outcome.base_dir.resolve(),
        )
        try:
            write_run_health_json(health_target, health_doc)
            outcome.run_health_json_path = str(health_target)
        except OSError as exc:
            print(status_messages.status(f"Run health JSON could not be written ({exc}).", level="warn"))

        quiet_batch_out = isinstance(run_ctx, StaticRunContext) and run_ctx.quiet and run_ctx.batch
        if not quiet_batch_out:
            print()
            print(status_messages.status(compact_run_health_stdout_line(health_doc), level="info"))

    if outcome.aborted:
        completed = outcome.completed_artifacts
        total = outcome.total_artifacts
        completion = f"{completed}/{total}" if total else str(completed)
        reason_token = abort_reason or abort_signal or "SIGINT"
        static_ids = [res.static_run_id for res in outcome.results if res.static_run_id]
        static_hint = f" static_run_id={static_ids[-1]}" if static_ids else ""
        footer = [
            "────────────────────────────────────────────────────────",
            "STATIC ANALYSIS — FAILED",
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

    has_persisted_run_id = any(getattr(app, "static_run_id", None) for app in outcome.results)
    if (
        persist_enabled
        and outcome.results
        and has_persisted_run_id
        and not outcome.aborted
        and not outcome.return_to_main_menu
        and not large_compact_batch
    ):
        _render_db_masvs_summary()

def prompt_deferred_post_run_diagnostics(outcome: RunOutcome, params: RunParameters) -> None:
    payload = outcome.deferred_diagnostics or {}
    if params.dry_run or not payload:
        return
    print()
    if outcome.aborted:
        outcome.return_to_main_menu = True
        return
    print("Post-run diagnostics")
    print("--------------------")
    print("[1] Open diagnostics menu")
    print("[2] Return to main menu")
    default_choice = "2"
    resp = prompt_utils.prompt_text(
        "Choice",
        default=default_choice,
        required=False,
    ).strip()
    if resp not in {"1"}:
        outcome.return_to_main_menu = True
        return
    render_post_run_diagnostics_menu(
        outcome=outcome,
        params=params,
        permission_profiles=payload.get("permission_profiles", []),
        component_profiles=payload.get("component_profiles", []),
        masvs_matrix=payload.get("masvs_matrix", {}),
        static_risk_rows=payload.get("static_risk_rows", []),
        secret_profiles=payload.get("secret_profiles", []),
        finding_profiles=payload.get("finding_profiles", []),
        trend_deltas=payload.get("trend_deltas", []),
        persist_enabled=bool(payload.get("persist_enabled", False)),
        compact_mode=bool(payload.get("compact_mode", False)),
    )
    outcome.deferred_diagnostics = {}


__all__ = ["prompt_deferred_post_run_diagnostics", "render_run_results"]
