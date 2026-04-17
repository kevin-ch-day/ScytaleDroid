"""Result rendering helpers for static analysis CLI."""

from __future__ import annotations

import json
import os
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
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
from scytaledroid.Utils.LoggingUtils import logging_engine

from ...engine.strings import analyse_strings
from ...persistence.ingest import ingest_baseline_payload
from ..core.models import RunOutcome, RunParameters
from ..core.run_context import StaticRunContext
from ..core.run_lifecycle import finalize_static_run
from ..core.run_persistence import persist_run_summary, update_static_run_status
from ..persistence.run_summary import refresh_static_run_manifest
from ..views.run_detail_view import (
    SEVERITY_TOKEN_ORDER,
    app_detail_loop,
    render_app_detail,
)
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
from .results_formatters import _format_highlight_tokens
from .results_persistence import (
    apply_persistence_outcome,
    collect_persistence_errors,
    merge_persistence_metadata,
)
from .results_persist import _build_ingest_payload, _persist_cohort_rollup
from .run_db_queries import _apply_display_names
from .scan_flow import format_duration
from .string_analysis_payload import analyse_string_payload, empty_string_analysis_payload
from .view import DetailBuffer

# Back-compat: tests and older callers patch these names.
_REQUIRED_PAPER_ARTIFACTS = REQUIRED_PAPER_ARTIFACTS


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
        session_note = f"Session: {session_meta.session_label}"
        if session_meta.canonical_id or session_meta.latest_id:
            parts: list[str] = []
            if session_meta.canonical_id:
                parts.append(f"canonical: {session_meta.canonical_id}")
            if session_meta.latest_id:
                parts.append(f"latest: {session_meta.latest_id}")
            if session_meta.attempts is not None:
                parts.append(f"attempts: {session_meta.attempts}")
            session_note += f" ({', '.join(parts)})"
        subtitle_parts.append(session_note)

    grade_label = "CANONICAL_GRADE"
    grade_reasons: list[str] = []
    if not params.dry_run:
        if not bool(params.persistence_ready):
            grade_label = "EXPERIMENTAL"
            grade_reasons.append("persistence gate failed")
        if outcome.failures:
            grade_label = "EXPERIMENTAL"
            grade_reasons.append("run failures present")
    grade_text = f"Grade: {grade_label}"
    if grade_reasons:
        grade_text += f" ({'; '.join(grade_reasons)})"
    footer = f"{grade_text}  |  Use the prompts below to drill into per-app findings."

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


def _format_counter_value(value: object) -> str:
    return "—" if value is None else str(value)


def _render_static_output_context(context: Mapping[str, object]) -> None:
    acquisition = context.get("acquisition") if isinstance(context.get("acquisition"), Mapping) else {}
    print("Stage Context")
    print("-------------")
    print("Stage           : Static Analysis")
    print("Purpose         : Analyze harvested APK artifacts only")
    print(f"Session ID      : {context.get('session_id') or 'n/a'}")
    print(f"Device serial   : {context.get('device_serial') or 'n/a'}")
    print(f"Inventory snap  : {_format_counter_value(context.get('snapshot_id'))}")
    print(f"Scope analyzed  : {context.get('scope_analyzed') or 'n/a'}")
    print(f"Mode            : {context.get('mode_label') or 'n/a'}")
    print(f"Analyzed apps   : {_format_counter_value(context.get('analyzed_apps'))}")
    print(f"Artifacts       : {_format_counter_value(context.get('observed_artifacts'))}")
    print()
    print("Acquisition Counters")
    print("--------------------")
    ordered_keys = (
        ("Inventoried", "inventoried"),
        ("In scope", "in_scope"),
        ("Policy eligible", "policy_eligible"),
        ("Scheduled", "scheduled"),
        ("Harvested", "harvested"),
        ("Persisted", "persisted"),
        ("Blocked policy", "blocked_policy"),
        ("Blocked scope", "blocked_scope"),
    )
    for label, key in ordered_keys:
        print(f"{label:<16}: {_format_counter_value(acquisition.get(key))}")
    print("Note            : Static analysis only uses harvested/persisted artifacts.")
    print()
    print("Device reality")
    print("--------------")
    print(f"Total inventoried packages : {_format_counter_value(acquisition.get('inventoried'))}")
    print()
    print("Acquired for analysis")
    print("---------------------")
    print(f"Harvested packages        : {_format_counter_value(acquisition.get('harvested'))}")
    print(f"Persisted packages        : {_format_counter_value(acquisition.get('persisted'))}")
    print(f"Analyzed applications     : {_format_counter_value(context.get('analyzed_apps'))}")
    print(f"Analyzed artifacts        : {_format_counter_value(context.get('observed_artifacts'))}")
    print()
    print("Not analyzed")
    print("------------")
    print(f"Blocked by policy         : {_format_counter_value(acquisition.get('blocked_policy'))}")
    print(f"Blocked by scope          : {_format_counter_value(acquisition.get('blocked_scope'))}")
    print()


def _render_artifact_completeness(
    *,
    planned_artifacts: int,
    observed_artifacts: int,
) -> None:
    planned = max(int(planned_artifacts or 0), 0)
    observed = max(int(observed_artifacts or 0), 0)
    completeness_pct = int(round((observed / planned) * 100.0)) if planned else 0
    drift_label = "none" if planned == observed else f"planned={planned} observed={observed}"
    print("Artifact Completeness")
    print("---------------------")
    print(f"Planned artifacts  : {planned}")
    print(f"Observed artifacts : {observed}")
    print(f"Completeness       : {observed}/{planned} ({completeness_pct}%)")
    print(f"Drift              : {drift_label}")
    print()


def _render_static_interpretation_footer() -> None:
    print("Interpretation")
    print("--------------")
    print("This static analysis applies to harvested APK artifacts only.")
    print("Blocked or unreadable packages were not statically analyzed here.")
    print("Composite grades summarize static structural exposure, not runtime behavior.")
    print()


def write_baseline_json(payload: dict[str, object], *, package: str, profile: str, scope: str) -> Path:
    """Write the baseline JSON artifact.

    This wrapper exists to keep a stable patch point for tests and legacy code.
    """
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
    """Build and write the dynamic plan JSON artifact.

    This wrapper exists to keep a stable patch point for tests and legacy code.
    """
    return build_dynamic_plan_artifact(
        base_report,
        payload,
        package_name=package,
        profile=profile,
        scope=scope,
        static_run_id=static_run_id,
    )


def _empty_string_analysis_payload(*, warning: str | None = None) -> Mapping[str, object]:
    return empty_string_analysis_payload(warning=warning)


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
            )
        return

    _render_run_results_impl(
        outcome,
        params,
        run_ctx=run_ctx,
        defer_persistence_footer=defer_persistence_footer,
    )


def _render_run_results_impl(
    outcome: RunOutcome,
    params: RunParameters,
    *,
    run_ctx: StaticRunContext | None,
    defer_persistence_footer: bool,
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
    print(
        summary_cards.format_summary_card(
            view_model.title,
            view_model.overview_items,
            subtitle=view_model.subtitle,
            footer=view_model.footer,
            width=90,
        )
    )
    _render_static_output_context(view_model.static_output_context)
    _render_artifact_completeness(
        planned_artifacts=view_model.planned_artifacts,
        observed_artifacts=view_model.observed_artifacts,
    )
    if view_model.version_line:
        print(
            status_messages.status(
                view_model.version_line,
                level="info",
            )
        )
    show_details = True
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
                                FROM findings
                                WHERE static_run_id=%s
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
    example_provider = None
    example_provider_package = None
    for app_result in outcome.results:
        base_report = app_result.base_report()
        if base_report is None:
            continue
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

    highlight_tokens = _format_highlight_tokens(
        highlight_stats,
        totals,
        len(outcome.results),
    )
    if highlight_tokens:
        print(status_messages.highlight("; ".join(highlight_tokens), show_icon=True))
    if p0_count and example_provider:
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

    for index, app_result in enumerate(outcome.results, start=1):
        if persist_enabled and compact_mode:
            if detailed_finalization_logs:
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
                if outcome_status and not outcome_status.success:
                    canon_errs, persist_errs = collect_persistence_errors(
                        outcome_status=outcome_status
                    )
                    canonical_failures.extend(canon_errs)
                    persistence_errors.extend(persist_errs)
                    if app_result.static_run_id and persist_enabled:
                        finalize_static_run(
                            static_run_id=app_result.static_run_id,
                            status="FAILED",
                            ended_at_utc=ended_at_utc,
                            abort_reason="persist_error",
                            abort_signal=abort_signal,
                        )
                    warning = (
                        "Aborting post-processing: persistence error "
                        f"(package={app_result.package_name})."
                    )
                    print(status_messages.status(warning, level="error"))
                    if "PERSISTENCE_ERROR" not in outcome.failures:
                        outcome.failures.append("PERSISTENCE_ERROR")
                    break
            except Exception as exc:
                warning = f"Failed to persist run summary for {app_result.package_name}: {exc}"
                print(status_messages.status(warning, level="warn"))
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

        if index < len(outcome.results):
            _emit_detail("")

    permission_profiles = _dedupe_profile_entries(permission_profiles)
    component_profiles = _dedupe_profile_entries(component_profiles)
    secret_profiles = _dedupe_profile_entries(secret_profiles)
    finding_profiles = _dedupe_profile_entries(finding_profiles)
    trend_deltas = _bulk_trend_deltas(params.session_stamp, finding_totals_by_package)
    static_risk_rows = _dedupe_profile_entries(static_risk_rows)
    _apply_display_names(permission_profiles)

    if run_notes:
        print(status_messages.status("Run notes", level="info"))
        for note in run_notes:
            print(f"  - {note}")

    if persist_enabled:
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
    else:
        print(
            status_messages.status(
                "findings (normalized) not persisted during dry run.",
                level="info",
            )
        )
    _render_static_interpretation_footer()
    print()

    session_stamp = params.session_stamp
    if not params.dry_run:
        print()
        if isinstance(run_ctx, StaticRunContext) and (run_ctx.batch or run_ctx.noninteractive):
            # Batch/noninteractive runs must not block on UI prompts.
            show_details = False
        else:
            print("Next view")
            print("---------")
            print("[1] Continue to tables/diagnostics")
            print("[2] Return to main menu")
            resp = prompt_utils.prompt_text("Choice", default="1", required=False).strip()
            if resp in {"2", "0"}:
                show_details = False

    if show_details:
        for line in detail_output.lines:
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
        if session_stamp and persist_enabled and not defer_persistence_footer:
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
        if not params.verbose_output and params.scope in {"all", "profile"}:
            _render_bucketed_session_summary(
                outcome=outcome,
                params=params,
                runtime_findings_total=runtime_findings_total,
                persistence_errors=persistence_errors,
            )

        _render_post_run_views(
            permission_profiles,
            masvs_matrix,
            static_risk_rows,
            scope_label=params.scope_label,
            snapshot_at=outcome.finished_at,
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
        # Frozen run context governs whether we can prompt for details.
        batch_or_noninteractive = bool(
            isinstance(run_ctx, StaticRunContext) and (run_ctx.batch or run_ctx.noninteractive)
        )
        if (
            params.verbose_output
            and len(outcome.results) <= 5
            and not batch_or_noninteractive
        ):
            _interactive_detail_loop(outcome, params, run_ctx=run_ctx)

    if persistence_errors and not params.dry_run:
        if not any("persistence" in str(item).lower() for item in outcome.failures):
            outcome.failures.append("persistence_failed")

    if not params.dry_run:
        outcome.persistence_failed = bool(persistence_errors)
        outcome.canonical_failed = bool(canonical_failures)
        if outcome.persistence_failed or outcome.canonical_failed:
            outcome.paper_grade_status = "fail"
        elif outcome.aborted:
            outcome.paper_grade_status = "warn"
        else:
            outcome.paper_grade_status = "ok"
        audit_notes: list[dict[str, str]] = []
        for message in persistence_errors:
            audit_notes.append({"code": "persistence_error", "message": str(message)})
        for message in canonical_failures:
            audit_notes.append({"code": "canonical_error", "message": str(message)})
        outcome.audit_notes = audit_notes

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
    if persist_enabled and outcome.results and has_persisted_run_id:
        _render_db_masvs_summary()


def _interactive_detail_loop(outcome: RunOutcome, params: RunParameters, *, run_ctx: StaticRunContext | None) -> None:
    if isinstance(run_ctx, StaticRunContext) and (run_ctx.batch or run_ctx.noninteractive):
        return
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


def _summarize_app_pipeline_for_results(app_result: object) -> dict[str, int]:
    ok = warn = fail = error = 0
    finding_fail = policy_fail = 0
    p0 = p1 = p2 = note = 0
    for artifact in getattr(app_result, "artifacts", []) or []:
        report = getattr(artifact, "report", None)
        metadata = getattr(report, "metadata", None)
        if not isinstance(metadata, Mapping):
            continue
        summary = metadata.get("pipeline_summary")
        if not isinstance(summary, Mapping):
            continue
        status_counts = summary.get("status_counts")
        if isinstance(status_counts, Mapping):
            ok += int(status_counts.get("OK", 0) or 0)
            warn += int(status_counts.get("WARN", 0) or 0)
        finding_fail += int(summary.get("finding_fail_count", 0) or 0)
        policy_fail += int(summary.get("policy_fail_count", 0) or 0)
        fail += int(summary.get("finding_fail_count", 0) or 0) + int(summary.get("policy_fail_count", 0) or 0)
        error += int(summary.get("error_count", 0) or 0)
        sev = summary.get("severity_counts")
        if isinstance(sev, Mapping):
            p0 += int(sev.get("P0", 0) or 0)
            p1 += int(sev.get("P1", 0) or 0)
            p2 += int(sev.get("P2", 0) or 0)
            note += int(sev.get("NOTE", 0) or 0)
    return {
        "ok": ok,
        "warn": warn,
        "fail": fail,
        "finding_fail": finding_fail,
        "policy_fail": policy_fail,
        "error": error,
        "p0": p0,
        "p1": p1,
        "p2": p2,
        "note": note,
    }


def _collect_app_error_detectors(app_result: object) -> list[tuple[str, str]]:
    """Return (detector, reason) tuples for pipeline execution errors."""
    out: list[tuple[str, str]] = []
    for artifact in getattr(app_result, "artifacts", []) or []:
        report = getattr(artifact, "report", None)
        metadata = getattr(report, "metadata", None)
        if not isinstance(metadata, Mapping):
            continue
        summary = metadata.get("pipeline_summary")
        if not isinstance(summary, Mapping):
            continue
        payload = summary.get("error_detectors")
        if not isinstance(payload, Sequence):
            continue
        for entry in payload:
            if not isinstance(entry, Mapping):
                continue
            detector = str(entry.get("detector") or entry.get("section") or "").strip()
            reason = str(entry.get("reason") or "").strip()
            if detector:
                out.append((detector, reason))
    return out


def _render_bucketed_session_summary(
    *,
    outcome: RunOutcome,
    params: RunParameters,
    runtime_findings_total: int,
    persistence_errors: Sequence[str],
) -> None:
    apps_total = len(outcome.results)
    artifacts_total = int(outcome.total_artifacts or sum(len(app.artifacts) for app in outcome.results))
    session_label = params.session_stamp or params.session_label or "unspecified"
    print()
    print(f"Session {session_label} Summary")
    print(f"Apps: {apps_total} • Artifacts: {artifacts_total} • Detector hits (raw): {runtime_findings_total}")

    rows: list[dict[str, object]] = []
    for app in outcome.results:
        counters = _summarize_app_pipeline_for_results(app)
        rows.append(
            {
                "package": app.package_name,
                "label": app.app_label or app.package_name,
                "artifacts": int(getattr(app, "discovered_artifacts", 0) or len(getattr(app, "artifacts", []) or [])),
                "duration_seconds": float(getattr(app, "duration_seconds", 0.0) or 0.0),
                "static_run_id": getattr(app, "static_run_id", None),
                **counters,
            }
        )

    execution_errors = [row for row in rows if int(row["error"]) > 0]
    if execution_errors:
        print()
        print(f"EXECUTION ERRORS ({len(execution_errors)})")
        for row in sorted(execution_errors, key=lambda r: (int(r["error"]), int(r["fail"])), reverse=True)[:10]:
            print(
                f"- {row['package']}: error={row['error']} fail={row['fail']} "
                f"(P0={row['p0']} P1={row['p1']} P2={row['p2']})"
            )
        detector_counts: Counter[str] = Counter()
        detector_reasons: dict[str, str] = {}
        for app in outcome.results:
            for detector, reason in _collect_app_error_detectors(app):
                detector_counts[detector] += 1
                if reason and detector not in detector_reasons:
                    detector_reasons[detector] = reason
        if detector_counts:
            print()
            print("TOP EXECUTION ERROR DETECTORS")
            for detector, count in detector_counts.most_common(5):
                reason = detector_reasons.get(detector, "")
                line = f"- {detector}: {count}"
                if reason:
                    line += f" (example: {reason[:120]})"
                print(line)

    check_fails = [row for row in rows if int(row["fail"]) > 0]
    if check_fails:
        print()
        print(f"CHECK FAILS (policy/finding) ({len(check_fails)})")
        for row in sorted(check_fails, key=lambda r: (int(r["fail"]), int(r["p0"])), reverse=True)[:10]:
            print(
                f"- {row['package']}: fail={row['fail']} "
                f"(policy={row['policy_fail']} finding={row['finding_fail']})"
            )

    p0_rows = [row for row in rows if int(row["p0"]) > 0]
    if p0_rows:
        print()
        print("P0 APPS (top)")
        for row in sorted(p0_rows, key=lambda r: (int(r["p0"]), int(r["p1"])), reverse=True)[:10]:
            print(f"- {row['package']} (P0={row['p0']}, P1={row['p1']}, P2={row['p2']})")

    outliers = [row for row in rows if int(row["artifacts"]) > 20]
    if outliers:
        print()
        print("OUTLIERS")
        for row in sorted(outliers, key=lambda r: int(r["artifacts"]), reverse=True)[:10]:
            print(
                f"- {row['package']}: artifacts={row['artifacts']} "
                f"time={format_duration(float(row['duration_seconds']))}"
            )

    missing_run_ids = [row for row in rows if not row.get("static_run_id")]
    if persistence_errors or missing_run_ids:
        print()
        print(
            "PERSISTENCE "
            f"(missing_run_id={len(missing_run_ids)} issues={len(list(dict.fromkeys(str(x) for x in persistence_errors)))})"
        )
        for row in missing_run_ids[:5]:
            print(f"- missing run_id: {row['package']}")

    print()
    print("Next actions")
    print("- D in selection prompt: inspect capture distribution/outliers")
    print("- View options → 1: summary details for top failing apps")
    print("- Database tools → 12: audit static risk coverage gaps")


__all__ = ["render_run_results"]
