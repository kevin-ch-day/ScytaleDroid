"""Rendering helpers for static analysis CLI results sections."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import prompt_utils, status_messages
from scytaledroid.Utils.evidence_store import filesystem_safe_slug

from ..core.models import RunOutcome, RunParameters
from .output_mode import compact_success_output_enabled


def _format_counter_value(value: object) -> str:
    return "—" if value is None else str(value)


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value or default)
    except Exception:
        return default


def _print_heading(title: str, underline: str = "-") -> None:
    print(title)
    print(underline * len(title))


def render_static_output_context(context: Mapping[str, object]) -> None:
    """Render static-analysis run context.

    Normal mode uses a compact summary. Verbose mode keeps the older expanded
    Stage Context / Acquisition Counters output.
    """
    acquisition = context.get("acquisition") if isinstance(context.get("acquisition"), Mapping) else {}

    if compact_success_output_enabled():
        _print_heading("Run Context")
        print(f"Session  : {context.get('session_id') or 'n/a'}")
        print(f"Device   : {context.get('device_serial') or 'n/a'}")
        print(f"Scope    : {context.get('scope_analyzed') or 'n/a'}")
        print(f"Mode     : {context.get('mode_label') or 'n/a'}")
        print(
            "Analyzed : "
            f"{_format_counter_value(context.get('analyzed_apps'))} app(s), "
            f"{_format_counter_value(context.get('observed_artifacts'))} artifact(s)"
        )
        print(
            "Harvest  : "
            f"{_format_counter_value(acquisition.get('harvested'))} harvested, "
            f"{_format_counter_value(acquisition.get('persisted'))} persisted"
        )
        blocked_policy = acquisition.get("blocked_policy")
        blocked_scope = acquisition.get("blocked_scope")
        if blocked_policy or blocked_scope:
            print(
                "Blocked  : "
                f"policy={_format_counter_value(blocked_policy)} "
                f"scope={_format_counter_value(blocked_scope)}"
            )
        print()
        return

    _print_heading("Stage Context")
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

    _print_heading("Acquisition Counters")
    ordered_keys = (
        ("Inventoried", "inventoried"),
        ("In scope", "in_scope"),
        ("Policy eligible", "policy_eligible"),
        ("Scheduled", "scheduled"),
        ("Harvested", "harvested"),
        ("Harvest persisted", "persisted"),
        ("Blocked policy", "blocked_policy"),
        ("Blocked scope", "blocked_scope"),
    )
    for label, key in ordered_keys:
        print(f"{label:<16}: {_format_counter_value(acquisition.get(key))}")
    print("Note            : Static analysis only uses harvested/persisted artifacts.")
    print()

    _print_heading("Device reality")
    print(f"Total inventoried packages : {_format_counter_value(acquisition.get('inventoried'))}")
    print()

    _print_heading("Acquired for analysis")
    print(f"Harvested packages        : {_format_counter_value(acquisition.get('harvested'))}")
    print(f"Harvest persisted packages: {_format_counter_value(acquisition.get('persisted'))}")
    print(f"Analyzed applications     : {_format_counter_value(context.get('analyzed_apps'))}")
    print(f"Analyzed artifacts        : {_format_counter_value(context.get('observed_artifacts'))}")
    print()

    _print_heading("Not analyzed")
    print(f"Blocked by policy         : {_format_counter_value(acquisition.get('blocked_policy'))}")
    print(f"Blocked by scope          : {_format_counter_value(acquisition.get('blocked_scope'))}")
    print()


def render_static_output_context_compact(
    context: Mapping[str, object],
    *,
    planned_artifacts: int,
    observed_artifacts: int,
) -> None:
    acquisition = context.get("acquisition") if isinstance(context.get("acquisition"), Mapping) else {}
    analyzed_apps = _format_counter_value(context.get("analyzed_apps"))
    inventory = _format_counter_value(context.get("snapshot_id"))
    inventoried = _format_counter_value(acquisition.get("inventoried"))
    blocked_policy = _format_counter_value(acquisition.get("blocked_policy"))
    blocked_scope = _format_counter_value(acquisition.get("blocked_scope"))

    _print_heading("Batch Context")
    print(f"Session       : {context.get('session_id') or 'n/a'}")
    print(f"Device        : {context.get('device_serial') or 'n/a'}")
    print(f"Inventory     : snapshot {inventory} | inventoried={inventoried}")
    print(f"Scope         : {context.get('scope_analyzed') or 'n/a'}")
    print(f"Mode          : {context.get('mode_label') or 'n/a'}")
    print(
        "Analyzed      : "
        f"{analyzed_apps} apps | {observed_artifacts}/{max(int(planned_artifacts or 0), 0)} artifacts"
    )
    print(f"Blocked       : policy={blocked_policy} scope={blocked_scope}")
    print()


def render_session_meta_details(session_meta: object) -> None:
    attempts = getattr(session_meta, "attempts", None)
    canonical_id = getattr(session_meta, "canonical_id", None)
    latest_id = getattr(session_meta, "latest_id", None)

    if not (attempts is not None or canonical_id is not None or latest_id is not None):
        return

    if compact_success_output_enabled():
        parts: list[str] = []
        if latest_id is not None:
            parts.append(f"latest_static_run_id={latest_id}")
        if canonical_id is not None:
            parts.append(f"canonical_static_run_id={canonical_id}")
        if attempts is not None:
            parts.append(f"apps_attempted={attempts}")
        if parts:
            print("Run Identity: " + " | ".join(parts))
            print()
        return

    _print_heading("Run Identity")
    if attempts is not None:
        print(f"Apps attempted         : {attempts}")
        print(f"Canonical runs finalized: {attempts}")
    if latest_id is not None:
        print(f"Latest static run id   : {latest_id}")
    if canonical_id is not None:
        print(f"Session baseline id    : {canonical_id}")
    print()


def render_artifact_completeness(
    *,
    planned_artifacts: int,
    observed_artifacts: int,
) -> None:
    planned = max(_safe_int(planned_artifacts), 0)
    observed = max(_safe_int(observed_artifacts), 0)
    completeness_pct = int(round((observed / planned) * 100.0)) if planned else 0
    drift_label = "none" if planned == observed else f"planned={planned} observed={observed}"

    if compact_success_output_enabled():
        suffix = "" if planned == observed else f" ({drift_label})"
        print(f"Artifacts: {observed}/{planned} complete ({completeness_pct}%){suffix}")
        print()
        return

    _print_heading("Artifact Completeness")
    print(f"Planned artifacts  : {planned}")
    print(f"Observed artifacts : {observed}")
    print(f"Completeness       : {observed}/{planned} ({completeness_pct}%)")
    print(f"Drift              : {drift_label}")
    print()


def render_static_interpretation_footer() -> None:
    if compact_success_output_enabled():
        return

    _print_heading("Interpretation")
    print("This static analysis applies to harvested APK artifacts only.")
    print("Blocked or unreadable packages were not statically analyzed here.")
    print("Composite grades summarize static structural exposure, not runtime behavior.")
    print()


def _resolve_persistence_audit_path(session_stamp: str | None) -> Path | None:
    stamp = str(session_stamp or "").strip()
    if not stamp:
        return None

    base = Path("output") / "audit" / "persistence"
    candidates = (
        base / f"{stamp}_persistence_audit.json",
        base / f"{stamp}_missing_run_ids.json",
    )
    return next((path for path in candidates if path.exists()), None)


def _resolve_permission_snapshot_path(session_stamp: str | None) -> Path | None:
    stamp = str(session_stamp or "").strip()
    if not stamp:
        return None

    snapshot_id = f"perm-audit:app:{stamp}"
    candidate = Path("data") / "audit" / filesystem_safe_slug(snapshot_id) / "snapshot.json"
    return candidate if candidate.exists() else None


def _mapping_section(payload: Mapping[str, object], key: str) -> Mapping[str, object]:
    section = payload.get(key)
    return section if isinstance(section, Mapping) else {}


def render_persistence_audit_summary_section(session_stamp: str | None) -> None:
    path = _resolve_persistence_audit_path(session_stamp)
    if path is None:
        print(status_messages.status("Persistence audit artifact not found.", level="warn"))
        return

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(status_messages.status(f"Failed to read persistence audit: {exc}", level="warn"))
        return

    summary = _mapping_section(payload, "summary")
    outcome_summary = _mapping_section(summary, "outcome")
    canonical = _mapping_section(summary, "canonical")
    bridge = _mapping_section(summary, "bridge")
    reconciliation = _mapping_section(summary, "reconciliation")
    reports = _mapping_section(summary, "reports")

    print()
    _print_heading("Persistence audit summary")
    print(f"Artifact : {path}")
    print(f"Schema   : {payload.get('schema_version') or 'unknown'}")
    print(f"Apps     : {payload.get('total_apps') or 0}")

    if outcome_summary:
        compat_stage = outcome_summary.get("compat_export_stage")
        print(
            "Outcome  : "
            f"canonical_failed={bool(outcome_summary.get('canonical_failed', False))} "
            f"persistence_failed={bool(outcome_summary.get('persistence_failed', False))} "
            f"compat_export_failed={bool(outcome_summary.get('compat_export_failed', False))}"
        )
        if compat_stage:
            print(f"Compat   : stage={compat_stage}")

    if canonical:
        statuses = canonical.get("run_statuses") or {}
        print(f"Canonical: statuses={statuses} findings={canonical.get('findings', 0)}")
        print(
            "           "
            f"permission_matrix={canonical.get('permission_matrix', 0)} "
            f"permission_risk={canonical.get('permission_risk', 0)} "
            f"handoff_paths={canonical.get('handoff_paths', 0)}"
        )

    if bridge:
        metrics_packages = bridge.get("metrics_packages", bridge.get("secondary_compat_mirror_packages", 0))
        buckets_packages = bridge.get("buckets_packages", bridge.get("secondary_compat_mirror_packages", 0))
        contributors_packages = bridge.get("contributors_packages", bridge.get("secondary_compat_mirror_packages", 0))
        print(
            "Compat   : "
            f"runs={bridge.get('runs', 0)} risk_scores={bridge.get('risk_scores', 0)} "
            f"metrics={metrics_packages} buckets={buckets_packages} contributors={contributors_packages}"
        )

    if reports:
        print(
            "Reports  : "
            f"json={reports.get('json_report_paths', 0)} "
            f"latest={reports.get('latest_json_paths', 0)} "
            f"archive={reports.get('archive_json_paths', 0)}"
        )

    if reconciliation:
        gap_items = [
            ("missing_legacy_runs_count", "compat runs"),
            ("missing_legacy_risk_count", "compat risk"),
            ("missing_secondary_compat_mirror_count", "secondary compat mirrors"),
            ("missing_findings_summary_count", "findings summary"),
            ("missing_string_summary_count", "string summary"),
            ("bridge_only_runs_count", "compat-only runs"),
            ("bridge_only_risk_count", "compat-only risk"),
        ]
        active_gaps = [
            f"{label}={reconciliation.get(key, 0)}"
            for key, label in gap_items
            if _safe_int(reconciliation.get(key, 0)) > 0
        ]
        print("Gaps     : " + (", ".join(active_gaps) if active_gaps else "none"))
    else:
        print("Gaps     : none")

    print("Note     : Compatibility counts are secondary checks; canonical rows remain authoritative.")


def render_permission_snapshot_summary_section(session_stamp: str | None) -> None:
    path = _resolve_permission_snapshot_path(session_stamp)
    if path is None:
        print(status_messages.status("Permission snapshot artifact not found.", level="warn"))
        return

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(status_messages.status(f"Failed to read permission snapshot: {exc}", level="warn"))
        return

    inventory = _mapping_section(payload, "inventory")
    permissions = payload.get("permissions") if isinstance(payload.get("permissions"), Sequence) else []
    signals = payload.get("signals") if isinstance(payload.get("signals"), Sequence) else []

    print()
    _print_heading("Permission snapshot")
    print(f"Artifact : {path}")
    print(
        "Apps     : "
        f"total={inventory.get('apps_total', 0)} in_scope={inventory.get('apps_in_scope', 0)}"
    )

    cohort_counts = inventory.get("cohort_counts")
    if isinstance(cohort_counts, Mapping):
        preview = ", ".join(f"{k}={v}" for k, v in list(cohort_counts.items())[:5])
        if preview:
            print(f"Cohorts  : {preview}")

    print(f"Permissions tracked: {len(permissions)}")
    print(f"Signals tracked    : {len(signals)}")


def render_export_all_tables_section(session_stamp: str | None) -> None:
    print()
    _print_heading("Export paths")
    stamp = str(session_stamp or "").strip()

    normalized_csv = Path("output") / "tables" / f"{stamp}_normalized_findings.csv" if stamp else None
    persistence_audit = _resolve_persistence_audit_path(stamp)
    permission_snapshot = _resolve_permission_snapshot_path(stamp)
    report_latest = Path("output") / "reports" / "static" / "latest"

    if normalized_csv is not None:
        print(f"Normalized findings CSV : {normalized_csv}")
    if persistence_audit is not None:
        print(f"Persistence audit       : {persistence_audit}")
    if permission_snapshot is not None:
        print(f"Permission snapshot     : {permission_snapshot}")
    print(f"Static HTML reports     : {report_latest}")


def render_post_run_diagnostics_menu(
    *,
    outcome: RunOutcome,
    params: RunParameters,
    permission_profiles: Sequence[dict[str, object]],
    component_profiles: Sequence[dict[str, object]],
    masvs_matrix: Mapping[str, Mapping[str, object]],
    static_risk_rows: Sequence[dict[str, object]],
    secret_profiles: Sequence[dict[str, object]],
    finding_profiles: Sequence[dict[str, object]],
    trend_deltas: Sequence[dict[str, object]],
    persist_enabled: bool,
    compact_mode: bool,
    render_db_severity_table_fn,
    render_post_run_views_fn,
    render_db_masvs_summary_fn,
    render_cross_app_insights_fn,
) -> None:
    while True:
        print()
        _print_heading("Post-run diagnostics")
        print("1) Normalized findings by package")
        print("2) Permission matrix")
        print("3) MASVS matrix")
        print("4) Static risk scores")
        print("5) Aggregate insights")
        print("6) Persistence audit summary")
        print("7) Permission snapshot")
        print("8) Export all tables")
        print("0) Back")

        choice = prompt_utils.prompt_text("Choice", default="0", required=False).strip()
        if choice in {"", "0"}:
            break

        if choice == "1":
            printed = False
            if params.session_stamp and persist_enabled:
                printed = render_db_severity_table_fn(params.session_stamp)
            if not printed:
                from ..views.run_detail_view import render_app_table

                render_app_table(outcome.results, diagnostic=params.dry_run, compact=compact_mode)

        elif choice == "2":
            render_post_run_views_fn(
                permission_profiles,
                {},
                [],
                scope_label=params.scope_label,
                snapshot_at=outcome.finished_at,
            )

        elif choice == "3":
            render_post_run_views_fn(
                [],
                masvs_matrix,
                [],
                scope_label=params.scope_label,
                snapshot_at=outcome.finished_at,
            )
            if persist_enabled:
                render_db_masvs_summary_fn()

        elif choice == "4":
            render_post_run_views_fn(
                [],
                {},
                static_risk_rows,
                scope_label=params.scope_label,
                snapshot_at=outcome.finished_at,
            )

        elif choice == "5":
            render_cross_app_insights_fn(
                permission_profiles,
                component_profiles,
                masvs_matrix,
                secret_profiles,
                finding_profiles,
                trend_deltas,
                scope_label=params.scope_label,
            )

        elif choice == "6":
            render_persistence_audit_summary_section(params.session_stamp)

        elif choice == "7":
            render_permission_snapshot_summary_section(params.session_stamp)

        elif choice == "8":
            render_export_all_tables_section(params.session_stamp)

        else:
            print(status_messages.status("Invalid selection.", level="warn"))