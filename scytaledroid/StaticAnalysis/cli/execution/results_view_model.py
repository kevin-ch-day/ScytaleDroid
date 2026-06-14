"""Static run result view-model helpers."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Utils.DisplayUtils import summary_cards

from ..core.models import RunOutcome, RunParameters


@dataclass(frozen=True, slots=True)
class RunResultsSessionMeta:
    session_label: str | None
    session_stamp: str | None
    attempts: int | None
    canonical_id: int | None
    latest_id: int | None
    first_static_run_id: int | None


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
    """Dense summary/persistence UX for multi-app profile or all-apps cohorts (non-verbose)."""
    return bool(
        not params.verbose_output
        and params.scope in {"all", "profile"}
        and len(outcome.results) >= 8
    )


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


def collect_static_output_context(
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
    result_manifest = (
        _load_json_mapping(getattr(outcome.results[0], "harvest_manifest_path", None))
        if outcome.results
        else {}
    )
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


def load_run_results_session_meta(
    *,
    params: RunParameters,
    run_sql_fn,
) -> RunResultsSessionMeta:
    session_label = params.session_label or params.session_stamp
    if not session_label or params.dry_run:
        return RunResultsSessionMeta(
            session_label=session_label,
            session_stamp=params.session_stamp,
            attempts=None,
            canonical_id=None,
            latest_id=None,
            first_static_run_id=None,
        )

    attempts: int | None = None
    canonical_id: int | None = None
    latest_id: int | None = None
    first_static_run_id: int | None = None
    try:
        row = run_sql_fn(
            "SELECT COUNT(*) FROM static_analysis_runs WHERE session_label=%s",
            (session_label,),
            fetch="one",
        )
        attempts = int(row[0]) if row and row[0] is not None else None
    except Exception:
        attempts = None
    try:
        row = run_sql_fn(
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
        row = run_sql_fn(
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
    try:
        row = run_sql_fn(
            """
            SELECT MIN(id)
            FROM static_analysis_runs
            WHERE session_label=%s
            """,
            (session_label,),
            fetch="one",
        )
        first_static_run_id = int(row[0]) if row and row[0] is not None else None
    except Exception:
        first_static_run_id = None
    return RunResultsSessionMeta(
        session_label=session_label,
        session_stamp=params.session_stamp,
        attempts=attempts,
        canonical_id=canonical_id,
        latest_id=latest_id,
        first_static_run_id=first_static_run_id,
    )


def build_run_results_view_model(
    outcome: RunOutcome,
    params: RunParameters,
    *,
    totals: Mapping[str, int],
    artifact_count: int,
    collect_static_output_context_fn,
    load_run_results_session_meta_fn,
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

    session_meta = load_run_results_session_meta_fn(params=params)
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

    static_output_context = collect_static_output_context_fn(
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
