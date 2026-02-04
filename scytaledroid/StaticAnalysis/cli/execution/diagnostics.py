"""Diagnostic linkage helpers for static analysis results."""

from __future__ import annotations

from collections.abc import Mapping

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils import diagnostics as db_diagnostics
from scytaledroid.Utils.DisplayUtils import table_utils
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ..core.models import RunOutcome
from .results_formatters import _hash_prefix
from .static_run_map import load_run_map, resolve_run_map_entry

SUPPORTED_RUN_SIGNATURE_VERSIONS = {"v1"}


def _schema_guard_status() -> tuple[bool, str]:
    required_columns = {
        "static_session_run_links": {
            "session_stamp",
            "package_name",
            "static_run_id",
            "pipeline_version",
            "run_signature",
            "run_signature_version",
            "base_apk_sha256",
            "artifact_set_hash",
        },
        "static_analysis_runs": {
            "id",
            "pipeline_version",
            "run_signature",
            "run_signature_version",
            "base_apk_sha256",
            "artifact_set_hash",
        },
    }
    missing: list[str] = []
    for table, expected in required_columns.items():
        comparison = db_diagnostics.compare_columns(table, expected)
        if comparison.get("missing"):
            missing.extend(f"{table}.{col}" for col in comparison["missing"])
    if missing:
        preview = ", ".join(missing[:6])
        remaining = len(missing) - 6
        if remaining > 0:
            preview = f"{preview}, +{remaining} more"
        return False, f"missing columns: {preview}"
    version = db_diagnostics.get_schema_version()
    return True, f"{version}" if version else "unknown"


def _fetch_db_linkage(
    session_stamp: str,
    package_name: str,
) -> tuple[Mapping[str, object] | None, str | None]:
    try:
        row = core_q.run_sql(
            """
            SELECT static_run_id,
                   pipeline_version,
                   run_signature,
                   run_signature_version,
                   run_origin,
                   origin_session_stamp
              FROM static_session_run_links
             WHERE session_stamp = %s
               AND package_name = %s
            """,
            (session_stamp, package_name),
            fetch="one_dict",
        )
    except Exception as exc:
        log.warning(
            f"Diagnostic linkage db_link query failed for session={session_stamp} package={package_name}: {exc}",
            category="static_analysis",
        )
        reason = "db_link_query_failed"
        if "Unknown column" in str(exc):
            reason = "db_link_query_failed (schema mismatch)"
        return None, reason
    if not row:
        return None, None
    if not isinstance(row, Mapping):
        return None, "db_link_invalid_row"
    return row, None


def _fetch_db_linkage_by_signature(
    package_name: str,
    run_signature: str,
) -> tuple[Mapping[str, object] | None, str | None]:
    try:
        row = core_q.run_sql(
            """
            SELECT sar.id AS static_run_id,
                   sar.pipeline_version,
                   sar.run_signature,
                   sar.run_signature_version
              FROM static_analysis_runs sar
              JOIN app_versions av ON av.id = sar.app_version_id
              JOIN apps a ON a.id = av.app_id
             WHERE a.package_name = %s
               AND sar.run_signature = %s
               AND sar.status = 'COMPLETED'
             ORDER BY sar.id DESC
             LIMIT 1
            """,
            (package_name, run_signature),
            fetch="one_dict",
        )
    except Exception as exc:
        log.warning(
            f"Diagnostic linkage db_lookup failed for package={package_name} signature={run_signature}: {exc}",
            category="static_analysis",
        )
        reason = "db_lookup_failed"
        if "Unknown column" in str(exc):
            reason = "db_lookup_failed (schema mismatch)"
        return None, reason
    if not row:
        return None, None
    if not isinstance(row, Mapping):
        return None, "db_lookup_invalid_row"
    return row, None


def _diagnostic_linkage_status(
    app_result,
    *,
    run_map: Mapping[str, object] | None,
    session_stamp: str | None,
) -> tuple[str, str | None]:
    if not session_stamp:
        return "UNAVAILABLE", "UNAVAILABLE: session_stamp missing"
    run_map_entry: Mapping[str, object] | None = None
    run_map_note: str | None = None
    if run_map:
        run_map_entry, run_map_note = resolve_run_map_entry(app_result, run_map)
    db_link_entry, db_link_note = _fetch_db_linkage(session_stamp, app_result.package_name)

    if run_map_entry and db_link_entry:
        run_map_id = run_map_entry.get("static_run_id")
        db_link_id = db_link_entry.get("static_run_id")
        if run_map_id != db_link_id:
            return "INVALID", "INVALID: run_map/db_link mismatch"
        return "VALID (run_map+db_link)", f"static_run_id={run_map_id}"

    if run_map_entry:
        return "VALID (run_map)", f"static_run_id={run_map_entry.get('static_run_id')}"
    if db_link_entry:
        db_pipeline = db_link_entry.get("pipeline_version")
        if db_pipeline in (None, ""):
            return "INVALID", "db_link missing pipeline_version"
        return "VALID (db_link)", f"static_run_id={db_link_entry.get('static_run_id')}"

    if app_result.run_signature:
        run_sig_version = getattr(app_result, "run_signature_version", None)
        if not run_sig_version:
            return "UNAVAILABLE", "UNAVAILABLE: db_lookup_blocked: missing_signature_version"
        if run_sig_version not in SUPPORTED_RUN_SIGNATURE_VERSIONS:
            return (
                "UNAVAILABLE",
                f"UNAVAILABLE: db_lookup_blocked: unsupported_signature_version={run_sig_version}",
            )
        lookup_entry, lookup_note = _fetch_db_linkage_by_signature(
            app_result.package_name,
            app_result.run_signature,
        )
        if lookup_entry:
            pipeline_version = lookup_entry.get("pipeline_version")
            if pipeline_version in (None, ""):
                return "INVALID", "db_lookup missing pipeline_version"
            lookup_version = lookup_entry.get("run_signature_version")
            if lookup_version and lookup_version not in SUPPORTED_RUN_SIGNATURE_VERSIONS:
                return (
                    "UNAVAILABLE",
                    f"UNAVAILABLE: db_lookup_blocked: unsupported_signature_version={lookup_version}",
                )
            return "VALID (db_lookup)", f"static_run_id={lookup_entry.get('static_run_id')}"
        if lookup_note:
            return "UNAVAILABLE", f"UNAVAILABLE: {lookup_note}"

    if db_link_note:
        return "UNAVAILABLE", "UNAVAILABLE: db_link query failed"
    if run_map_note:
        if "static_run_id/pipeline_version" in run_map_note:
            return "UNAVAILABLE", f"UNAVAILABLE: {run_map_note}"
        return "INVALID", f"INVALID: {run_map_note}"
    return "UNAVAILABLE", "UNAVAILABLE: no run_map; no db link"


def _render_diagnostic_app_summary(
    outcome: RunOutcome,
    *,
    session_stamp: str | None,
    compact_mode: bool = True,
    verbose_mode: bool = False,
) -> tuple[list[tuple[str, str, str]], list[str], list[bool]]:
    try:
        run_map = load_run_map(session_stamp)
    except Exception as exc:
        log.warning(
            f"Diagnostic run_map load failed for session={session_stamp}: {exc}",
            category="static_analysis",
        )
        run_map = None
    headers = ["App", "Artifacts", "Executed", "Persisted", "Identity", "Linkage", "RunID", "Sig"]
    rows: list[list[str]] = []
    issue_rows: list[list[str]] = []
    warnings: list[tuple[str, str, str]] = []
    linkage_states: list[str] = []
    run_id_states: list[bool] = []
    trace_rows: list[list[str]] = []
    label_map: dict[str, str] = {}
    for app in outcome.results:
        label_map[app.package_name] = app.app_label or app.package_name
        identity_note = app.identity_error_reason if app.identity_valid is False else None
        run_map_entry: Mapping[str, object] | None = None
        db_link_entry: Mapping[str, object] | None = None
        run_map_note: str | None = None
        if run_map:
            run_map_entry, run_map_note = resolve_run_map_entry(app, run_map)
        if session_stamp:
            db_link_entry, _ = _fetch_db_linkage(session_stamp, app.package_name)
        linkage, linkage_note = _diagnostic_linkage_status(app, run_map=run_map, session_stamp=session_stamp)
        linkage_states.append(linkage)
        base_prefix = _hash_prefix(app.base_apk_sha256)
        set_prefix = _hash_prefix(app.artifact_set_hash)
        identity_cell = "b=— s=—"
        if base_prefix or set_prefix:
            identity_cell = f"b={base_prefix or '—'} s={set_prefix or '—'}"
        static_run_id = None
        run_signature = app.run_signature
        lookup_entry: Mapping[str, object] | None = None
        if linkage.startswith("VALID (db_lookup)") and app.run_signature:
            lookup_entry, _ = _fetch_db_linkage_by_signature(
                app.package_name,
                app.run_signature,
            )
        trace_note = None
        if linkage.startswith("VALID"):
            if "run_map" in linkage:
                source = run_map_entry
                trace_note = "resolved_from=run_map"
            elif "db_link" in linkage:
                source = db_link_entry
                trace_note = "resolved_from=db_link"
            elif "db_lookup" in linkage:
                source = lookup_entry
                trace_note = f"resolved_from=db_lookup (run_signature={app.run_signature_version or '—'} match)"
            else:
                source = None
            if source:
                static_run_id = source.get("static_run_id")
                run_signature = run_signature or source.get("run_signature")
        rows.append(
            [
                app.app_label or app.package_name,
                str(app.discovered_artifacts),
                str(app.executed_artifacts),
                str(app.persisted_artifacts),
                identity_cell,
                linkage,
                str(static_run_id) if static_run_id is not None else "—",
                _hash_prefix(run_signature) or "—",
            ]
        )
        run_id_states.append(static_run_id is not None)
        if identity_note:
            warnings.append(("Identity", app.package_name, identity_note))
            issue_rows.append(["Identity", label_map[app.package_name], identity_note])
        if linkage_note and not linkage.startswith("VALID"):
            warnings.append(("Linkage", app.package_name, linkage_note))
            issue_rows.append(["Linkage", label_map[app.package_name], linkage_note])
        if verbose_mode and trace_note:
            trace_rows.append([label_map[app.package_name], trace_note])
    if rows:
        print("\nDiagnostic — Per-app summary")
        table_utils.render_table(headers, rows)
    if compact_mode and issue_rows:
        print("\nDiagnostic — Issues")
        for row in issue_rows:
            if len(row[2]) > 80:
                row[2] = f"{row[2][:79]}…"
        table_utils.render_table(["Type", "App", "Note"], issue_rows)
    if verbose_mode and trace_rows:
        print("\nDiagnostic — Linkage trace")
        table_utils.render_table(["App", "Resolution"], trace_rows)
    return warnings, linkage_states, run_id_states


def _group_diagnostic_warnings(
    entries: list[tuple[str, str, str]],
    *,
    max_packages: int = 5,
) -> list[str]:
    grouped: dict[tuple[str, str], list[str]] = {}
    for category, package, note in entries:
        key = (category, note)
        grouped.setdefault(key, []).append(package)
    lines: list[str] = []
    for (category, note), packages in grouped.items():
        packages_sorted = sorted(set(packages))
        shown = packages_sorted[:max_packages]
        extra = len(packages_sorted) - len(shown)
        package_list = ", ".join(shown)
        if extra > 0:
            package_list = f"{package_list} (+{extra} more)"
        lines.append(f"{category} {note}: {len(packages_sorted)} apps — {package_list}")
    return sorted(lines)


def _plan_provenance_lines(
    run_id_states: list[bool],
    run_signature_ok: bool,
    artifact_set_ok: bool,
) -> list[str]:
    lines: list[str] = []
    if run_id_states and all(run_id_states):
        lines.append("OK static_run_id present")
    else:
        missing = sum(1 for ok in run_id_states if not ok)
        total = len(run_id_states)
        lines.append(f"FAIL static_run_id present (missing {missing}/{total})")
        lines.append("    Fix: resolve linkage (run_map/db_link/db_lookup) so RunID is present.")
    lines.append(f"{'OK' if run_signature_ok else 'FAIL'} run_signature present")
    lines.append(f"{'OK' if artifact_set_ok else 'FAIL'} artifact_set_hash present")
    return lines


__all__ = [
    "SUPPORTED_RUN_SIGNATURE_VERSIONS",
    "_diagnostic_linkage_status",
    "_group_diagnostic_warnings",
    "_plan_provenance_lines",
    "_render_diagnostic_app_summary",
    "_schema_guard_status",
]