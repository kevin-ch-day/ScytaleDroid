"""DB verification footer helpers for static analysis runs.

The severity table and MASVS summary renderers live in smaller focused modules:
- db_severity_table.py
- db_masvs_summary.py
- db_verification_common.py

This module keeps the post-run persistence footer because it still coordinates
multiple canonical and compatibility table checks.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_core import permission_intel as intel_db
from scytaledroid.Database.db_core.db_config import DB_CONFIG
from scytaledroid.Database.db_scripts.static_run_audit import collect_static_run_counts
from scytaledroid.Utils.DisplayUtils import status_messages

from .db_masvs_summary import render_db_masvs_summary as _render_db_masvs_summary
from .db_severity_table import render_db_severity_table as _render_db_severity_table
from .db_verification_common import resolve_static_run_ids as _resolve_static_run_ids
from .db_verification_common import table_has_column as _table_has_column
from .output_mode import compact_success_output_enabled

SNAPSHOT_PREFIX = "perm-audit:app:"


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value or default)
    except Exception:
        return default


def _scalar_count(sql: str, params: tuple[object, ...] = ()) -> int:
    """Return an integer count from a scalar SQL query."""
    try:
        row = core_q.run_sql(sql, params, fetch="one")
    except Exception:
        return 0

    if not row:
        return 0

    value = row[0] if not isinstance(row, dict) else next(iter(row.values()), 0)
    return _safe_int(value)


def _scalar_total(sql: str) -> int:
    """Return an integer count from a scalar SQL query with no parameters."""
    try:
        row = core_q.run_sql(sql, fetch="one")
    except Exception:
        return 0

    if not row:
        return 0

    value = row[0] if not isinstance(row, dict) else next(iter(row.values()), 0)
    return _safe_int(value)


def _canonical_static_findings_session_rows(session_stamp: str) -> int:
    """Count persisted canonical findings rows for all static runs in a session_stamp."""
    if not session_stamp:
        return 0
    return _scalar_count(
        """
        SELECT COUNT(*)
        FROM static_analysis_findings f
        JOIN static_analysis_runs sar ON sar.id = f.run_id
        WHERE sar.session_stamp = %s
        """,
        (session_stamp,),
    )


def _format_list(items: Sequence[str], *, limit: int = 5) -> str:
    if not items:
        return ""

    unique = sorted(set(str(item) for item in items if str(item).strip()))
    preview = ", ".join(unique[:limit])
    remaining = len(unique) - limit

    if remaining > 0:
        preview += f", +{remaining} more"

    return preview


def _session_label_for_stamp(session_stamp: str) -> str | None:
    try:
        row = core_q.run_sql(
            """
            SELECT session_label
            FROM static_analysis_runs
            WHERE session_stamp=%s
            ORDER BY id DESC
            LIMIT 1
            """,
            (session_stamp,),
            fetch="one",
        )
    except Exception:
        return None

    if row and row[0]:
        return str(row[0])

    return None


def _sample_selection_meta(static_ids: Sequence[int]) -> tuple[str | None, str | None]:
    if not static_ids:
        return None, None

    placeholders = ",".join(["%s"] * len(static_ids))

    try:
        row = core_q.run_sql(
            f"""
            SELECT selection_version, selection_params
            FROM static_string_sample_sets
            WHERE static_run_id IN ({placeholders})
            ORDER BY id DESC
            LIMIT 1
            """,
            tuple(static_ids),
            fetch="one",
        )
    except Exception:
        return None, None

    if not row:
        return None, None

    if isinstance(row, dict):
        selection_version = row.get("selection_version")
        params_payload = row.get("selection_params")
    else:
        selection_version, params_payload = row

    policy_version = None

    if params_payload:
        if isinstance(params_payload, str):
            try:
                params_payload = json.loads(params_payload)
            except Exception:
                params_payload = None

        if isinstance(params_payload, Mapping):
            policy_version = params_payload.get("policy_version")

    return (
        str(selection_version) if selection_version is not None else None,
        str(policy_version) if policy_version is not None else None,
    )


def _governance_status() -> str | None:
    try:
        version, _sha, row_count = intel_db.latest_governance_snapshot()
        if version and row_count > 0:
            return f"OK ({version})"
        if intel_db.governance_row_count() > 0:
            return "ERROR (governance rows missing header)"
        return "SKIPPED_GOVERNANCE_MISSING"
    except Exception:
        return None


def _audit_value(audit_counts: Mapping[str, object], table: str) -> int | None:
    if table not in audit_counts:
        return None

    try:
        value, status = audit_counts[table]
    except Exception:
        return None

    if isinstance(status, str) and status.startswith("SKIP"):
        return None

    return _safe_int(value)


def _audit_or(
    audit_counts: Mapping[str, object],
    table: str,
    fallback_sql: str | None = None,
    params: tuple[object, ...] = (),
) -> int:
    value = _audit_value(audit_counts, table)
    if value is not None:
        return value

    if fallback_sql is None:
        return 0

    return _scalar_count(fallback_sql, params)


def _count_by_run(
    table: str,
    *,
    static_run_ids: Sequence[int],
    latest_static_run_ids: Sequence[int],
    latest_run_ids: Sequence[int],
    group_scope: bool,
) -> int:
    scoped_static_ids = static_run_ids if group_scope else latest_static_run_ids

    if scoped_static_ids and _table_has_column(table, "static_run_id"):
        placeholders = ",".join(["%s"] * len(scoped_static_ids))
        return _scalar_count(
            f"SELECT COUNT(*) FROM {table} WHERE static_run_id IN ({placeholders})",
            tuple(scoped_static_ids),
        )

    if latest_run_ids:
        placeholders = ",".join(["%s"] * len(latest_run_ids))
        return _scalar_count(
            f"SELECT COUNT(*) FROM {table} WHERE run_id IN ({placeholders})",
            tuple(latest_run_ids),
        )

    return 0


def _status_from_audit(
    *,
    audit,
    missing: Sequence[str],
    run_status: str | None,
    abort_reason: str | None,
    abort_signal: str | None,
) -> str | None:
    if not audit:
        return None

    if audit.is_group_scope:
        status = (
            "OK (group scope)"
            if not missing
            else "ERROR (missing " + ", ".join(sorted(missing)) + ")"
        )
    elif audit.run_id is None:
        status = "ORPHAN (run_id missing)" if audit.is_orphan else "SKIPPED (run_id missing)"
    elif missing:
        status = "ERROR (missing " + ", ".join(sorted(missing)) + ")"
    else:
        status = "OK (canonical static persistence)"

    if run_status == "FAILED" and (abort_reason or abort_signal):
        return "FAILED (counts may be partial)"

    return status


def _attempt_lines(session_label: str | None) -> list[tuple[str, str]]:
    if not session_label:
        return []

    lines: list[tuple[str, str]] = []

    try:
        row = core_q.run_sql(
            """
            SELECT COUNT(*)
            FROM static_analysis_runs
            WHERE session_label=%s
            """,
            (session_label,),
            fetch="one",
        )
        attempts = _safe_int(row[0] if row else 0)
        lines.append(("attempts", str(attempts)))
    except Exception:
        pass

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
        if row and row[0]:
            lines.append(("canonical", f"static_run_id={int(row[0])}"))
    except Exception:
        pass

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
        if row and row[0]:
            lines.append(("latest", f"static_run_id={int(row[0])}"))
    except Exception:
        pass

    return lines


def _render_attempt_history(session_label: str | None) -> None:
    if not session_label:
        return

    try:
        rows = core_q.run_sql(
            """
            SELECT id, COALESCE(run_started_utc, ended_at_utc, created_at) AS ts, is_canonical,
                   COALESCE(NULLIF(status, ''), 'UNKNOWN') AS run_status,
                   COALESCE(abort_reason, '') AS abort_reason
            FROM static_analysis_runs
            WHERE session_label=%s
            ORDER BY id DESC
            LIMIT 5
            """,
            (session_label,),
            fetch="all",
        )
    except Exception:
        rows = None

    if not rows:
        return

    print()
    print("Attempts (latest first)")

    for row in rows:
        try:
            attempt_id = int(row[0])
        except Exception:
            attempt_id = row[0]

        timestamp = row[1] or "—"

        if timestamp != "—":
            try:
                parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
                timestamp = parsed.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

        canonical_flag = "canonical" if int(row[2] or 0) else "archived"
        print(f"  - {attempt_id} ({canonical_flag}) {timestamp}")
        run_status = str(row[3] if len(row) > 3 else "").strip() or "UNKNOWN"
        abort_reason = str(row[4] if len(row) > 4 else "").strip()
        detail = f"static_run.status={run_status}"
        if abort_reason:
            detail += f" · abort_reason={abort_reason}"
        print(f"    {detail}")


def _compact_footer_ok(
    *,
    session_stamp: str,
    latest_run_ids: Sequence[int],
    latest_static_run_ids: Sequence[int],
    static_run_ids: Sequence[int],
    audit,
    db_verification_status: str | None,
) -> None:
    print()
    print(f"Diagnostics: OK for session {session_stamp}")

    run_part = ",".join(str(r) for r in latest_run_ids) if latest_run_ids else "<none>"
    static_part = ",".join(str(r) for r in latest_static_run_ids) if latest_static_run_ids else "<none>"
    print(f"run_id={run_part} static_run_id={static_part}")

    if audit and audit.is_group_scope:
        print(f"scope=group runs={len(latest_run_ids)} static_runs={len(static_run_ids)}")

    if db_verification_status:
        print(f"db_verification={db_verification_status}")


def _render_persistence_footer(
    session_stamp: str,
    *,
    had_errors: bool = False,
    canonical_failures: list[str | None] = None,
    run_status: str | None = None,
    abort_reason: str | None = None,
    abort_signal: str | None = None,
) -> None:
    """Render persistence verification for a static-analysis session.

    Normal successful runs get a compact footer. Verbose mode, failures, and
    partial/interrupted runs still get the full detailed diagnostics.
    """
    canonical_failures = canonical_failures or []

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
    group_scope = bool(audit and audit.is_group_scope)

    snapshot_key = f"{SNAPSHOT_PREFIX}{session_stamp}"

    try:
        snapshot_row = core_q.run_sql(
            "SELECT snapshot_id FROM permission_audit_snapshots WHERE snapshot_key=%s",
            (snapshot_key,),
            fetch="one",
        )
    except Exception:
        snapshot_row = None

    snapshot_id = _safe_int(snapshot_row[0]) if snapshot_row and snapshot_row[0] is not None else None

    findings_summary = _audit_or(
        audit_counts,
        "static_findings_summary (baseline)",
        "SELECT COUNT(*) FROM static_findings_summary WHERE session_stamp = %s",
        (session_stamp,),
    )
    findings_detail = _audit_or(
        audit_counts,
        "static_findings (baseline detail)",
        """
        SELECT COUNT(*)
        FROM static_findings f
        JOIN static_findings_summary s ON s.id = f.summary_id
        WHERE s.session_stamp = %s
        """,
        (session_stamp,),
    )
    strings_summary = _audit_or(
        audit_counts,
        "static_string_summary",
        "SELECT COUNT(*) FROM static_string_summary WHERE session_stamp = %s",
        (session_stamp,),
    )
    string_samples_raw = _audit_or(
        audit_counts,
        "static_string_samples",
        """
        SELECT COUNT(*)
        FROM static_string_samples x
        JOIN static_findings_summary s ON s.id = x.summary_id
        WHERE s.session_stamp = %s
        """,
        (session_stamp,),
    )
    string_samples_selected = _audit_or(
        audit_counts,
        "static_string_selected_samples",
        """
        SELECT COUNT(*)
        FROM static_string_selected_samples x
        JOIN static_findings_summary s ON s.id = x.summary_id
        WHERE s.session_stamp = %s
        """,
        (session_stamp,),
    )

    selection_version, policy_version = _sample_selection_meta(latest_static_run_ids)

    buckets = _audit_or(audit_counts, "buckets") or _count_by_run(
        "buckets",
        static_run_ids=static_run_ids,
        latest_static_run_ids=latest_static_run_ids,
        latest_run_ids=latest_run_ids,
        group_scope=group_scope,
    )
    metrics = _audit_or(audit_counts, "metrics") or _count_by_run(
        "metrics",
        static_run_ids=static_run_ids,
        latest_static_run_ids=latest_static_run_ids,
        latest_run_ids=latest_run_ids,
        group_scope=group_scope,
    )
    findings = _audit_or(audit_counts, "findings") or _count_by_run(
        "findings",
        static_run_ids=static_run_ids,
        latest_static_run_ids=latest_static_run_ids,
        latest_run_ids=latest_run_ids,
        group_scope=group_scope,
    )

    scope_static_ids = static_run_ids if group_scope else latest_static_run_ids

    snapshot_count = _audit_or(
        audit_counts,
        "permission_audit_snapshots",
        "SELECT COUNT(*) FROM permission_audit_snapshots WHERE snapshot_key = %s",
        (snapshot_key,),
    )

    if snapshot_count == 0 and scope_static_ids:
        placeholders = ",".join(["%s"] * len(scope_static_ids))
        snapshot_count = _scalar_count(
            f"SELECT COUNT(*) FROM permission_audit_snapshots WHERE static_run_id IN ({placeholders})",
            tuple(scope_static_ids),
        )

    if snapshot_count == 0 and scope_static_ids:
        placeholders = ",".join(["%s"] * len(scope_static_ids))
        snapshot_count = _scalar_count(
            f"SELECT COUNT(DISTINCT snapshot_id) FROM permission_audit_apps WHERE static_run_id IN ({placeholders})",
            tuple(scope_static_ids),
        )

    snapshot_apps = _audit_or(audit_counts, "permission_audit_apps")

    if snapshot_apps == 0 and snapshot_id is not None:
        snapshot_apps = _scalar_count(
            "SELECT COUNT(*) FROM permission_audit_apps WHERE snapshot_id = %s",
            (snapshot_id,),
        )

    if snapshot_apps == 0 and scope_static_ids:
        placeholders = ",".join(["%s"] * len(scope_static_ids))
        snapshot_apps = _scalar_count(
            f"SELECT COUNT(*) FROM permission_audit_apps WHERE static_run_id IN ({placeholders})",
            tuple(scope_static_ids),
        )

    permission_matrix_rows = 0
    if scope_static_ids:
        placeholders = ",".join(["%s"] * len(scope_static_ids))
        permission_matrix_rows = _scalar_count(
            f"SELECT COUNT(*) FROM static_permission_matrix WHERE run_id IN ({placeholders})",
            tuple(scope_static_ids),
        )

    canonical_finding_rows = _canonical_static_findings_session_rows(session_stamp)
    # Legacy mirror tables (`findings`, `buckets`, `metrics`, `runs`) are optional once
    # canonical persistence (`static_analysis_findings`) is populated for the session.
    findings_evidence_ok = bool(findings) or canonical_finding_rows > 0

    required_counts = {
        "findings": findings_evidence_ok,
        "static_string_summary": strings_summary,
        "static_string_samples": string_samples_raw,
    }
    missing = [name for name, value in required_counts.items() if not value]

    audit_error_tables: list[str] = []
    for table, payload in audit_counts.items():
        try:
            _value, status = payload
        except Exception:
            continue
        if isinstance(status, str) and status.startswith("ERROR"):
            audit_error_tables.append(table)

    db_verification_status = _status_from_audit(
        audit=audit,
        missing=missing,
        run_status=run_status,
        abort_reason=abort_reason,
        abort_signal=abort_signal,
    )
    db_verification_ok = bool(db_verification_status and db_verification_status.startswith("OK"))

    if (
        compact_success_output_enabled()
        and not had_errors
        and not canonical_failures
        and not audit_error_tables
        and db_verification_ok
        and run_status != "FAILED"
    ):
        _compact_footer_ok(
            session_stamp=session_stamp,
            latest_run_ids=latest_run_ids,
            latest_static_run_ids=latest_static_run_ids,
            static_run_ids=static_run_ids,
            audit=audit,
            db_verification_status=db_verification_status,
        )
        return

    runs_total = _scalar_total("SELECT COUNT(*) FROM runs")
    buckets_total = _scalar_total("SELECT COUNT(*) FROM buckets")
    metrics_total = _scalar_total("SELECT COUNT(*) FROM metrics")
    findings_total = _scalar_total("SELECT COUNT(*) FROM findings")
    strings_summary_total = _scalar_total("SELECT COUNT(*) FROM static_string_summary")
    string_samples_raw_total = _scalar_total("SELECT COUNT(*) FROM static_string_samples")
    string_samples_selected_total = _scalar_total("SELECT COUNT(*) FROM static_string_selected_samples")
    findings_summary_total = _scalar_total("SELECT COUNT(*) FROM static_findings_summary")
    findings_detail_total = _scalar_total("SELECT COUNT(*) FROM static_findings")
    snapshot_total = _scalar_total("SELECT COUNT(*) FROM permission_audit_snapshots")
    snapshot_apps_total = _scalar_total("SELECT COUNT(*) FROM permission_audit_apps")

    print()
    header = f"Diagnostics for session {session_stamp}"
    print(header)
    print("=" * len(header))

    if group_scope:
        scope_note = f"run_id={len(run_ids)} static_run_id={len(static_run_ids)}"
    else:
        scope_note = "run_id=" + ",".join(str(r) for r in latest_run_ids) if latest_run_ids else "run_id=<none>"
        if latest_static_run_ids:
            scope_note += " static_run_id=" + ",".join(str(r) for r in latest_static_run_ids)

    run_count = len(run_ids) if group_scope else len(latest_run_ids)

    lines: list[tuple[str, str]] = [
        ("run_scope", scope_note),
        ("runs", f"this_run={run_count}  db_total={runs_total}"),
        (
            "findings",
            (
                f"legacy_table_this_run={findings}  db_total_legacy={findings_total}"
                + (
                    f"  canonical_session_rows={canonical_finding_rows}"
                    if canonical_finding_rows
                    else ""
                )
            ).rstrip(),
        ),
        ("baseline_summary_rows", f"this_run={findings_summary}  db_total={findings_summary_total}"),
        ("baseline_rule_hits", f"this_run={findings_detail}  db_total={findings_detail_total}"),
        ("static_string_summary", f"this_run={strings_summary}  db_total={strings_summary_total}"),
        ("static_string_samples", f"this_run={string_samples_raw}  db_total={string_samples_raw_total}"),
        ("static_string_selected", f"this_run={string_samples_selected}  db_total={string_samples_selected_total}"),
        ("string_sample_policy", f"version={selection_version or '—'}  policy={policy_version or '—'}"),
        ("buckets", f"legacy_optional this_run={buckets}  db_total={buckets_total}"),
        ("metrics", f"legacy_optional this_run={metrics}  db_total={metrics_total}"),
        ("permission_audit_snapshots", f"this_run={snapshot_count}  db_total={snapshot_total}"),
        ("permission_audit_apps", f"this_run={snapshot_apps}  db_total={snapshot_apps_total}"),
    ]

    governance_status = _governance_status()
    if governance_status:
        lines.append(("governance", governance_status))

    if group_scope:
        lines.append(("scope_note", "Group scope detected; per-package mapping not applicable."))

    if audit and audit.run_id is None:
        if audit.is_group_scope:
            lines.append(("run_linkage", "Group scope (run_id not required)"))
        elif audit.is_orphan:
            lines.append(("run_linkage", "ORPHAN (run_id missing)"))
        else:
            lines.append(("run_linkage", "run_id missing"))

    if run_status == "FAILED" and (abort_reason or abort_signal):
        reason_token = abort_reason or abort_signal or "SIGINT"
        lines.append(("abort_reason", reason_token))
        if snapshot_count == 0 and permission_matrix_rows > 0:
            lines.append(
                (
                    "permission_contract",
                    "interrupted run: static_permission_matrix persisted before permission_audit snapshot refresh",
                )
            )

    if len(run_ids) > 1 or len(static_run_ids) > 1:
        note = (
            "Multiple runs for session; this_run aggregates group scope."
            if group_scope
            else "Multiple runs for session; see canonical/latest below."
        )
        lines.append(("note", note))

    session_label = _session_label_for_stamp(session_stamp)
    lines.extend(_attempt_lines(session_label))

    width = max(len(name) for name, _ in lines) if lines else 0

    print("Persisted (authoritative)")
    print("------------------------")
    for name, detail in lines:
        print(f"  {name.ljust(width)} : {detail}")

    _render_attempt_history(session_label)

    stale_runs = _scalar_total(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status IN ('STARTED', 'RUNNING')
          AND TIMESTAMPDIFF(HOUR, created_at, UTC_TIMESTAMP()) > 24
        """
    )
    if stale_runs:
        print(
            status_messages.status(
                f"Stale STARTED/RUNNING rows >24h: {stale_runs}",
                level="warn",
            )
        )

    db_engine = str(DB_CONFIG.get("engine", "")).lower()
    audit_static_run_id = audit.static_run_id if audit and hasattr(audit, "static_run_id") else None

    if run_status == "FAILED" and (abort_reason or abort_signal):
        reason_token = abort_reason or abort_signal or "SIGINT"
        print(f"  {'status'.ljust(width)} : FAILED ({reason_token}) — counts may be partial")
    elif audit and audit.run_id is None and not audit.is_group_scope:
        if audit.is_orphan:
            print(f"  {'status'.ljust(width)} : WARN (orphan run_id missing)")
        else:
            print(f"  {'status'.ljust(width)} : WARN (run_id missing)")
    elif canonical_failures:
        unique_failures = sorted(set(str(item) for item in canonical_failures if item))
        print(f"  {'status'.ljust(width)} : WARN (canonical snapshots failed)")
        print(
            f"  {'canonical_failures'.ljust(width)} : "
            f"{len(unique_failures)} ({_format_list(unique_failures)})"
        )
    elif audit_error_tables:
        print(
            f"  {'status'.ljust(width)} : "
            f"WARN (canonical checks failed: {_format_list(audit_error_tables)})"
        )
    elif had_errors or missing:
        missing_preview = _format_list(missing)
        backend_note = " (backend=sqlite)" if db_engine == "sqlite" else ""
        if missing and db_verification_ok:
            reason = f"missing required persistence rows: {missing_preview}{backend_note}".strip()
            print(f"  {'status'.ljust(width)} : WARN ({reason})")
        else:
            reason = (
                f"missing required persistence rows: {missing_preview}{backend_note}".strip()
                if missing
                else "persist/export step reported errors (review warnings above)"
            )
            print(f"  {'status'.ljust(width)} : ERROR ({reason})")
    else:
        if group_scope:
            print(f"  {'status'.ljust(width)} : OK (group scope)")
        else:
            print(f"  {'status'.ljust(width)} : OK")

    if audit:
        status_text = db_verification_status or "SKIPPED"
        prefix = f"static_run_id={audit_static_run_id} " if audit_static_run_id is not None else ""
        print(f"  {'db_verification'.ljust(width)} : {status_text} {prefix}".rstrip())

    high_downgraded = 0
    if run_ids:
        placeholders = ",".join(["%s"] * len(run_ids))
        high_downgraded = _scalar_count(
            (
                f"SELECT COALESCE(SUM(value_num),0) FROM metrics "
                f"WHERE feature_key='findings.high_downgraded' AND run_id IN ({placeholders})"
            ),
            tuple(run_ids),
        )

    if high_downgraded:
        print(f"  {'metrics.high_downgraded'.ljust(width)} : {high_downgraded}")


__all__ = [
    "_render_db_masvs_summary",
    "_render_db_severity_table",
    "_render_persistence_footer",
]