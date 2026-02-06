"""DB verification helpers for static analysis runs."""

from __future__ import annotations

import json
import os
from collections import defaultdict
from collections.abc import Mapping, MutableMapping, Sequence

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_core.db_config import DB_CONFIG
from scytaledroid.Database.db_scripts.static_run_audit import collect_static_run_counts
from scytaledroid.Utils.DisplayUtils import status_messages, table_utils

from ..reports.masvs_summary_report import fetch_db_masvs_summary, fetch_db_masvs_summary_static
from .results_formatters import _normalize_target_sdk
from .static_run_map import extract_static_run_ids, load_run_map

SNAPSHOT_PREFIX = "perm-audit:app:"


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
        run_map = load_run_map(session_stamp)
    except Exception:
        return []
    static_ids = extract_static_run_ids(run_map)
    if static_ids:
        return static_ids
    try:
        rows = core_q.run_sql(
            """
            SELECT id
            FROM static_analysis_runs
            WHERE session_stamp = %s
            ORDER BY id DESC
            """,
            (session_stamp,),
            fetch="all",
        )
    except Exception:
        return []
    return [int(row[0]) for row in rows or [] if row and row[0] is not None]


def _per_app_severity_from_findings(
    static_run_ids: Sequence[int],
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
    severity_rows = _per_app_severity_from_findings(static_run_ids)
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
        target_sdk = _normalize_target_sdk(target_map.get(pkg))
        table_rows.append(
            [
                str(idx),
                pkg,
                target_sdk,
                str(int(pkg_counts.get("High", 0))),
                str(int(pkg_counts.get("Medium", 0))),
                str(int(pkg_counts.get("Low", 0))),
                str(int(pkg_counts.get("Info", 0))),
            ]
        )

    print()
    print("Normalized findings (deduped) — per package")
    table_utils.render_table(
        ["#", "Package", "targetSdk", "High", "Medium", "Low", "Info"],
        table_rows,
    )
    return True


def _render_db_masvs_summary() -> None:
    try:
        from scytaledroid.Utils.System import output_prefs
        ctx = output_prefs.get_run_context()
        if ctx and not ctx.persistence_ready:
            print()
            print(
                status_messages.status(
                    "DB MASVS Summary unavailable (persistence gate failed).",
                    level="warn",
                )
            )
            return
        summary = None
        session_stamp = ctx.session_stamp if ctx and ctx.session_stamp else os.getenv("SCYTALEDROID_STATIC_SESSION")
        if session_stamp:
            run_map = load_run_map(session_stamp)
            static_ids = extract_static_run_ids(run_map)
            if static_ids:
                summary = fetch_db_masvs_summary_static(static_ids[-1])
        if summary is None:
            summary = fetch_db_masvs_summary()
        if not summary:
            return
        run_id, rows = summary
        print()
        print(f"DB MASVS Summary (run_id={run_id})")
        print("MASVS matrix totals (area rollup)")
        print("Area       High  Med   Low   Info  Status  Worst CVSS                Avg  Bands")
        no_data = True
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
                if status != "NO DATA":
                    no_data = False
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
        if no_data:
            print(status_messages.status("DB MASVS Summary has no data for this run.", level="warn"))
    except Exception:
        pass


def _render_persistence_footer(
    session_stamp: str,
    *,
    had_errors: bool = False,
    canonical_failures: list[str | None] = None,
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

    def _from_audit(table: str) -> int | None:
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
    string_samples_selected = _audit_or(
        "static_string_selected_samples",
        """
        SELECT COUNT(*)
        FROM static_string_selected_samples x
        JOIN static_findings_summary s ON s.id = x.summary_id
        WHERE s.session_stamp = %s
        """,
        (session_stamp,),
    )

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
        if selection_version is not None:
            selection_version = str(selection_version)
        if policy_version is not None:
            policy_version = str(policy_version)
        return selection_version, policy_version

    selection_version, policy_version = _sample_selection_meta(latest_static_run_ids)
    buckets = _audit_or("buckets") or _count_by_run("buckets")
    metrics = _audit_or("metrics") or _count_by_run("metrics")
    findings = _audit_or("findings") or _count_by_run("findings")

    snapshot_count = _audit_or(
        "permission_audit_snapshots",
        "SELECT COUNT(*) FROM permission_audit_snapshots WHERE snapshot_key = %s",
        (snapshot_key,),
    )
    if snapshot_count == 0 and latest_static_run_ids:
        placeholders = ",".join(["%s"] * len(latest_static_run_ids))
        snapshot_count = _count(
            f"SELECT COUNT(*) FROM permission_audit_snapshots WHERE static_run_id IN ({placeholders})",
            tuple(latest_static_run_ids),
        )
    snapshot_apps = _audit_or("permission_audit_apps")
    if snapshot_apps == 0 and snapshot_id is not None:
        snapshot_apps = _count(
            "SELECT COUNT(*) FROM permission_audit_apps WHERE snapshot_id = %s",
            (snapshot_id,),
        )
    if snapshot_apps == 0 and latest_static_run_ids:
        placeholders = ",".join(["%s"] * len(latest_static_run_ids))
        snapshot_apps = _count(
            f"SELECT COUNT(*) FROM permission_audit_apps WHERE static_run_id IN ({placeholders})",
            tuple(latest_static_run_ids),
        )

    runs_total = _count_total("SELECT COUNT(*) FROM runs")
    buckets_total = _count_total("SELECT COUNT(*) FROM buckets")
    metrics_total = _count_total("SELECT COUNT(*) FROM metrics")
    findings_total = _count_total("SELECT COUNT(*) FROM findings")
    strings_summary_total = _count_total("SELECT COUNT(*) FROM static_string_summary")
    string_samples_raw_total = _count_total("SELECT COUNT(*) FROM static_string_samples")
    string_samples_selected_total = _count_total("SELECT COUNT(*) FROM static_string_selected_samples")
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
            scope_note += " static_run_id=" + ",".join(str(r) for r in latest_static_run_ids)
    run_count = len(run_ids) if (audit and audit.is_group_scope) else len(latest_run_ids)
    lines = [
        ("run_scope", scope_note),
        ("runs", f"this_run={run_count}  db_total={runs_total}"),
        ("findings", f"this_run={findings}  db_total={findings_total}"),
        (
            "baseline_summary_rows",
            f"this_run={findings_summary}  db_total={findings_summary_total}",
        ),
        (
            "baseline_rule_hits",
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
        (
            "static_string_selected",
            f"this_run={string_samples_selected}  db_total={string_samples_selected_total}",
        ),
        (
            "string_sample_policy",
            f"version={selection_version or '—'}  policy={policy_version or '—'}",
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
        lines.append(("scope_note", "Group scope detected; per-package mapping not applicable."))
    if audit and audit.run_id is None:
        if audit.is_group_scope:
            lines.append(("run_linkage", "Group scope (run_id not required)"))
        elif audit.is_orphan:
            lines.append(("run_linkage", "ORPHAN (run_id missing)"))
        else:
            lines.append(("run_linkage", "run_id missing"))
    if run_status == "ABORTED":
        reason_token = abort_reason or abort_signal or "SIGINT"
        lines.append(("abort_reason", reason_token))
    if len(run_ids) > 1 or len(static_run_ids) > 1:
        note = (
            "Multiple runs for session; this_run aggregates group scope."
            if audit and audit.is_group_scope
            else "Multiple runs for session; see canonical/latest below."
        )
        lines.append(("note", note))
    session_label = None
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
        if row and row[0]:
            session_label = str(row[0])
    except Exception:
        session_label = None
    if session_label:
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
            attempts = int(row[0]) if row and row[0] is not None else 0
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
    width = max(len(name) for name, _ in lines) if lines else 0
    for name, detail in lines:
        print(f"  {name.ljust(width)} : {detail}")

    if session_label:
        try:
            rows = core_q.run_sql(
                """
                SELECT id, COALESCE(run_started_utc, ended_at_utc, created_at) AS ts, is_canonical
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
        if rows:
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
                        ts_str = str(timestamp)
                        parsed = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        timestamp = parsed.strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        pass
                canonical_flag = "canonical" if int(row[2] or 0) else "archived"
                print(f"  - {attempt_id} ({canonical_flag}) {timestamp}")

    stale_runs = _count_total(
        """
        SELECT COUNT(*)
        FROM static_analysis_runs
        WHERE status='RUNNING'
          AND TIMESTAMPDIFF(HOUR, created_at, UTC_TIMESTAMP()) > 24
        """,
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
    audit_error_tables: list[str] = []
    if audit_counts:
        for table, (_, status) in audit_counts.items():
            if isinstance(status, str) and status.startswith("ERROR"):
                audit_error_tables.append(table)

    def _format_list(items: list[str], *, limit: int = 5) -> str:
        if not items:
            return ""
        unique = sorted(set(items))
        preview = ", ".join(unique[:limit])
        remaining = len(unique) - limit
        if remaining > 0:
            preview += f", +{remaining} more"
        return preview

    db_verification_status: str | None = None
    audit_static_run_id = audit.static_run_id if audit and hasattr(audit, "static_run_id") else None
    if audit:
        if audit.is_group_scope:
            db_verification_status = (
                "OK (group scope)" if not missing else "ERROR (missing " + ", ".join(sorted(missing)) + ")"
            )
        elif audit.run_id is None:
            if audit.is_orphan:
                db_verification_status = "ORPHAN (run_id missing)"
            else:
                db_verification_status = "SKIPPED (run_id missing)"
        elif missing:
            db_verification_status = "ERROR (missing " + ", ".join(sorted(missing)) + ")"
        else:
            db_verification_status = "OK (canonical tables populated)"
        if run_status == "ABORTED":
            db_verification_status = "ABORTED (counts may be partial)"

    db_verification_ok = bool(db_verification_status and db_verification_status.startswith("OK"))
    db_engine = str(DB_CONFIG.get("engine", "")).lower()

    if run_status == "ABORTED":
        reason_token = abort_reason or abort_signal or "SIGINT"
        print(f"  {'status'.ljust(width)} : ABORTED ({reason_token}) — counts may be partial")
    elif audit and audit.run_id is None and not audit.is_group_scope:
        if audit.is_orphan:
            print(f"  {'status'.ljust(width)} : WARN (orphan run_id missing)")
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
    elif audit_error_tables:
        print(
            f"  {'status'.ljust(width)} : WARN (canonical checks failed: {_format_list(audit_error_tables)})"
        )
    elif had_errors or missing:
        missing_preview = _format_list(missing)
        backend_note = " (backend=sqlite)" if db_engine == "sqlite" else ""
        if missing and db_verification_ok:
            reason = f"missing canonical tables: {missing_preview}{backend_note}".strip()
            print(f"  {'status'.ljust(width)} : WARN ({reason})")
        else:
            reason = (
                f"missing canonical tables: {missing_preview}{backend_note}".strip()
                if missing
                else "see logs"
            )
            print(f"  {'status'.ljust(width)} : ERROR ({reason})")
    else:
        if audit and audit.is_group_scope:
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
        params = tuple(run_ids)
        query = (
            f"SELECT COALESCE(SUM(value_num),0) FROM metrics "
            f"WHERE feature_key='findings.high_downgraded' AND run_id IN ({placeholders})"
        )
        high_downgraded = _count(query, params)
    if high_downgraded:
        print(f"  {'metrics.high_downgraded'.ljust(width)} : {high_downgraded}")


__all__ = [
    "_render_db_masvs_summary",
    "_render_db_severity_table",
    "_render_persistence_footer",
]
