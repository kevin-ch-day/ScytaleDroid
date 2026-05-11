"""Session-level permission evidence metrics (core DB + optional audit JSON)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages, table_utils

from .post_run_session_summary import load_persistence_audit_payload


def _classify_matrix_risk_skew(status: str, mc: int, rc: int) -> tuple[str, str] | None:
    """Return (class, reason) when matrix and vnext counts disagree; ``None`` if aligned."""

    if (mc > 0 and rc > 0) or (mc == 0 and rc == 0):
        return None
    st = (status or "").strip().upper()
    if st == "COMPLETED":
        if mc > 0 and rc == 0:
            return (
                "SUSPICIOUS_B",
                "COMPLETED: matrix rows but no vnext — investigate permission_risk.write vs matrix stage",
            )
        return (
            "SUSPICIOUS_C",
            "COMPLETED: vnext rows but no matrix — investigate matrix persistence or empty profile",
        )
    if st == "FAILED":
        if mc == 0 and rc > 0:
            return (
                "EXPECTED_A",
                "FAILED: vnext rows without matrix — often partial txn before matrix fix, "
                "or matrix gate/table issue; verify permission_matrix.write vs permission_risk.write",
            )
        return (
            "EXPECTED_A",
            "FAILED terminal: partial persistence (matrix before permission_risk failure) is common",
        )
    return (
        "EXPECTED_A",
        f"status={st or 'UNKNOWN'}: skew common for non-COMPLETED runs (skipped/partial)",
    )


def _scalar(sql: str, params: tuple[object, ...]) -> int:
    try:
        row = core_q.run_sql(sql, params, fetch="one")
    except Exception:
        return 0
    if not row:
        return 0
    return int(row[0] or 0)


def fetch_permission_session_insights(
    session_stamp: str,
    *,
    output_dir: str | None = None,
) -> dict[str, Any]:
    """Return structured permission/session metrics; gaps use ``None`` or empty lists."""

    stamp = (session_stamp or "").strip()
    out: dict[str, Any] = {
        "session_stamp": stamp,
        "gaps": [],
    }
    if not stamp:
        out["gaps"].append("session_stamp_empty")
        return out

    attempted = _scalar(
        "SELECT COUNT(*) FROM static_analysis_runs WHERE session_stamp=%s",
        (stamp,),
    )
    completed = _scalar(
        "SELECT COUNT(*) FROM static_analysis_runs WHERE session_stamp=%s AND UPPER(COALESCE(status,''))='COMPLETED'",
        (stamp,),
    )
    failed = _scalar(
        "SELECT COUNT(*) FROM static_analysis_runs WHERE session_stamp=%s AND UPPER(COALESCE(status,''))='FAILED'",
        (stamp,),
    )

    ids_sql = "SELECT id FROM static_analysis_runs WHERE session_stamp=%s"
    matrix_apps = _scalar(
        f"SELECT COUNT(DISTINCT run_id) FROM static_permission_matrix WHERE run_id IN ({ids_sql})",
        (stamp,),
    )
    matrix_rows = _scalar(
        f"SELECT COUNT(*) FROM static_permission_matrix WHERE run_id IN ({ids_sql})",
        (stamp,),
    )
    risk_apps = _scalar(
        f"SELECT COUNT(DISTINCT run_id) FROM static_permission_risk_vnext WHERE run_id IN ({ids_sql})",
        (stamp,),
    )
    risk_rows = _scalar(
        f"SELECT COUNT(*) FROM static_permission_risk_vnext WHERE run_id IN ({ids_sql})",
        (stamp,),
    )
    audit_app_rows = _scalar(
        f"SELECT COUNT(*) FROM permission_audit_apps WHERE static_run_id IN ({ids_sql})",
        (stamp,),
    )

    distinct_perm = _scalar(
        f"SELECT COUNT(DISTINCT permission_name) FROM static_permission_matrix WHERE run_id IN ({ids_sql})",
        (stamp,),
    )

    intel_configured = False
    try:
        from scytaledroid.Database.db_core import permission_intel as intel_db

        intel_configured = bool(intel_db.is_permission_intel_configured())
    except Exception:
        intel_configured = False

    mismatch_completed: list[dict[str, Any]] = []
    skew_all: list[dict[str, Any]] = []
    skew_counts: Counter[str] = Counter()
    try:
        raw = core_q.run_sql(
            """
            SELECT sar.id,
                   a.package_name,
                   COALESCE(sar.status, ''),
                   (SELECT COUNT(*) FROM static_permission_matrix m WHERE m.run_id = sar.id) AS mc,
                   (SELECT COUNT(*) FROM static_permission_risk_vnext r WHERE r.run_id = sar.id) AS rc,
                   (SELECT COUNT(*) FROM permission_audit_apps p WHERE p.static_run_id = sar.id) AS ac
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE sar.session_stamp = %s
            ORDER BY sar.id ASC
            """,
            (stamp,),
            fetch="all",
        ) or []
        for row in raw:
            if not row or len(row) < 6:
                continue
            sid = int(row[0])
            pkg = str(row[1])
            status = str(row[2])
            mc = int(row[3] or 0)
            rc = int(row[4] or 0)
            ac = int(row[5] or 0)
            skew = _classify_matrix_risk_skew(status, mc, rc)
            if skew:
                klass, reason = skew
                skew_counts[klass] += 1
                rec = {
                    "static_run_id": sid,
                    "package": pkg,
                    "status": status,
                    "matrix_rows": mc,
                    "risk_rows": rc,
                    "audit_rows": ac,
                    "skew_class": klass,
                    "likely_reason": reason,
                }
                skew_all.append(rec)
                if status.strip().upper() == "COMPLETED":
                    mismatch_completed.append(rec)
    except Exception as exc:
        out["gaps"].append(f"mismatch_query_failed:{exc.__class__.__name__}")

    dup_warn_counter: Counter[str] = Counter()
    warn_events = 0
    total_duplicate_skips = 0
    rows_with_any_persistence_warnings = 0
    payload = load_persistence_audit_payload(stamp, output_dir=output_dir)
    if payload and isinstance(payload.get("rows"), list):
        for row in payload["rows"]:
            if not isinstance(row, Mapping):
                continue
            pws = row.get("persistence_warnings") or []
            if not isinstance(pws, list):
                continue
            if pws:
                rows_with_any_persistence_warnings += 1
            for w in pws:
                if not isinstance(w, Mapping):
                    continue
                if str(w.get("warning_code") or "") != "duplicate_permission_skipped":
                    continue
                warn_events += 1
                cname = str(w.get("canonical_permission_name") or "")
                try:
                    n = int(w.get("duplicates_skipped_count") or 1)
                except (TypeError, ValueError):
                    n = 1
                total_duplicate_skips += n
                if cname:
                    dup_warn_counter[cname] += n
    else:
        out["gaps"].append("persistence_audit_json_missing_or_stale_duplicate_rollup")

    duplicate_audit_notes: list[str] = []
    if payload and isinstance(payload.get("rows"), list):
        if warn_events == 0:
            duplicate_audit_notes.append(
                "No duplicate_permission_skipped warnings in persistence audit JSON. "
                "This is expected when canonicalization did not collapse duplicate keys, "
                "or when the audit was captured before persistence_warnings were recorded "
                "(do not rewrite historical JSON)."
            )
        if rows_with_any_persistence_warnings == 0 and len(payload["rows"]) > 0:
            duplicate_audit_notes.append(
                f"No audit rows carry persistence_warnings ({len(payload['rows'])} rows). "
                "Historical runs often predate structured warning payloads."
            )

    skew_sample = sorted(
        skew_all,
        key=lambda r: (
            0 if str(r.get("skew_class", "")).startswith("SUSPICIOUS") else 1,
            int(r.get("static_run_id") or 0),
        ),
    )[:25]

    out.update(
        {
            "apps_attempted": attempted,
            "apps_completed": completed,
            "apps_failed": failed,
            "apps_with_matrix_rows": matrix_apps,
            "matrix_row_total": matrix_rows,
            "distinct_canonical_permissions_in_matrix": distinct_perm,
            "apps_with_permission_risk_rows": risk_apps,
            "permission_risk_row_total": risk_rows,
            "permission_audit_app_rows": audit_app_rows,
            "permission_intel_configured": intel_configured,
            "matrix_risk_mismatch_completed_apps": len(mismatch_completed),
            "matrix_risk_mismatch_examples": mismatch_completed[:15],
            "matrix_risk_skew_total": len(skew_all),
            "matrix_risk_skew_by_class": dict(skew_counts),
            "matrix_risk_skew_sample": skew_sample,
            "audit_rows_with_persistence_warnings": rows_with_any_persistence_warnings,
            "duplicate_skip_warnings_in_audit": warn_events,
            "duplicate_permission_skips_total_from_audit": total_duplicate_skips,
            "top_duplicate_canonical_in_audit": dup_warn_counter.most_common(10),
            "duplicate_audit_notes": duplicate_audit_notes,
        }
    )
    return out


def render_permission_session_insights(session_stamp: str, *, output_dir: str | None = None) -> None:
    data = fetch_permission_session_insights(session_stamp, output_dir=output_dir)
    print()
    menu_utils.print_section("Permission session insights (core DB)")
    menu_utils.print_metrics(
        [
            ("apps_attempted", str(data.get("apps_attempted", "—"))),
            ("apps_completed", str(data.get("apps_completed", "—"))),
            ("apps_failed", str(data.get("apps_failed", "—"))),
            ("apps_with_matrix_rows", str(data.get("apps_with_matrix_rows", "—"))),
            ("matrix_row_total", str(data.get("matrix_row_total", "—"))),
            ("distinct permissions (matrix)", str(data.get("distinct_canonical_permissions_in_matrix", "—"))),
            ("apps_with_permission_risk_rows", str(data.get("apps_with_permission_risk_rows", "—"))),
            ("permission_risk_row_total", str(data.get("permission_risk_row_total", "—"))),
            ("permission_audit_app_rows", str(data.get("permission_audit_app_rows", "—"))),
            ("Permission Intel DSN configured", str(data.get("permission_intel_configured", "—"))),
            ("matrix↔risk mismatches (COMPLETED)", str(data.get("matrix_risk_mismatch_completed_apps", "—"))),
            ("matrix↔risk skew (all statuses)", str(data.get("matrix_risk_skew_total", "—"))),
            ("audit rows w/ persistence_warnings", str(data.get("audit_rows_with_persistence_warnings", "—"))),
            ("duplicate_skip warnings (audit JSON)", str(data.get("duplicate_skip_warnings_in_audit", "—"))),
            (
                "duplicate skips total (from audit JSON)",
                str(data.get("duplicate_permission_skips_total_from_audit", "—")),
            ),
        ]
    )
    gaps = data.get("gaps") or []
    if gaps:
        print()
        for g in gaps:
            print(status_messages.status(f"Gap/TODO: {g}", level="warn"))

    for note in data.get("duplicate_audit_notes") or []:
        print()
        print(status_messages.status(note, level="info"))

    skew_by = data.get("matrix_risk_skew_by_class") or {}
    if skew_by:
        print()
        menu_utils.print_section("Matrix ↔ vnext skew counts (by class)")
        for k in sorted(skew_by.keys(), key=lambda x: (0 if x.startswith("SUSPICIOUS") else 1, x)):
            print(f"  {k}: {skew_by[k]}")

    skew_sample = data.get("matrix_risk_skew_sample") or []
    if skew_sample:
        print()
        menu_utils.print_section("Matrix ↔ vnext skew sample (debug)")
        table_utils.render_table(
            [
                "static_run_id",
                "package",
                "status",
                "matrix",
                "vnext",
                "audit",
                "class",
                "likely_reason",
            ],
            [
                [
                    str(e.get("static_run_id")),
                    str(e.get("package") or "")[:28],
                    str(e.get("status") or "")[:12],
                    str(e.get("matrix_rows")),
                    str(e.get("risk_rows")),
                    str(e.get("audit_rows")),
                    str(e.get("skew_class") or ""),
                    str(e.get("likely_reason") or "")[:56],
                ]
                for e in skew_sample
            ],
        )

    top_dup = data.get("top_duplicate_canonical_in_audit") or []
    if top_dup:
        print()
        menu_utils.print_section("Top duplicate canonicalization warnings (from audit JSON)")
        for name, cnt in top_dup:
            print(f"  {name}: {cnt}")


__all__ = [
    "fetch_permission_session_insights",
    "render_permission_session_insights",
]
