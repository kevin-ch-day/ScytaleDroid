"""Per-app permission evidence drilldown (core DB + optional report JSON)."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Utils.DisplayUtils import menu_utils, status_messages, table_utils

from .permission_session_insights import _classify_matrix_risk_skew
from .post_run_session_summary import load_persistence_audit_payload


def _scalar(sql: str, params: tuple[object, ...]) -> Any:
    try:
        row = core_q.run_sql(sql, params, fetch="one")
    except Exception:
        return None
    if not row:
        return None
    return row[0]


def _table_exists(name: str) -> bool:
    try:
        row = core_q.run_sql(
            """
            SELECT COUNT(*) FROM information_schema.tables
            WHERE table_schema = DATABASE() AND table_name = %s
            """,
            (name,),
            fetch="one",
        )
        return bool(row and int(row[0] or 0) > 0)
    except Exception:
        return False


def _resolve_run(
    *,
    session_stamp: str | None,
    package_name: str | None,
    static_run_id: int | None,
) -> tuple[dict[str, Any] | None, list[str]]:
    gaps: list[str] = []
    pkg = (package_name or "").strip()
    stamp = (session_stamp or "").strip()

    if static_run_id is not None:
        rows = core_q.run_sql(
            """
            SELECT sar.id, sar.session_stamp, sar.scope_label, sar.status,
                   a.package_name, a.display_name, av.version_name, av.version_code
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE sar.id = %s
            """,
            (int(static_run_id),),
            fetch="all",
        ) or []
        if not rows:
            return None, ["static_run_id_not_found"]
        row = rows[0]
        rec = {
            "static_run_id": int(row[0]),
            "session_stamp": str(row[1] or ""),
            "scope_label": str(row[2] or ""),
            "status": str(row[3] or ""),
            "package_name": str(row[4] or ""),
            "display_name": str(row[5] or "") or None,
            "version_name": str(row[6] or "") or None,
            "version_code": row[7],
        }
        if pkg and rec["package_name"] != pkg:
            gaps.append("package_mismatch_vs_static_run_id")
        return rec, gaps

    if not stamp or not pkg:
        return None, ["need_session_stamp_and_package_or_static_run_id"]

    rows = core_q.run_sql(
        """
        SELECT sar.id, sar.session_stamp, sar.scope_label, sar.status,
               a.package_name, a.display_name, av.version_name, av.version_code
        FROM static_analysis_runs sar
        JOIN app_versions av ON av.id = sar.app_version_id
        JOIN apps a ON a.id = av.app_id
        WHERE sar.session_stamp = %s AND a.package_name = %s
        ORDER BY sar.id DESC
        """,
        (stamp, pkg),
        fetch="all",
    ) or []
    if not rows:
        return None, ["no_static_analysis_runs_for_session_and_package"]
    if len(rows) > 1:
        gaps.append(f"multiple_runs_using_latest_id_count_{len(rows)}")
    row = rows[0]
    return {
        "static_run_id": int(row[0]),
        "session_stamp": str(row[1] or ""),
        "scope_label": str(row[2] or ""),
        "status": str(row[3] or ""),
        "package_name": str(row[4] or ""),
        "display_name": str(row[5] or "") or None,
        "version_name": str(row[6] or "") or None,
        "version_code": row[7],
    }, gaps


def _matrix_rollup(static_run_id: int) -> dict[str, Any]:
    out: dict[str, Any] = {"matrix_row_count": 0}
    try:
        row = core_q.run_sql(
            """
            SELECT
              COUNT(*) AS n,
              SUM(CASE WHEN is_runtime_dangerous <> 0 THEN 1 ELSE 0 END) AS dangerous,
              SUM(CASE WHEN is_signature <> 0 THEN 1 ELSE 0 END) AS signature,
              SUM(CASE WHEN is_privileged <> 0 THEN 1 ELSE 0 END) AS privileged,
              SUM(CASE WHEN is_special_access <> 0 THEN 1 ELSE 0 END) AS special_access,
              SUM(CASE WHEN is_custom <> 0 THEN 1 ELSE 0 END) AS custom,
              SUM(CASE WHEN source = 'framework' THEN 1 ELSE 0 END) AS src_framework,
              SUM(CASE WHEN source = 'play_services' THEN 1 ELSE 0 END) AS src_play,
              SUM(CASE WHEN source IS NOT NULL AND source NOT IN ('framework','play_services') THEN 1 ELSE 0 END) AS src_other
            FROM static_permission_matrix
            WHERE run_id = %s
            """,
            (static_run_id,),
            fetch="one",
        )
        if row:
            out["matrix_row_count"] = int(row[0] or 0)
            out["dangerous_rows"] = int(row[1] or 0)
            out["signature_rows"] = int(row[2] or 0)
            out["privileged_rows"] = int(row[3] or 0)
            out["special_access_rows"] = int(row[4] or 0)
            out["custom_rows"] = int(row[5] or 0)
            out["source_framework_rows"] = int(row[6] or 0)
            out["source_play_services_rows"] = int(row[7] or 0)
            out["source_other_namespace_rows"] = int(row[8] or 0)
    except Exception as exc:
        out["error"] = f"{exc.__class__.__name__}: {exc}"
    return out


def _top_custom_permissions(static_run_id: int, *, limit: int = 12) -> list[str]:
    try:
        rows = core_q.run_sql(
            """
            SELECT permission_name
            FROM static_permission_matrix
            WHERE run_id = %s AND is_custom <> 0
            ORDER BY permission_name ASC
            LIMIT %s
            """,
            (static_run_id, int(limit)),
            fetch="all",
        )
        return [str(r[0]) for r in rows or [] if r]
    except Exception:
        return []


def fetch_permission_app_drilldown(
    *,
    session_stamp: str | None = None,
    package_name: str | None = None,
    static_run_id: int | None = None,
    report_path: Path | str | None = None,
    output_dir: str | None = None,
) -> dict[str, Any]:
    """Return structured per-app permission metrics."""

    run, gaps = _resolve_run(
        session_stamp=session_stamp,
        package_name=package_name,
        static_run_id=static_run_id,
    )
    out: dict[str, Any] = {
        "gaps": list(gaps),
        "report_path": str(report_path) if report_path else None,
    }
    if not run:
        return out

    sid = int(run["static_run_id"])
    stamp = str(run["session_stamp"])
    pkg = str(run["package_name"])
    out["run"] = run

    risk_n = 0
    try:
        row = core_q.run_sql(
            "SELECT COUNT(*) FROM static_permission_risk_vnext WHERE run_id = %s",
            (sid,),
            fetch="one",
        )
        risk_n = int(row[0] or 0) if row else 0
    except Exception as exc:
        out["gaps"].append(f"risk_count_failed:{exc.__class__.__name__}")

    audit_n = 0
    try:
        row = core_q.run_sql(
            """
            SELECT COUNT(*) FROM permission_audit_apps
            WHERE static_run_id = %s AND package_name = %s
            """,
            (sid, pkg),
            fetch="one",
        )
        audit_n = int(row[0] or 0) if row else 0
    except Exception as exc:
        out["gaps"].append(f"audit_apps_count_failed:{exc.__class__.__name__}")

    matrix = _matrix_rollup(sid)
    mc = int(matrix.get("matrix_row_count") or 0)

    skew = _classify_matrix_risk_skew(str(run.get("status") or ""), mc, risk_n)
    skew_rec = None
    if skew:
        skew_rec = {"class": skew[0], "reason": skew[1]}

    intel_configured = False
    try:
        from scytaledroid.Database.db_core import permission_intel as intel_db

        intel_configured = bool(intel_db.is_permission_intel_configured())
    except Exception:
        intel_configured = False

    dup_events = 0
    dup_total = 0
    dup_top: list[tuple[str, int]] = []
    payload = load_persistence_audit_payload(stamp, output_dir=output_dir)
    if payload and isinstance(payload.get("rows"), list):
        for row in payload["rows"]:
            if not isinstance(row, Mapping):
                continue
            if str(row.get("package_name") or row.get("package") or "") != pkg:
                continue
            pws = row.get("persistence_warnings") or []
            if not isinstance(pws, list):
                continue
            for w in pws:
                if not isinstance(w, Mapping):
                    continue
                if str(w.get("warning_code") or "") != "duplicate_permission_skipped":
                    continue
                dup_events += 1
                cname = str(w.get("canonical_permission_name") or "")
                try:
                    n = int(w.get("duplicates_skipped_count") or 1)
                except (TypeError, ValueError):
                    n = 1
                dup_total += n
                if cname:
                    dup_top.append((cname, n))
    else:
        out["gaps"].append("persistence_audit_json_missing_duplicate_rollup_unavailable")

    dup_top.sort(key=lambda t: (-t[1], t[0]))
    dup_top = dup_top[:10]

    raw_declared: list[str] = []
    raw_declared_n: int | None = None
    report_note = None
    if report_path:
        try:
            from scytaledroid.StaticAnalysis.persistence.reports import load_report

            rpt = load_report(Path(report_path).resolve())
            perms = getattr(rpt.permissions, "declared", ()) or ()
            raw_declared = [str(p) for p in perms if p]
            raw_declared_n = len(raw_declared)
        except Exception as exc:
            report_note = f"report_load_failed:{exc.__class__.__name__}"

    risk_score_row = None
    if _table_exists("risk_scores"):
        try:
            sc = str(run.get("scope_label") or "")
            row = core_q.run_sql(
                """
                SELECT risk_score, risk_grade, dangerous, signature, vendor
                FROM risk_scores
                WHERE session_stamp = %s AND package_name = %s AND scope_label = %s
                LIMIT 1
                """,
                (stamp, pkg, sc),
                fetch="one",
            )
            if row:
                risk_score_row = {
                    "risk_score": row[0],
                    "risk_grade": row[1],
                    "dangerous": row[2],
                    "signature": row[3],
                    "vendor": row[4],
                }
        except Exception as exc:
            out["gaps"].append(f"risk_scores_lookup_failed:{exc.__class__.__name__}")

    distinct_canon = _scalar(
        "SELECT COUNT(DISTINCT permission_name) FROM static_permission_matrix WHERE run_id=%s",
        (sid,),
    )
    distinct_canon_i = int(distinct_canon or 0) if distinct_canon is not None else mc

    out.update(
        {
            "canonical_matrix_rows": mc,
            "distinct_matrix_permission_name_count": distinct_canon_i,
            "permission_risk_vnext_rows": risk_n,
            "permission_audit_app_rows": audit_n,
            "permission_intel_configured": intel_configured,
            "matrix_rollup": matrix,
            "matrix_risk_consistency": skew_rec,
            "duplicate_skip_events_in_audit": dup_events,
            "duplicate_skips_total_in_audit": dup_total,
            "top_duplicate_canonical_in_audit": dup_top,
            "raw_permissions_from_report": {
                "declared_count": raw_declared_n,
                "declared_sample": raw_declared[:20],
                "note": report_note,
            },
            "classification_heuristic": {
                "aosp_like_rows": int(matrix.get("source_framework_rows") or 0),
                "play_services_rows": int(matrix.get("source_play_services_rows") or 0),
                "other_namespace_rows": int(matrix.get("source_other_namespace_rows") or 0),
                "custom_flag_rows": int(matrix.get("custom_rows") or 0),
                "note": "Heuristic from static_permission_matrix.source and is_custom; not a governance proof.",
            },
            "top_custom_permissions": _top_custom_permissions(sid),
            "risk_scores_snapshot": risk_score_row,
        }
    )
    return out


def render_permission_app_drilldown(
    *,
    session_stamp: str | None = None,
    package_name: str | None = None,
    static_run_id: int | None = None,
    report_path: Path | str | None = None,
    output_dir: str | None = None,
) -> None:
    data = fetch_permission_app_drilldown(
        session_stamp=session_stamp,
        package_name=package_name,
        static_run_id=static_run_id,
        report_path=report_path,
        output_dir=output_dir,
    )
    print()
    menu_utils.print_section("Per-app permission drilldown")
    run = data.get("run")
    if not isinstance(run, Mapping):
        for g in data.get("gaps") or ["unknown_error"]:
            print(status_messages.status(str(g), level="warn"))
        return

    menu_utils.print_metrics(
        [
            ("package", str(run.get("package_name") or "")),
            ("display_name", str(run.get("display_name") or "—")),
            ("static_run_id", str(run.get("static_run_id") or "")),
            ("session_stamp", str(run.get("session_stamp") or "")),
            ("status", str(run.get("status") or "")),
            ("matrix rows", str(data.get("canonical_matrix_rows"))),
            ("distinct permission_name (matrix)", str(data.get("distinct_matrix_permission_name_count"))),
            ("vnext rows", str(data.get("permission_risk_vnext_rows"))),
            ("permission_audit_apps rows", str(data.get("permission_audit_app_rows"))),
            ("Permission Intel configured", str(data.get("permission_intel_configured"))),
            ("duplicate_skip events (audit JSON)", str(data.get("duplicate_skip_events_in_audit"))),
            ("duplicate skips total (audit JSON)", str(data.get("duplicate_skips_total_in_audit"))),
        ]
    )

    h = data.get("classification_heuristic") or {}
    if isinstance(h, Mapping):
        print()
        menu_utils.print_section("Classification (heuristic, matrix columns)")
        menu_utils.print_metrics(
            [
                ("AOSP-like (source=framework)", str(h.get("aosp_like_rows"))),
                ("Play services source rows", str(h.get("play_services_rows"))),
                ("Other namespace source rows", str(h.get("other_namespace_rows"))),
                ("is_custom flag rows", str(h.get("custom_flag_rows"))),
            ]
        )
        note = h.get("note")
        if note:
            print(status_messages.status(str(note), level="info"))

    mr = data.get("matrix_rollup") or {}
    if isinstance(mr, Mapping) and mr.get("matrix_row_count") is not None:
        print()
        menu_utils.print_section("Matrix flag rollups")
        menu_utils.print_metrics(
            [
                ("dangerous rows", str(mr.get("dangerous_rows"))),
                ("signature rows", str(mr.get("signature_rows"))),
                ("privileged rows", str(mr.get("privileged_rows"))),
                ("special_access rows", str(mr.get("special_access_rows"))),
            ]
        )

    skew = data.get("matrix_risk_consistency")
    print()
    menu_utils.print_section("Matrix ↔ vnext consistency")
    if isinstance(skew, Mapping):
        print(f"  class: {skew.get('class')}")
        print(f"  reason: {skew.get('reason')}")
    else:
        print("  aligned (or both empty)")

    raw = data.get("raw_permissions_from_report") or {}
    if isinstance(raw, Mapping):
        print()
        menu_utils.print_section("Raw manifest permissions (report JSON, if provided)")
        print(f"  declared_count: {raw.get('declared_count', '—')}")
        if raw.get("note"):
            print(status_messages.status(str(raw.get("note")), level="warn"))
        sample = raw.get("declared_sample") or []
        if isinstance(sample, list) and sample:
            for line in sample[:12]:
                print(f"    {line}")

    top_c = data.get("top_custom_permissions") or []
    if top_c:
        print()
        menu_utils.print_section("Top custom-flag permissions (alphabetic sample)")
        for name in top_c:
            print(f"  {name}")

    dup = data.get("top_duplicate_canonical_in_audit") or []
    if dup:
        print()
        menu_utils.print_section("Duplicate canonicalization (from audit JSON)")
        table_utils.render_table(["canonical_permission_name", "skips"], [[a, str(b)] for a, b in dup])

    rs = data.get("risk_scores_snapshot")
    if isinstance(rs, Mapping):
        print()
        menu_utils.print_section("risk_scores row (session + package + scope)")
        menu_utils.print_metrics([(k, str(v)) for k, v in rs.items()])

    gaps = [g for g in (data.get("gaps") or []) if g]
    if gaps:
        print()
        for g in gaps:
            print(status_messages.status(f"Gap/TODO: {g}", level="warn"))


__all__ = [
    "fetch_permission_app_drilldown",
    "render_permission_app_drilldown",
]
