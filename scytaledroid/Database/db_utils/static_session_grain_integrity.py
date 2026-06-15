"""Read-only helpers for static session grain / integrity reporting.

These functions perform **SELECT**-style work only (via ``run_sql``) and optional
filesystem reads. They do not write to the database or delete files.

See ``scripts/db/report_static_session_grain_integrity.py`` for the operator CLI.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

# Operator-facing grain legend (text reports).
GRAIN_LEGEND_LINES: tuple[str, ...] = (
    "Grain (read-only summary)",
    "---------------------------",
    "Package-level DB runs      : static_analysis_runs rows for this session",
    "APK artifact JSON reports   : optional filesystem count under reports/archive/<session>/",
    "Canonical findings rows    : base-report / package-level (static_analysis_findings)",
    "Pipeline event counters    : artifact-stage sums (CLI only; use --aggregate-json-summaries)",
    "String DB rollup           : base APK only (static_string_summary rows linked to SAR in this session)",
)


def format_grain_integrity_cli_command(
    session_stamp: str,
    *,
    scope_label: str | None = None,
    count_archive: bool = True,
    aggregate_json: bool = False,
    with_display_labels: bool = False,
) -> str:
    """Shell copy/paste for ``scripts/db/report_static_session_grain_integrity.py`` (repo root).

    Escapes single quotes in ``session_stamp`` / ``scope_label`` for typical ``bash`` use.
    """

    stamp = str(session_stamp or "").strip()
    if not stamp:
        return (
            "PYTHONPATH=. python scripts/db/report_static_session_grain_integrity.py "
            "--session-stamp <session_stamp> [--scope-label …] [--count-archive-json] "
            "[--aggregate-json-summaries] [--with-display-labels]"
        )
    safe = stamp.replace("'", "'\"'\"'")
    parts = [
        "PYTHONPATH=. python scripts/db/report_static_session_grain_integrity.py",
        f"--session-stamp '{safe}'",
    ]
    if scope_label and str(scope_label).strip():
        sl = str(scope_label).strip().replace("'", "'\"'\"'")
        parts.append(f"--scope-label '{sl}'")
    if count_archive:
        parts.append("--count-archive-json")
    if aggregate_json:
        parts.append("--aggregate-json-summaries")
    if with_display_labels:
        parts.append("--with-display-labels")
    return " ".join(parts)


def load_grain_operator_display_overrides(path: Path | str | None) -> dict[str, str]:
    """Load ``package_name`` → ``display_name`` from a hygiene-style CSV (last row wins per package)."""

    if path is None:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    by_lower: dict[str, str] = {}
    try:
        with p.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or "package_name" not in reader.fieldnames:
                return {}
            for row in reader:
                pkg = str(row.get("package_name") or "").strip()
                disp = str(row.get("display_name") or "").strip()
                if pkg and disp:
                    by_lower[pkg.lower()] = disp
    except OSError:
        return {}
    return by_lower


def operator_display_for_grain_row(
    row: Mapping[str, Any],
    *,
    override_by_lower: Mapping[str, str],
) -> str:
    """Curated CSV (if any) beats ``apps.display_name``; fall back to package id."""

    pkg = str(row.get("package_name") or "").strip()
    if not pkg:
        return "—"
    o = str(override_by_lower.get(pkg.lower()) or "").strip()
    if o:
        return o
    dn = str(row.get("display_name") or "").strip()
    if dn:
        return dn
    return pkg


def reports_archive_dir(*, session_stamp: str, data_dir: str | Path = "data") -> Path:
    """Return ``data/static_analysis/reports/archive/<session_stamp>/`` (may not exist)."""

    safe = str(session_stamp or "").strip().replace("..", "_")
    return Path(data_dir) / "static_analysis" / "reports" / "archive" / safe


def count_json_files_in_dir(directory: Path) -> int:
    """Count ``*.json`` files directly under ``directory`` (non-recursive)."""

    if not directory.is_dir():
        return 0
    return sum(1 for p in directory.iterdir() if p.is_file() and p.suffix.lower() == ".json")


def pipeline_rollup_from_report_dict(payload: Mapping[str, Any]) -> tuple[int, int, int, str | None]:
    """Return (warn_total, policy_rows, error_events, package_name) from one report dict."""

    pkg = None
    manifest = payload.get("manifest")
    if isinstance(manifest, Mapping):
        raw = manifest.get("package_name")
        if isinstance(raw, str) and raw.strip():
            pkg = raw.strip()

    meta = payload.get("metadata")
    if not isinstance(meta, Mapping):
        return 0, 0, 0, pkg

    summary = meta.get("pipeline_summary")
    if not isinstance(summary, Mapping):
        return 0, 0, 0, pkg

    sc = summary.get("status_counts")
    warn = 0
    if isinstance(sc, Mapping):
        warn = int(sc.get("WARN", 0) or 0)

    pol = 0
    for key in ("policy_fail_detectors", "finding_fail_detectors"):
        block = summary.get(key)
        if isinstance(block, list):
            pol += len(block)

    errs = summary.get("error_detectors")
    err_n = len(errs) if isinstance(errs, list) else 0

    return warn, pol, err_n, pkg


def aggregate_archive_json_pipeline_totals(
    archive_dir: Path,
    *,
    max_files: int = 5000,
) -> dict[str, Any]:
    """Sum pipeline_summary rollups from JSON files under ``archive_dir`` (read-only).

    Each file is parsed fully; large sessions should pass a bounded ``max_files``.
    """

    per_pkg: dict[str, dict[str, int]] = defaultdict(lambda: {"files": 0, "warn": 0, "policy": 0, "errors": 0})
    files_seen = 0
    parse_errors = 0

    if not archive_dir.is_dir():
        return {
            "archive_dir": str(archive_dir),
            "files_seen": 0,
            "parse_errors": 0,
            "per_package": {},
            "totals": {"files": 0, "warn": 0, "policy": 0, "errors": 0},
        }

    paths = sorted(p for p in archive_dir.iterdir() if p.is_file() and p.suffix.lower() == ".json")
    for path in paths[: max(0, int(max_files))]:
        files_seen += 1
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            parse_errors += 1
            continue
        if not isinstance(payload, Mapping):
            parse_errors += 1
            continue
        w, p, e, pkg = pipeline_rollup_from_report_dict(payload)
        key = pkg or "<unknown_package>"
        bucket = per_pkg[key]
        bucket["files"] += 1
        bucket["warn"] += w
        bucket["policy"] += p
        bucket["errors"] += e

    totals = {"files": 0, "warn": 0, "policy": 0, "errors": 0}
    for vals in per_pkg.values():
        totals["files"] += int(vals["files"])
        totals["warn"] += int(vals["warn"])
        totals["policy"] += int(vals["policy"])
        totals["errors"] += int(vals["errors"])

    return {
        "archive_dir": str(archive_dir),
        "files_seen": files_seen,
        "parse_errors": parse_errors,
        "per_package": dict(per_pkg),
        "totals": totals,
    }


def _scalar(
    run_sql: Callable[..., Any],
    sql: str,
    params: Sequence[object] | None = None,
) -> int | None:
    try:
        row = run_sql(sql, params, fetch="one", query_name="static_session_grain_integrity.scalar")
    except Exception:
        return None
    if row is None:
        return 0
    if isinstance(row, dict):
        return int(next(iter(row.values())) or 0)
    return int(row[0] or 0)


def _scope_sql(scope_label: str | None) -> tuple[str, tuple[object, ...]]:
    if scope_label and str(scope_label).strip():
        return " AND r.scope_label = %s ", (str(scope_label).strip(),)
    return "", ()


def collect_session_grain(
    run_sql: Callable[..., Any],
    *,
    session_stamp: str,
    scope_label: str | None = None,
    top_packages: int = 20,
) -> dict[str, Any]:
    """Run read-only SQL for one ``session_stamp``; return structured counters + per-package rows."""

    stamp = str(session_stamp or "").strip()
    scope_extra, scope_params = _scope_sql(scope_label)

    def qcount(sql: str, params: Sequence[object]) -> int | None:
        return _scalar(run_sql, sql, params)

    params_base: tuple[object, ...] = (stamp, *scope_params)

    n_runs = qcount(
        f"SELECT COUNT(*) FROM static_analysis_runs r WHERE r.session_stamp=%s{scope_extra}",
        params_base,
    )
    if n_runs == 0:
        return {"session_stamp": stamp, "scope_label": scope_label, "static_run_rows": 0}

    status_rows = run_sql(
        f"""
        SELECT COALESCE(r.status, ''), COUNT(*)
        FROM static_analysis_runs r
        WHERE r.session_stamp=%s{scope_extra}
        GROUP BY COALESCE(r.status, '')
        """,
        params_base,
        fetch="all",
        query_name="static_session_grain_integrity.status_breakdown",
    ) or []

    findings = qcount(
        """
        SELECT COUNT(*) FROM static_analysis_findings f
        INNER JOIN static_analysis_runs r ON r.id = f.run_id
        WHERE r.session_stamp=%s
        """
        + scope_extra,
        params_base,
    )

    matrix = qcount(
        """
        SELECT COUNT(*) FROM static_permission_matrix m
        WHERE m.run_id IN (SELECT r.id FROM static_analysis_runs r WHERE r.session_stamp=%s"""
        + scope_extra
        + ")",
        params_base,
    )

    risk = qcount(
        """
        SELECT COUNT(*) FROM static_permission_risk_vnext v
        WHERE v.run_id IN (SELECT r.id FROM static_analysis_runs r WHERE r.session_stamp=%s"""
        + scope_extra
        + ")",
        params_base,
    )

    str_summary = qcount(
        f"""
        SELECT COUNT(*) FROM static_string_summary s
        INNER JOIN static_analysis_runs r ON r.id = s.static_run_id
        WHERE r.session_stamp=%s{scope_extra}
        """,
        params_base,
    )

    str_samples = qcount(
        """
        SELECT COUNT(*) FROM static_string_samples ss
        WHERE ss.static_run_id IN (SELECT r.id FROM static_analysis_runs r WHERE r.session_stamp=%s"""
        + scope_extra
        + ")",
        params_base,
    )

    correlation = qcount(
        """
        SELECT COUNT(*) FROM static_correlation_results c
        INNER JOIN static_analysis_runs r ON r.id = c.static_run_id
        WHERE r.session_stamp=%s"""
        + scope_extra
        + "",
        params_base,
    )

    session_links = qcount(
        "SELECT COUNT(*) FROM static_session_run_links WHERE session_stamp=%s",
        (stamp,),
    )

    rollups = qcount(
        "SELECT COUNT(*) FROM static_session_rollups WHERE session_stamp=%s",
        (stamp,),
    )

    persist_fail = qcount(
        """
        SELECT COUNT(*) FROM static_persistence_failures p
        INNER JOIN static_analysis_runs r ON r.id = p.static_run_id
        WHERE r.session_stamp=%s"""
        + scope_extra
        + "",
        params_base,
    )

    reg_rows = qcount(
        """
        SELECT COUNT(*) FROM artifact_registry ar
        WHERE ar.run_type='static'
          AND (
            ar.static_run_id IN (SELECT r.id FROM static_analysis_runs r WHERE r.session_stamp=%s"""
        + scope_extra
        + """)
            OR (
              ar.static_run_id IS NULL
              AND ar.run_id IN (
                SELECT CAST(r.id AS CHAR)
                FROM static_analysis_runs r
                WHERE r.session_stamp=%s"""
        + scope_extra
        + """
              )
            )
          )
        """,
        params_base + params_base,
    )

    per_pkg_sql = (
        """
        SELECT
          r.id AS static_run_id,
          a.package_name AS package_name,
          a.display_name AS display_name,
          r.status AS run_status,
          (SELECT COUNT(*) FROM static_analysis_findings f WHERE f.run_id = r.id) AS finding_rows,
          (SELECT COUNT(*) FROM static_permission_matrix m WHERE m.run_id = r.id) AS matrix_rows,
          (SELECT COUNT(*) FROM static_permission_risk_vnext v WHERE v.run_id = r.id) AS risk_rows,
          (SELECT COUNT(*) FROM static_string_summary s WHERE s.static_run_id = r.id) AS string_summary_rows,
          (SELECT COUNT(*) FROM static_string_samples ss WHERE ss.static_run_id = r.id) AS string_sample_rows,
          (SELECT COUNT(*) FROM static_correlation_results c WHERE c.static_run_id = r.id) AS correlation_rows,
          (SELECT COUNT(*) FROM static_persistence_failures p WHERE p.static_run_id = r.id) AS persist_fail_rows,
          (SELECT COUNT(*) FROM artifact_registry ar
             WHERE ar.run_type='static'
               AND (ar.static_run_id = r.id OR (ar.static_run_id IS NULL AND ar.run_id = CAST(r.id AS CHAR)))) AS artifact_registry_rows
        FROM static_analysis_runs r
        JOIN app_versions av ON av.id = r.app_version_id
        JOIN apps a ON a.id = av.app_id
        WHERE r.session_stamp=%s
        """
        + scope_extra
        + """
        ORDER BY 12 DESC, r.id ASC
        LIMIT %s
        """
    )
    top_n = max(1, int(top_packages))
    pkg_rows = run_sql(
        per_pkg_sql,
        (*params_base, top_n),
        fetch="all",
        dictionary=True,
        query_name="static_session_grain_integrity.per_package",
    )
    packages_out: list[dict[str, Any]] = []
    if isinstance(pkg_rows, list):
        for row in pkg_rows:
            if isinstance(row, dict):
                packages_out.append(dict(row))

    status_norm: list[tuple[str, int]] = []
    for item in status_rows or []:
        if isinstance(item, dict):
            vals = list(item.values())
            if len(vals) >= 2:
                status_norm.append((str(vals[0] or ""), int(vals[1] or 0)))
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            status_norm.append((str(item[0] or ""), int(item[1] or 0)))

    return {
        "session_stamp": stamp,
        "scope_label": scope_label,
        "static_run_rows": int(n_runs or 0),
        "status_breakdown": status_norm,
        "canonical_findings_rows": int(findings or 0),
        "permission_matrix_rows": int(matrix or 0),
        "permission_risk_vnext_rows": int(risk or 0),
        "string_summary_rows": int(str_summary or 0),
        "string_sample_rows": int(str_samples or 0),
        "correlation_rows": int(correlation or 0),
        "session_link_rows": int(session_links or 0),
        "rollup_rows": int(rollups or 0),
        "persistence_failure_rows": int(persist_fail or 0),
        "artifact_registry_rows_static": int(reg_rows or 0),
        "top_packages": packages_out,
    }


def render_text_report(
    data: Mapping[str, Any],
    *,
    json_archive_count: int | None = None,
    json_aggregate: Mapping[str, Any] | None = None,
    with_display_labels: bool = False,
    display_override_by_lower: Mapping[str, str] | None = None,
) -> str:
    """Render a plain-text report for stdout."""

    lines: list[str] = []
    lines.extend(GRAIN_LEGEND_LINES)
    lines.append("")
    lines.append("Session counters")
    lines.append("----------------")
    lines.append(f"  session_stamp                 : {data.get('session_stamp')}")
    if data.get("scope_label"):
        lines.append(f"  scope_label filter            : {data.get('scope_label')}")
    lines.append(f"  static_analysis_runs          : {data.get('static_run_rows', 0)}")
    br = data.get("status_breakdown") or []
    if isinstance(br, list) and br and isinstance(br[0], (list, tuple)):
        lines.append("  status breakdown              :")
        for status, count in br:
            label = (status or "<empty>")[:24]
            lines.append(f"      {label:<24} {int(count)}")
    lines.append(f"  static_analysis_findings      : {data.get('canonical_findings_rows', 0)}")
    lines.append(f"  static_permission_matrix      : {data.get('permission_matrix_rows', 0)}")
    lines.append(f"  static_permission_risk_vnext  : {data.get('permission_risk_vnext_rows', 0)}")
    lines.append(f"  static_string_summary         : {data.get('string_summary_rows', 0)}")
    lines.append(f"  static_string_samples         : {data.get('string_sample_rows', 0)}")
    lines.append(f"  static_correlation_results    : {data.get('correlation_rows', 0)}")
    lines.append(f"  static_session_run_links      : {data.get('session_link_rows', 0)}")
    lines.append(f"  static_session_rollups        : {data.get('rollup_rows', 0)}")
    lines.append(f"  static_persistence_failures     : {data.get('persistence_failure_rows', 0)}")
    lines.append(f"  artifact_registry (static)    : {data.get('artifact_registry_rows_static', 0)}")
    if json_archive_count is not None:
        lines.append(f"  APK JSON files (archive dir)   : {json_archive_count}")
    lines.append("")
    overrides = display_override_by_lower or {}
    pkg_w = 26 if with_display_labels else 40
    lines.append(
        "Top packages (DB footprint; registry rows include dep/manifest entries — not APK count)"
        + ("; display = CSV override if present else apps.display_name else package" if with_display_labels else "")
    )
    lines.append("-" * 108)
    if with_display_labels:
        hdr = (
            f"{'package':<{pkg_w}} {'display':<22} {'run':>10} {'find':>6} {'matrix':>6} {'risk':>6} "
            f"{'strSum':>6} {'samp':>6} {'corr':>6} {'persistF':>8} {'reg':>5}"
        )
    else:
        hdr = (
            f"{'package':<{pkg_w}} {'run':>10} {'find':>6} {'matrix':>6} {'risk':>6} "
            f"{'strSum':>6} {'samp':>6} {'corr':>6} {'persistF':>8} {'reg':>5}"
        )
    lines.append(hdr)
    lines.append("-" * len(hdr))
    for row in data.get("top_packages") or []:
        if not isinstance(row, Mapping):
            continue
        pkg = str(row.get("package_name") or "")[: pkg_w - 2]
        if with_display_labels:
            disp = operator_display_for_grain_row(row, override_by_lower=overrides)[:20]
            lines.append(
                f"{pkg:<{pkg_w}} "
                f"{disp:<22} "
                f"{int(row.get('static_run_id') or 0):>10} "
                f"{int(row.get('finding_rows') or 0):>6} "
                f"{int(row.get('matrix_rows') or 0):>6} "
                f"{int(row.get('risk_rows') or 0):>6} "
                f"{int(row.get('string_summary_rows') or 0):>6} "
                f"{int(row.get('string_sample_rows') or 0):>6} "
                f"{int(row.get('correlation_rows') or 0):>6} "
                f"{int(row.get('persist_fail_rows') or 0):>8} "
                f"{int(row.get('artifact_registry_rows') or 0):>5}"
            )
        else:
            lines.append(
                f"{pkg:<{pkg_w}} "
                f"{int(row.get('static_run_id') or 0):>10} "
                f"{int(row.get('finding_rows') or 0):>6} "
                f"{int(row.get('matrix_rows') or 0):>6} "
                f"{int(row.get('risk_rows') or 0):>6} "
                f"{int(row.get('string_summary_rows') or 0):>6} "
                f"{int(row.get('string_sample_rows') or 0):>6} "
                f"{int(row.get('correlation_rows') or 0):>6} "
                f"{int(row.get('persist_fail_rows') or 0):>8} "
                f"{int(row.get('artifact_registry_rows') or 0):>5}"
            )
    if json_aggregate and int(json_aggregate.get("files_seen") or 0) > 0:
        lines.append("")
        lines.append("Optional: pipeline_summary sums from archive JSON (artifact-stage; not deduped)")
        lines.append("-" * 88)
        tot = json_aggregate.get("totals") or {}
        lines.append(
            f"  files_parsed={json_aggregate.get('files_seen')} "
            f"parse_errors={json_aggregate.get('parse_errors')} "
            f"warn_sum={tot.get('warn')} policy_list_rows_sum={tot.get('policy')} error_events_sum={tot.get('errors')}"
        )
        lines.append("")
        sub = f"{'package':<40} {'json_files':>10} {'warn_sum':>10} {'policy_rows':>12} {'err_events':>10}"
        lines.append(sub)
        lines.append("-" * len(sub))
        per = json_aggregate.get("per_package") or {}
        if isinstance(per, Mapping):
            for pkg in sorted(per.keys(), key=lambda k: (-int((per[k] or {}).get("files", 0) or 0), k))[:25]:
                b = per[pkg] if isinstance(per.get(pkg), Mapping) else {}
                lines.append(
                    f"{str(pkg)[:38]:<40} "
                    f"{int(b.get('files', 0)):>10} "
                    f"{int(b.get('warn', 0)):>10} "
                    f"{int(b.get('policy', 0)):>12} "
                    f"{int(b.get('errors', 0)):>10}"
                )
            lines.append("")
            lines.append("Artifact JSON vs canonical DB (package_name match; JSON side not deduped)")
            lines.append("-" * 88)
            hdr2 = f"{'package':<36} {'json':>5} {'art_WARN':>9} {'art_policy':>11} {'DB_find':>8}"
            lines.append(hdr2)
            lines.append("-" * len(hdr2))
            for row in data.get("top_packages") or []:
                if not isinstance(row, Mapping):
                    continue
                pkg = str(row.get("package_name") or "")
                jb = per[pkg] if isinstance(per.get(pkg), Mapping) else {}
                lines.append(
                    f"{pkg[:34]:<36} "
                    f"{int(jb.get('files', 0)):>5} "
                    f"{int(jb.get('warn', 0)):>9} "
                    f"{int(jb.get('policy', 0)):>11} "
                    f"{int(row.get('finding_rows') or 0):>8}"
                )
    lines.append("")
    lines.append("Notes")
    lines.append("-----")
    lines.append("  string_summary session count uses rows linked to static_analysis_runs (orphan summaries excluded).")
    lines.append("  Use archive JSON counts or --aggregate-json-summaries for artifact-stage rollups.")
    lines.append("  Canonical DB findings are base-report scoped; live CLI counters sum per-artifact stages.")
    lines.append(
        "  Persistence-audit 'Under latest/' counts JSON paths recorded on outcomes (hash-keyed under "
        "data/static_analysis/reports/latest/). This report's archive JSON line counts *.json under "
        "data/static_analysis/reports/archive/<session>/ — a different tree; totals usually differ."
    )
    return "\n".join(lines) + "\n"


__all__ = [
    "GRAIN_LEGEND_LINES",
    "aggregate_archive_json_pipeline_totals",
    "collect_session_grain",
    "count_json_files_in_dir",
    "format_grain_integrity_cli_command",
    "load_grain_operator_display_overrides",
    "operator_display_for_grain_row",
    "pipeline_rollup_from_report_dict",
    "render_text_report",
    "reports_archive_dir",
]
