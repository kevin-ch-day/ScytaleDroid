#!/usr/bin/env python3
"""Read-only core DB static schema inventory (no DDL).

Classifies canonical static, permission cohort, derived, and legacy objects; reports
``information_schema`` presence, approximate row counts for base tables, optional
``status_tags`` on legacy tables (plus ``sparse_zero_table_ok`` for optional dynload
detector tables when ``TABLE_ROWS==0``), optional legacy names only when present
(``correlations``), and **view dependencies** (``VIEW_TABLE_USAGE`` when available, else
``VIEW_DEFINITION`` backtick parse — best-effort).

Run from repo root::

  PYTHONPATH=. python scripts/db/static_schema_audit.py
  PYTHONPATH=. python scripts/db/static_schema_audit.py --json

See ``docs/maintenance/static_database_schema_audit_plan.md`` for semantics and next steps.

Exit codes: 0 report emitted; 1 DB disabled / connection or query failure.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any

# Base tables treated as legacy for dependency warnings + empty/stale heuristics.
LEGACY_TABLE_NAMES = frozenset({"runs", "findings", "metrics", "buckets", "contributors", "correlations"})
_VIEW_BTICK = re.compile(r"`([^`]+)`")

# Curated catalogue: name -> metadata (see static_database_schema_audit_plan.md)
AUDIT_PROFILES: dict[str, dict[str, str]] = {
    "static_analysis_runs": {
        "classification": "canonical_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "StaticAnalysis/cli/persistence/run_writers.py, run_summary.py",
        "readers_hint": "menus, run_health, db_verification, audit_static_session.py",
        "notes": "Primary static run identity; schema_gate required.",
    },
    "static_analysis_findings": {
        "classification": "canonical_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "persistence stage writers / ingest",
        "readers_hint": "reporting, menus, Web views",
        "notes": "",
    },
    "static_permission_matrix": {
        "classification": "canonical_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "permission_matrix.py persistence",
        "readers_hint": "views, menus, reconcile",
        "notes": "",
    },
    "static_permission_risk_vnext": {
        "classification": "canonical_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "permission_risk.py persistence",
        "readers_hint": "views_permission, menus, artifact_map DB skew",
        "notes": "",
    },
    "static_string_summary": {
        "classification": "canonical_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "persist_static_sections / string writers",
        "readers_hint": "run_health, menus",
        "notes": "",
    },
    "static_string_samples": {
        "classification": "canonical_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "string persistence",
        "readers_hint": "run_health, menus",
        "notes": "",
    },
    "static_string_sample_sets": {
        "classification": "canonical_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "Database/db_func/static_analysis/string_analysis.py; db_queries/static_analysis/string_analysis.py",
        "readers_hint": "db_verification.py; query_runner.py; menu_actions.py; health_checks/summary.py",
        "notes": "String pipeline sibling to static_string_summary/samples; not in static_schema_gate required_tables.",
    },
    "static_string_selected_samples": {
        "classification": "canonical_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "Database/db_func/static_analysis/string_analysis.py; db_queries/static_analysis/string_analysis.py",
        "readers_hint": "db_verification.py; query_runner.py; menu_actions.py; health_checks/summary.py",
        "notes": "Selected sample rows per set; pairs with static_string_sample_sets.",
    },
    "static_correlation_results": {
        "classification": "derived_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "StaticAnalysis/cli/persistence/run_summary.py (correlation stage INSERT)",
        "readers_hint": "session_diagnostics.py; UI/menu SQL (tests/ui/test_global_menu_rollout.py patterns)",
        "notes": "Canonical correlation payload table; superseded legacy base name correlations. Not in static_schema_gate.",
    },
    "static_fileproviders": {
        "classification": "canonical_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "Database/db_queries/harvest/storage_surface.py; StaticAnalysis/persistence/ingest.py",
        "readers_hint": "views_web.py; health_checks.py; session_diagnostics.py",
        "notes": "File-provider / authority detector persistence; tests/static_analysis/test_ingest_provider_compat.py.",
    },
    "static_provider_acl": {
        "classification": "canonical_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "Database/db_queries/harvest/storage_surface.py (with static_fileproviders)",
        "readers_hint": "views_web.py; health_checks.py; session_diagnostics.py",
        "notes": "ACL rows for provider authorities; sparse row counts are normal.",
    },
    "static_dynload_events": {
        "classification": "canonical_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "StaticAnalysis/modules/dynamic_loading.py → Database/db_func/harvest/dynamic_loading.replace_events; db_queries/harvest/dynamic_loading.py",
        "readers_hint": "Database/db_queries/views_static.py (dynload module_key)",
        "notes": "DynamicLoadingDetector persistence; whole table may be empty if detector never emitted rows.",
    },
    "static_reflection_calls": {
        "classification": "canonical_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "StaticAnalysis/modules/dynamic_loading.py → db_func/harvest/dynamic_loading.replace_reflection_calls",
        "readers_hint": "views_static.py; views_dynamic.py",
        "notes": "Pairs with static_dynload_events; empty table is plausible when dynload path unused.",
    },
    "static_session_run_links": {
        "classification": "canonical_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "session link persistence",
        "readers_hint": "run_persistence_queries, menus",
        "notes": "schema_gate required.",
    },
    "static_session_rollups": {
        "classification": "canonical_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "session finalizer / rollup writers",
        "readers_hint": "menus, audits",
        "notes": "schema_gate required.",
    },
    "static_persistence_failures": {
        "classification": "canonical_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "persistence failure capture",
        "readers_hint": "post_run diagnostics, artifact_map",
        "notes": "",
    },
    "permission_audit_snapshots": {
        "classification": "canonical_keep",
        "owner_domain": "Permissions",
        "writers_hint": "PermissionAuditAccumulator / persistence",
        "readers_hint": "health_checks_permission, menus",
        "notes": "permissions_schema_gate.",
    },
    "permission_audit_apps": {
        "classification": "canonical_keep",
        "owner_domain": "Permissions",
        "writers_hint": "permission audit persistence",
        "readers_hint": "health_checks_permission, Web views",
        "notes": "",
    },
    "permission_signal_observations": {
        "classification": "canonical_keep",
        "owner_domain": "Permissions",
        "writers_hint": "permission audit pipeline",
        "readers_hint": "reporting / observation readers",
        "notes": "permissions_schema_gate.",
    },
    "artifact_registry": {
        "classification": "derived_keep",
        "owner_domain": "Cross-cutting",
        "writers_hint": "artifact_registry.record_artifacts; manifest_writer; dep_export; permission audit",
        "readers_hint": "manifest_writer SELECT; dynamic db_maintenance integrity views",
        "notes": "Not static_analysis_findings; path/hash registry.",
    },
    "risk_scores": {
        "classification": "bridge_compat",
        "owner_domain": "Permissions",
        "writers_hint": "permission_risk.py (upsert)",
        "readers_hint": "views_permission.py; run_persistence_queries reconcile",
        "notes": "Bridge/reconcile surface vs static_permission_matrix; not primary findings truth.",
    },
    "static_findings_summary": {
        "classification": "derived_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "db_func/static_analysis/static_findings.py",
        "readers_hint": "db_verification, query_runner, views_web",
        "notes": "Baseline summary; distinct from static_analysis_findings.",
    },
    "static_findings": {
        "classification": "derived_keep",
        "owner_domain": "StaticAnalysis",
        "writers_hint": "db_func/static_analysis/static_findings.py",
        "readers_hint": "db_verification, masvs_summary_report",
        "notes": "Baseline detail rows.",
    },
    "runs": {
        "classification": "legacy_freeze",
        "owner_domain": "Legacy",
        "writers_hint": "(none expected for new static)",
        "readers_hint": "historical readers if any",
        "notes": "empty_expected under canonical-only writers.",
    },
    "findings": {
        "classification": "legacy_freeze",
        "owner_domain": "Legacy",
        "writers_hint": "(none expected for new static)",
        "readers_hint": "legacy",
        "notes": "Legacy findings table name; do not confuse with static_analysis_findings.",
    },
    "metrics": {
        "classification": "legacy_freeze",
        "owner_domain": "Legacy",
        "writers_hint": "(none expected)",
        "readers_hint": "legacy",
        "notes": "",
    },
    "buckets": {
        "classification": "legacy_freeze",
        "owner_domain": "Legacy",
        "writers_hint": "(none expected)",
        "readers_hint": "legacy",
        "notes": "",
    },
    "contributors": {
        "classification": "legacy_freeze",
        "owner_domain": "Legacy",
        "writers_hint": "(unknown)",
        "readers_hint": "legacy",
        "notes": "Classify drop_later_candidate only after consumer grep.",
    },
    # High-signal views (read-only inventory; DDL in repo)
    "v_static_handoff_v1": {
        "classification": "derived_keep",
        "owner_domain": "StaticAnalysis/Dynamic handoff",
        "writers_hint": "(view DDL only)",
        "readers_hint": "dynamic plan loader, schema_gate",
        "notes": "HIGH RISK to change; see AGENTS.md static-to-dynamic handoff.",
    },
    "v_run_identity": {
        "classification": "derived_keep",
        "owner_domain": "StaticAnalysis/Dynamic",
        "writers_hint": "(view DDL only)",
        "readers_hint": "cohort identity consumers",
        "notes": "HIGH RISK to change.",
    },
}

# Legacy base names that may never have been created in a given catalog — emit a row only
# when present; do not warn when absent (unlike mandatory AUDIT_PROFILES).
AUDIT_OPTIONAL_LEGACY: dict[str, dict[str, str]] = {
    "correlations": {
        "classification": "legacy_freeze",
        "owner_domain": "Legacy",
        "writers_hint": "(inactive — scytaledroid/Database/db_utils/bridge_posture.py; canonical: static_correlation_results)",
        "readers_hint": "historical only if table exists",
        "notes": "Optional legacy name; many installs never had this table. No missing-schema warning.",
    },
}


def _view_table_usage_supported(run_sql) -> bool:
    try:
        row = run_sql(
            "SELECT COUNT(*) AS c FROM information_schema.tables "
            "WHERE table_schema = 'information_schema' AND table_name = 'VIEW_TABLE_USAGE'",
            (),
            fetch="one_dict",
        )
        return int(row.get("c") or 0) > 0 if row else False
    except Exception:
        return False


def _all_object_names_in_schema(run_sql, *, db: str) -> frozenset[str]:
    try:
        rows = run_sql(
            "SELECT TABLE_NAME AS n FROM information_schema.tables WHERE TABLE_SCHEMA=%s",
            (db,),
            fetch="all_dict",
        ) or []
        return frozenset(str(r["n"]) for r in rows if r.get("n"))
    except Exception:
        return frozenset()


def _view_deps_table_usage(run_sql, *, db: str, view_name: str) -> list[str] | None:
    try:
        rows = run_sql(
            "SELECT DISTINCT TABLE_SCHEMA AS ts, TABLE_NAME AS tn "
            "FROM information_schema.VIEW_TABLE_USAGE "
            "WHERE VIEW_SCHEMA=%s AND VIEW_NAME=%s",
            (db, view_name),
            fetch="all_dict",
        ) or []
        out: list[str] = []
        for r in rows:
            ts, tn = r.get("ts"), r.get("tn")
            if not tn:
                continue
            ts_s = str(ts or db)
            if ts_s != db:
                out.append(f"{ts_s}.{tn}")
            else:
                out.append(str(tn))
        return sorted(set(out))
    except Exception:
        return None


def _view_deps_definition(
    run_sql, *, db: str, view_name: str, schema_names: frozenset[str]
) -> list[str]:
    try:
        row = run_sql(
            "SELECT VIEW_DEFINITION AS d FROM information_schema.VIEWS "
            "WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s",
            (db, view_name),
            fetch="one_dict",
        )
        if not row:
            return []
        raw = str(row.get("d") or "")
        candidates = {m.group(1) for m in _VIEW_BTICK.finditer(raw)}
        hits = {n for n in candidates if n in schema_names and n != view_name}
        return sorted(hits)
    except Exception:
        return []


def _resolve_view_dependencies(
    run_sql,
    *,
    db: str,
    view_name: str,
    schema_names: frozenset[str],
    prefer_table_usage: bool,
) -> tuple[list[str], str]:
    if prefer_table_usage:
        u = _view_deps_table_usage(run_sql, db=db, view_name=view_name)
        if u is not None:
            return u, "VIEW_TABLE_USAGE"
    d = _view_deps_definition(run_sql, db=db, view_name=view_name, schema_names=schema_names)
    if d:
        return d, "VIEW_DEFINITION"
    return [], "unavailable"


def _legacy_hits_from_deps(deps: list[str]) -> list[str]:
    found: set[str] = set()
    for dep in deps:
        tail = dep.split(".")[-1] if "." in dep else dep
        if tail in LEGACY_TABLE_NAMES:
            found.add(tail)
    return sorted(found)


def _status_tags_for_legacy_table(*, name: str, otype: str, row_count: int | None) -> list[str]:
    if name not in LEGACY_TABLE_NAMES or otype != "BASE TABLE":
        return []
    if row_count == 0:
        return ["empty_expected"]
    if row_count is not None and row_count > 0:
        return ["stale_review"]
    return []


SPARSE_ZERO_OK_TABLES = frozenset({"static_dynload_events", "static_reflection_calls"})


def _status_tags_sparse_detector_tables(*, name: str, otype: str, row_count: int | None) -> list[str]:
    """Whole-table zero rows can be normal if DynamicLoadingDetector never persisted data."""
    if name not in SPARSE_ZERO_OK_TABLES or otype != "BASE TABLE":
        return []
    if row_count == 0:
        return ["sparse_zero_table_ok"]
    return []


def _fetch_db_name(run_sql) -> str | None:
    try:
        row = run_sql("SELECT DATABASE() AS dbname", (), fetch="one_dict")
        if not row:
            return None
        val = row.get("dbname")
        return str(val) if val else None
    except Exception:
        return None


def _fetch_ismeta(run_sql, *, db: str, table_name: str) -> dict[str, Any] | None:
    sql = (
        "SELECT TABLE_NAME, TABLE_TYPE, TABLE_ROWS, ENGINE "
        "FROM information_schema.TABLES "
        "WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s"
    )
    try:
        row = run_sql(sql, (db, table_name), fetch="one_dict")
        return dict(row) if row else None
    except Exception:
        return None


def _discover_static_permission_objects(run_sql, *, db: str) -> list[str]:
    sql = (
        "SELECT TABLE_NAME FROM information_schema.TABLES "
        "WHERE TABLE_SCHEMA=%s AND (TABLE_NAME LIKE %s OR TABLE_NAME LIKE %s) "
        "ORDER BY TABLE_NAME"
    )
    try:
        rows = run_sql(sql, (db, "static\\_%", "permission\\_%"), fetch="all_dict") or []
    except Exception:
        return []
    names: list[str] = []
    for row in rows:
        name = row.get("TABLE_NAME")
        if name:
            names.append(str(name))
    return names


def _append_row(
    rows_out: list[dict[str, Any]],
    warnings: list[str],
    *,
    name: str,
    profile: dict[str, str] | None,
    meta: dict[str, Any] | None,
    missing: bool,
    run_sql,
    db: str,
    schema_names: frozenset[str],
    prefer_view_table_usage: bool,
) -> None:
    if missing or not meta:
        if profile:
            rows_out.append(
                {
                    "name": name,
                    "object_type": "MISSING",
                    "row_count": None,
                    "row_count_note": "object not present in information_schema.TABLES",
                    "classification": profile["classification"],
                    "owner_domain": profile["owner_domain"],
                    "writers_hint": profile["writers_hint"],
                    "readers_hint": profile["readers_hint"],
                    "notes": profile.get("notes", ""),
                    "status_tags": [],
                    "view_dependencies": [],
                    "view_dependency_legacy_hits": [],
                    "view_dependency_engine": None,
                }
            )
        return

    otype = str(meta.get("TABLE_TYPE") or "")
    engine = meta.get("ENGINE")
    rc = meta.get("TABLE_ROWS")
    note = ""
    if otype == "BASE TABLE":
        note = "information_schema.TABLE_ROWS (often approximate for InnoDB)"
    elif otype == "VIEW":
        note = "views have no TABLE_ROWS; count not queried in v1"

    row_count: int | None = None
    if rc is not None:
        try:
            row_count = int(rc)
        except (TypeError, ValueError):
            row_count = None

    classification = (profile or {}).get("classification", "unknown_needs_review")
    owner_domain = (profile or {}).get("owner_domain", "unknown")
    writers_hint = (profile or {}).get("writers_hint", "grep scytaledroid/ + scripts/")
    readers_hint = (profile or {}).get("readers_hint", "grep scytaledroid/ + scripts/")
    notes = (profile or {}).get("notes", "")
    if not profile:
        notes = (
            "Discovered via static_% / permission_% prefix; add to AUDIT_PROFILES after review."
            if not notes
            else notes
        )

    status_tags = _status_tags_for_legacy_table(name=name, otype=otype, row_count=row_count)
    status_tags.extend(
        _status_tags_sparse_detector_tables(name=name, otype=otype, row_count=row_count)
    )
    view_dependencies: list[str] = []
    view_dependency_engine: str | None = None
    legacy_dep_hits: list[str] = []
    if otype == "VIEW":
        view_dependencies, view_dependency_engine = _resolve_view_dependencies(
            run_sql,
            db=db,
            view_name=name,
            schema_names=schema_names,
            prefer_table_usage=prefer_view_table_usage,
        )
        legacy_dep_hits = _legacy_hits_from_deps(view_dependencies)
        if legacy_dep_hits:
            warnings.append(
                f"View {name} references legacy table(s): {', '.join(legacy_dep_hits)}"
            )

    rows_out.append(
        {
            "name": name,
            "object_type": otype,
            "engine": engine,
            "row_count": row_count,
            "row_count_note": note,
            "classification": classification,
            "owner_domain": owner_domain,
            "writers_hint": writers_hint,
            "readers_hint": readers_hint,
            "notes": notes,
            "status_tags": status_tags,
            "view_dependencies": view_dependencies,
            "view_dependency_legacy_hits": legacy_dep_hits,
            "view_dependency_engine": view_dependency_engine,
        }
    )


def _build_report_rows(
    run_sql,
    *,
    db: str,
    include_catalogue_missing: bool,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    warnings: list[str] = []
    rows_out: list[dict[str, Any]] = []
    schema_names = _all_object_names_in_schema(run_sql, db=db)
    prefer_vtu = _view_table_usage_supported(run_sql)

    ordered_names = sorted(AUDIT_PROFILES.keys())
    for name in ordered_names:
        profile = AUDIT_PROFILES[name]
        meta = _fetch_ismeta(run_sql, db=db, table_name=name)
        if not meta:
            if include_catalogue_missing:
                _append_row(
                    rows_out,
                    warnings,
                    name=name,
                    profile=profile,
                    meta=None,
                    missing=True,
                    run_sql=run_sql,
                    db=db,
                    schema_names=schema_names,
                    prefer_view_table_usage=prefer_vtu,
                )
            else:
                warnings.append(f"Catalogued object not in schema: {name}")
            continue
        _append_row(
            rows_out,
            warnings,
            name=name,
            profile=profile,
            meta=meta,
            missing=False,
            run_sql=run_sql,
            db=db,
            schema_names=schema_names,
            prefer_view_table_usage=prefer_vtu,
        )

    for name in sorted(AUDIT_OPTIONAL_LEGACY.keys()):
        if name not in schema_names:
            continue
        profile = AUDIT_OPTIONAL_LEGACY[name]
        meta = _fetch_ismeta(run_sql, db=db, table_name=name)
        if not meta:
            continue
        _append_row(
            rows_out,
            warnings,
            name=name,
            profile=profile,
            meta=meta,
            missing=False,
            run_sql=run_sql,
            db=db,
            schema_names=schema_names,
            prefer_view_table_usage=prefer_vtu,
        )

    discovered = set(_discover_static_permission_objects(run_sql, db=db))
    catalogued = set(AUDIT_PROFILES.keys()) | set(AUDIT_OPTIONAL_LEGACY.keys())
    for name in sorted(discovered - catalogued):
        meta = _fetch_ismeta(run_sql, db=db, table_name=name)
        if not meta:
            continue
        _append_row(
            rows_out,
            warnings,
            name=name,
            profile=None,
            meta=meta,
            missing=False,
            run_sql=run_sql,
            db=db,
            schema_names=schema_names,
            prefer_view_table_usage=prefer_vtu,
        )

    rows_out.sort(key=lambda r: (r.get("classification") or "", r.get("name") or ""))

    engines = {r.get("view_dependency_engine") for r in rows_out if r.get("view_dependency_engine")}
    if "VIEW_TABLE_USAGE" in engines:
        top_engine = "VIEW_TABLE_USAGE"
    elif "VIEW_DEFINITION" in engines:
        top_engine = "VIEW_DEFINITION"
    else:
        top_engine = "unavailable"
    meta_out = {
        "view_dependency_engine": top_engine,
        "view_table_usage_supported": prefer_vtu,
        "schema_object_count": len(schema_names),
    }
    return rows_out, warnings, meta_out


def _print_human(
    rows: list[dict[str, Any]],
    warnings: list[str],
    *,
    db: str,
    audit_meta: dict[str, Any],
) -> None:
    print("ScytaleDroid static schema audit (read-only)")
    print(f"  database: {db}")
    print(f"  view_dependency_engine (views): {audit_meta.get('view_dependency_engine')}")
    print(f"  schema_object_count: {audit_meta.get('schema_object_count')}")
    print()
    for row in rows:
        print(f"{row.get('name')} [{row.get('object_type')}]")
        print(f"  classification   : {row.get('classification')}")
        tags = row.get("status_tags") or []
        if tags:
            print(f"  status_tags      : {', '.join(str(t) for t in tags)}")
        print(f"  owner_domain     : {row.get('owner_domain')}")
        rc = row.get("row_count")
        print(f"  row_count        : {rc if rc is not None else 'n/a'}")
        if row.get("row_count_note"):
            print(f"  row_count_note   : {row.get('row_count_note')}")
        if row.get("engine"):
            print(f"  engine           : {row.get('engine')}")
        vde = row.get("view_dependency_engine")
        if row.get("object_type") == "VIEW":
            print(f"  view_dep_engine  : {vde}")
            deps = row.get("view_dependencies") or []
            if deps:
                preview = ", ".join(deps[:24])
                tail = f" … (+{len(deps) - 24} more)" if len(deps) > 24 else ""
                print(f"  view_dependencies: {preview}{tail}")
            else:
                print("  view_dependencies: (none resolved)")
            leg = row.get("view_dependency_legacy_hits") or []
            if leg:
                print(f"  legacy_via_view  : {', '.join(leg)}")
        print(f"  writers_hint     : {row.get('writers_hint')}")
        print(f"  readers_hint     : {row.get('readers_hint')}")
        if row.get("notes"):
            print(f"  notes            : {row.get('notes')}")
        print()
    if warnings:
        print("Warnings:")
        for w in warnings:
            print(f"  - {w}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON array instead of human text.",
    )
    parser.add_argument(
        "--list-missing-catalogue",
        action="store_true",
        help="Emit MISSING rows for catalogue objects absent from schema (default: warn only).",
    )
    args = parser.parse_args()

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
    except ImportError as exc:
        sys.stderr.write(f"Import failed (use repo root and PYTHONPATH=.): {exc}\n")
        return 1

    if not db_config.db_enabled():
        sys.stderr.write("Database disabled (configure SCYTALEDROID_DB_* or URL).\n")
        return 1

    run_sql = core_q.run_sql
    db = _fetch_db_name(run_sql)
    if not db:
        sys.stderr.write("Could not resolve current database name.\n")
        return 1

    rows, warnings, audit_meta = _build_report_rows(
        run_sql,
        db=db,
        include_catalogue_missing=bool(args.list_missing_catalogue),
    )

    payload = {
        "database": db,
        "generated_by": "scripts/db/static_schema_audit.py",
        "audit_meta": audit_meta,
        "rows": rows,
        "warnings": warnings,
    }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        _print_human(rows, warnings, db=db, audit_meta=audit_meta)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
