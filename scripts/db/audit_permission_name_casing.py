#!/usr/bin/env python3
"""Read-only audit: permission string columns vs lowercase+trim normalization (core DB + optional Intel).

Surfaces include obvious matrix/risk columns, **signal mappings**, **cohort expectations**,
**FileProvider / provider ACL permission columns**, optional **JSON probes** (findings evidence,
signal observation JSON, audit details), **schema discovery** for permission-like column names,
and expanded **Intel** dictionary/meta tables.

No data is modified. Use the report to plan migrations / generated columns.

Examples (run from repo root with PYTHONPATH=.):

  python scripts/db/audit_permission_name_casing.py
  python scripts/db/audit_permission_name_casing.py --intel
  python scripts/db/audit_permission_name_casing.py --probe-json --probe-limit 200
  python scripts/db/audit_permission_name_casing.py --discover
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core import db_queries as core_q


def _engine() -> str:
    return str(db_config.DB_CONFIG.get("engine") or "mysql").lower()


def _table_exists(table: str) -> bool:
    eng = _engine()
    try:
        if eng == "sqlite":
            row = core_q.run_sql(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=%s LIMIT 1",
                (table,),
                fetch="one",
            )
            return bool(row)
        row = core_q.run_sql(
            """
            SELECT COUNT(*) FROM information_schema.tables
            WHERE table_schema = DATABASE() AND table_name = %s
            """,
            (table,),
            fetch="one",
        )
        return bool(row and int(row[0] or 0) > 0)
    except Exception:
        return False


def _not_normalized_predicate(column: str) -> str:
    """SQL predicate: row needs normalization (whitespace or not all-lowercase)."""

    c = column
    if _engine() == "sqlite":
        return (
            f"({c} IS NOT NULL AND TRIM({c}) <> '' AND "
            f"(TRIM({c}) <> {c} OR LOWER(TRIM({c})) <> {c}))"
        )
    return (
        f"({c} IS NOT NULL AND TRIM({c}) <> '' AND "
        f"(LENGTH({c}) <> LENGTH(TRIM({c})) OR HEX(TRIM({c})) <> HEX(LOWER(TRIM({c})))))"
    )


def _column_exists(table: str, col: str) -> bool:
    try:
        if _engine() == "sqlite":
            rows = core_q.run_sql(f"PRAGMA table_info(`{table}`)", fetch="all") or []
            return any(str(r[1]).lower() == col.lower() for r in rows if r)
        row = core_q.run_sql(
            """
            SELECT COUNT(*) FROM information_schema.columns
            WHERE table_schema = DATABASE() AND table_name = %s AND column_name = %s
            """,
            (table, col),
            fetch="one",
        )
        return bool(row and int(row[0] or 0) > 0)
    except Exception:
        return False


def _audit_column(
    table: str,
    column: str,
    *,
    group_by_run: bool,
    extra_where: str | None = None,
    category: str = "scalar",
    group_key_override: str | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "category": category,
        "table": table,
        "column": column,
        "error": None,
    }
    if extra_where:
        out["filter"] = extra_where
    if not _table_exists(table):
        out["note"] = "table_missing"
        return out
    if not _column_exists(table, column):
        out["note"] = "column_missing"
        return out
    try:
        filt = f" AND ({extra_where})" if extra_where else ""
        row = core_q.run_sql(f"SELECT COUNT(*) FROM `{table}` WHERE 1=1{filt}", fetch="one")
        out["row_count"] = int(row[0] or 0) if row else 0
        pred = _not_normalized_predicate(f"`{column}`")
        row2 = core_q.run_sql(
            f"SELECT COUNT(*) FROM `{table}` WHERE {pred}{filt}",
            fetch="one",
        )
        out["not_lower_trim_count"] = int(row2[0] or 0) if row2 else 0
        row3 = core_q.run_sql(
            f"""
            SELECT COUNT(DISTINCT LOWER(TRIM(`{column}`))),
                   COUNT(DISTINCT `{column}`)
            FROM `{table}`
            WHERE `{column}` IS NOT NULL AND TRIM(`{column}`) <> ''{filt}
            """,
            fetch="one",
        )
        if row3:
            out["distinct_canonical_lower_trim"] = int(row3[0] or 0)
            out["distinct_raw_values"] = int(row3[1] or 0)
        gkey = group_key_override
        if group_by_run and gkey is None:
            gkey = "run_id" if table != "permission_signal_observations" else "static_run_id"
        if group_by_run and gkey and _column_exists(table, gkey):
            row4 = core_q.run_sql(
                f"""
                SELECT {gkey} AS k,
                       COUNT(*) AS n,
                       COUNT(DISTINCT LOWER(TRIM(`{column}`))) AS canon,
                       COUNT(DISTINCT `{column}`) AS raw_spelling
                FROM `{table}`
                WHERE `{column}` IS NOT NULL AND TRIM(`{column}`) <> ''{filt}
                GROUP BY {gkey}
                HAVING n > canon OR raw_spelling > canon
                LIMIT 15
                """,
                fetch="all",
            )
            out["sample_run_collisions"] = [list(r) for r in (row4 or [])]
    except Exception as exc:
        out["error"] = f"{exc.__class__.__name__}: {exc}"
    return out


_PERM_TOKEN = re.compile(
    r"(?i)(?:^android\.permission\.[a-z0-9_]+|^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)$"
)


def _looks_like_permission_constant(s: str) -> bool:
    t = (s or "").strip()
    if not t or len(t) > 256:
        return False
    if t.startswith("android.permission."):
        return True
    if ".permission." in t and "." in t and " " not in t:
        return True
    if _PERM_TOKEN.match(t) and "permission" in t.lower():
        return True
    return False


def _needs_normalization(s: str) -> bool:
    t = s.strip()
    return bool(t) and (t != t.lower() or s != s.strip())


def _walk_json_values(obj: object, sink: list[str]) -> None:
    if isinstance(obj, str):
        sink.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _walk_json_values(v, sink)
    elif isinstance(obj, list):
        for v in obj:
            _walk_json_values(v, sink)


def _json_probe_table(
    table: str,
    pk_col: str,
    json_col: str,
    *,
    limit: int,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "category": "json_probe",
        "table": table,
        "column": json_col,
    }
    if not _table_exists(table) or not _column_exists(table, json_col):
        out["note"] = "table_or_column_missing"
        return out
    try:
        rows = core_q.run_sql(
            f"SELECT `{pk_col}`, `{json_col}` FROM `{table}` WHERE `{json_col}` IS NOT NULL LIMIT %s",
            (int(limit),),
            fetch="all",
        )
    except Exception as exc:
        out["error"] = f"{exc.__class__.__name__}: {exc}"
        return out

    rows_scanned = 0
    permish_strings: list[str] = []
    for r in rows or []:
        if not r or len(r) < 2:
            continue
        rows_scanned += 1
        raw = r[1]
        parsed: object
        if raw is None:
            continue
        if isinstance(raw, (dict, list)):
            parsed = raw
        else:
            try:
                parsed = json.loads(str(raw))
            except Exception:
                continue
        buf: list[str] = []
        _walk_json_values(parsed, buf)
        for s in buf:
            if _looks_like_permission_constant(s):
                permish_strings.append(s)

    weird = [s for s in permish_strings if _needs_normalization(s)]
    out["rows_scanned"] = rows_scanned
    out["permission_like_strings_found"] = len(permish_strings)
    out["permission_like_not_lower_trim"] = len(weird)
    out["sample_mixed_case"] = list(dict.fromkeys(weird))[:12]
    return out


def _persistence_failure_permission_mentions(*, limit: int) -> dict[str, Any]:
    """Heuristic: failure blobs sometimes quote permission constants."""

    out: dict[str, Any] = {"category": "text_probe", "table": "static_persistence_failures"}
    if not _table_exists("static_persistence_failures"):
        out["note"] = "table_missing"
        return out
    eng = _engine()
    try:
        if eng == "sqlite":
            pred = "(IFNULL(errors_tail,'') LIKE '%android.permission%' OR IFNULL(exception_message,'') LIKE '%android.permission%')"
            rows = core_q.run_sql(
                f"""
                SELECT id, exception_message, errors_tail
                FROM static_persistence_failures
                WHERE {pred}
                LIMIT %s
                """,
                (int(limit),),
                fetch="all",
            )
        else:
            rows = core_q.run_sql(
                f"""
                SELECT id, exception_message, errors_tail
                FROM static_persistence_failures
                WHERE (
                  COALESCE(errors_tail,'') REGEXP 'android[.]permission[.]'
                  OR COALESCE(exception_message,'') REGEXP 'android[.]permission[.]'
                )
                LIMIT %s
                """,
                (int(limit),),
                fetch="all",
            )
    except Exception as exc:
        out["error"] = f"{exc.__class__.__name__}: {exc}"
        return out

    hits = 0
    samples: list[str] = []
    for r in rows or []:
        if not r:
            continue
        hits += 1
        blob = f"{r[1] or ''}\n{r[2] or ''}"
        for m in re.findall(r"android\.permission\.[A-Za-z0-9_]+", blob):
            if m != m.lower() and m not in samples:
                samples.append(m)
        if len(samples) >= 10:
            break
    out["rows_matched_heuristic"] = hits
    out["sample_mixed_case_constants_in_text"] = samples[:10]
    return out


def _discover_permission_like_columns() -> list[dict[str, Any]]:
    """Find string-ish columns whose names look permission-related (MySQL / MariaDB)."""

    if _engine() == "sqlite":
        return [{"note": "schema_discover_skipped_sqlite"}]
    try:
        rows = core_q.run_sql(
            """
            SELECT table_name, column_name, data_type
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND (
                    column_name LIKE '%permission%'
                 OR column_name IN ('perm_name', 'subject_key', 'constant_value', 'primary_permission')
              )
              AND data_type IN (
                'varchar', 'char', 'text', 'tinytext', 'mediumtext', 'longtext', 'json'
              )
            ORDER BY table_name, column_name
            """,
            fetch="all",
        )
    except Exception as exc:
        return [{"error": f"{exc.__class__.__name__}: {exc}"}]
    out: list[dict[str, Any]] = []
    for r in rows or []:
        if not r:
            continue
        out.append(
            {
                "table": str(r[0]),
                "column": str(r[1]),
                "data_type": str(r[2]),
            }
        )
    return out


def _intel_audit_extended() -> list[dict[str, Any]]:
    try:
        from scytaledroid.Database.db_core import permission_intel as intel_db
    except Exception as exc:
        return [{"error": f"intel_import:{exc}"}]

    if not intel_db.is_permission_intel_configured():
        return [{"note": "permission_intel_not_configured"}]

    results: list[dict[str, Any]] = []
    targets = [
        ("android_permission_dict_aosp", "constant_value"),
        ("android_permission_dict_aosp", "name"),
        ("android_permission_dict_oem", "permission_string"),
        ("android_permission_dict_unknown", "permission_string"),
        ("android_permission_dict_queue", "permission_string"),
        ("permission_governance_snapshot_rows", "permission_string"),
        ("android_permission_meta_oem_prefix", "namespace_prefix"),
    ]
    for table, col in targets:
        entry: dict[str, Any] = {"table": table, "column": col}
        try:
            row = intel_db.run_sql(f"SELECT COUNT(*) FROM `{table}`", fetch="one", read_only=True)
            entry["row_count"] = int(row[0] or 0) if row else 0
            pred = _not_normalized_predicate(col)
            row2 = intel_db.run_sql(
                f"SELECT COUNT(*) FROM `{table}` WHERE {pred}",
                fetch="one",
                read_only=True,
            )
            entry["not_lower_trim_count"] = int(row2[0] or 0) if row2 else 0
        except Exception as exc:
            entry["error"] = f"{exc.__class__.__name__}: {exc}"
        results.append(entry)

    # Optional reference tables mirrored onto the Intel catalog in some deployments.
    for table, col in (
        ("permission_signal_mappings", "perm_name"),
        ("permission_cohort_expectations", "subject_key"),
    ):
        entry: dict[str, Any] = {"table": table, "column": col, "note": "intel_optional_mirror"}
        try:
            perm_filter = ""
            if table == "permission_cohort_expectations":
                perm_filter = "subject_kind = 'permission' AND "
            row = intel_db.run_sql(
                f"SELECT COUNT(*) FROM `{table}` WHERE {perm_filter}1=1",
                fetch="one",
                read_only=True,
            )
            entry["row_count"] = int(row[0] or 0) if row else 0
            pred = _not_normalized_predicate(col)
            row2 = intel_db.run_sql(
                f"SELECT COUNT(*) FROM `{table}` WHERE {perm_filter}{pred}",
                fetch="one",
                read_only=True,
            )
            entry["not_lower_trim_count"] = int(row2[0] or 0) if row2 else 0
            entry.pop("note", None)
        except Exception as exc:
            entry["note"] = f"intel_table_absent_or_unreadable:{exc.__class__.__name__}"
        results.append(entry)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--intel",
        action="store_true",
        help="Include Permission Intel DB (SCYTALEDROID_PERMISSION_INTEL_DB_*).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON only.",
    )
    parser.add_argument(
        "--probe-json",
        action="store_true",
        help="Sample JSON columns for embedded permission-like strings (read-only, row-limited).",
    )
    parser.add_argument(
        "--probe-limit",
        type=int,
        default=150,
        help="Max rows per table for --probe-json (default: 150).",
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help="List information_schema columns matching %%permission%% (MySQL/MariaDB).",
    )
    args = parser.parse_args()
    lim = max(1, min(int(args.probe_limit), 50_000))

    core_targets: list[tuple[str, str, bool, str | None, str, str | None]] = [
        ("static_permission_matrix", "permission_name", True, None, "run_evidence", None),
        ("static_permission_risk_vnext", "permission_name", True, None, "run_evidence", None),
        ("permission_signal_observations", "primary_permission", True, None, "run_evidence", None),
        ("permission_signal_mappings", "perm_name", False, None, "config_catalog", None),
        (
            "permission_cohort_expectations",
            "subject_key",
            False,
            "subject_kind = 'permission'",
            "config_catalog",
            None,
        ),
        ("static_fileproviders", "base_permission", True, None, "component_acl", None),
        ("static_fileproviders", "read_permission", True, None, "component_acl", None),
        ("static_fileproviders", "write_permission", True, None, "component_acl", None),
        ("static_provider_acl", "read_permission", True, None, "component_acl", "provider_id"),
        ("static_provider_acl", "write_permission", True, None, "component_acl", "provider_id"),
    ]

    report: dict[str, Any] = {
        "engine": _engine(),
        "core": [
            _audit_column(
                t,
                c,
                group_by_run=g,
                extra_where=ew,
                category=cat,
                group_key_override=gko,
            )
            for t, c, g, ew, cat, gko in core_targets
        ],
    }

    if args.probe_json:
        report["json_probes"] = [
            _json_probe_table("static_analysis_findings", "id", "evidence", limit=lim),
            _json_probe_table(
                "permission_signal_observations",
                "id",
                "trigger_permissions_json",
                limit=lim,
            ),
            _json_probe_table("permission_audit_apps", "audit_id", "details", limit=lim),
        ]
        report["text_probes"] = [_persistence_failure_permission_mentions(limit=lim)]

    if args.discover:
        discovered = _discover_permission_like_columns()
        audited_pairs = {(t, c) for t, c, *_ in core_targets}
        suggestions = [
            x
            for x in discovered
            if isinstance(x, dict)
            and x.get("table")
            and x.get("column")
            and (str(x["table"]), str(x["column"])) not in audited_pairs
        ]
        report["schema_discover_all"] = discovered
        report["schema_discover_not_in_scalar_audit"] = suggestions

    if args.intel:
        report["permission_intel"] = _intel_audit_extended()

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"DB engine: {report['engine']}")
        print("\n## Core DB (scalar columns)")
        for block in report["core"]:
            print(json.dumps(block, indent=2, default=str))
        if args.probe_json:
            print("\n## JSON / text probes")
            for block in report.get("json_probes") or []:
                print(json.dumps(block, indent=2, default=str))
            for block in report.get("text_probes") or []:
                print(json.dumps(block, indent=2, default=str))
        if args.discover:
            print("\n## Schema discover (permission-like columns, may include false positives)")
            for block in report.get("schema_discover_not_in_scalar_audit") or []:
                print(json.dumps(block, indent=2, default=str))
        if args.intel:
            print("\n## Permission Intel")
            for block in report.get("permission_intel") or []:
                print(json.dumps(block, indent=2, default=str))
        print(
            "\nNotes: risk_scores stores aggregate counts only. "
            "JSON probes use heuristics (android.permission*, *.permission.*); "
            "schema discover lists columns by name — verify semantics before adding migrations. "
            "Do not mutate data from this script."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
