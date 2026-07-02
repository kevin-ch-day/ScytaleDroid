"""Derived DB indexing of dynamic domain-context observations."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.DynamicAnalysis.domain_context import (
    DomainReference,
    classify_domain,
    default_domain_references,
    normalize_domain,
)


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _reference_rows_to_objects(rows: list[Mapping[str, Any]]) -> tuple[DomainReference, ...]:
    refs: list[DomainReference] = []
    for row in rows:
        refs.append(
            DomainReference(
                package_name_scope=str(row.get("package_name_scope") or ""),
                domain_pattern=str(row.get("domain_pattern") or ""),
                match_type=str(row.get("match_type") or ""),
                owner_class=str(row.get("owner_class") or ""),
                role_class=str(row.get("role_class") or ""),
                confidence=str(row.get("confidence") or ""),
                classification_basis=str(row.get("classification_basis") or ""),
                source_label=str(row.get("source_label") or "db_seed"),
                source_url=str(row.get("source_url") or "") or None,
                notes=str(row.get("notes") or "") or None,
            )
        )
    return tuple(refs)


def load_domain_references_from_db() -> tuple[DomainReference, ...]:
    try:
        rows = core_q.run_sql(
            """
            SELECT
              package_name_scope,
              domain_pattern,
              match_type,
              owner_class,
              role_class,
              confidence,
              classification_basis,
              source_label,
              source_url,
              notes
            FROM dynamic_domain_reference
            WHERE is_active = 1
            ORDER BY package_name_scope, match_type, domain_pattern
            """,
            (),
            fetch="all",
            dictionary=True,
            query_name="dynamic.domain_context.load_references",
        ) or []
    except Exception:
        rows = []
    if not rows:
        return default_domain_references()
    return _reference_rows_to_objects([row for row in rows if isinstance(row, Mapping)])


def build_domain_observation_rows_from_pcap_report(
    report: Mapping[str, Any],
    *,
    dynamic_run_id: str,
    package_name: str,
    references: tuple[DomainReference, ...] | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    refs = references or default_domain_references()

    def _append(kind: str, items: object, *, source: str) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            domain = normalize_domain(item.get("value"))
            if not domain:
                continue
            count = item.get("count")
            try:
                count_i = int(count) if count is not None else None
            except Exception:
                count_i = None
            ctx = classify_domain(domain, package_name=package_name, references=refs)
            rows.append(
                {
                    "dynamic_run_id": dynamic_run_id,
                    "package_name": package_name,
                    "indicator_type": kind,
                    "observed_domain": ctx.get("domain"),
                    "root_domain": ctx.get("root_domain"),
                    "indicator_count": count_i,
                    "indicator_source": source,
                    "owner_class": ctx.get("owner_class"),
                    "role_class": ctx.get("role_class"),
                    "confidence": ctx.get("confidence"),
                    "classification_basis": ctx.get("basis"),
                    "package_name_scope": ctx.get("package_name_scope"),
                    "match_type": ctx.get("match_type"),
                    "is_first_party": 1 if ctx.get("first_party") else 0,
                }
            )

    _append("dns", report.get("top_dns"), source="top_dns")
    _append("sni", report.get("top_sni"), source="top_sni")
    return rows


def build_domain_observation_rows_from_network_indicators(
    indicator_rows: list[Mapping[str, Any]],
    *,
    dynamic_run_id: str,
    package_name: str,
    references: tuple[DomainReference, ...] | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    refs = references or default_domain_references()
    for item in indicator_rows:
        kind = str(item.get("indicator_type") or "").strip().lower()
        if kind not in {"dns", "sni"}:
            continue
        domain = normalize_domain(item.get("indicator_value"))
        if not domain:
            continue
        try:
            count_i = int(item.get("indicator_count") or 0)
        except Exception:
            count_i = 0
        ctx = classify_domain(domain, package_name=package_name, references=refs)
        rows.append(
            {
                "dynamic_run_id": dynamic_run_id,
                "package_name": package_name,
                "indicator_type": kind,
                "observed_domain": ctx.get("domain"),
                "root_domain": ctx.get("root_domain"),
                "indicator_count": count_i,
                "indicator_source": str(item.get("indicator_source") or "dynamic_network_indicators")[:32],
                "owner_class": ctx.get("owner_class"),
                "role_class": ctx.get("role_class"),
                "confidence": ctx.get("confidence"),
                "classification_basis": ctx.get("basis"),
                "package_name_scope": ctx.get("package_name_scope"),
                "match_type": ctx.get("match_type"),
                "is_first_party": 1 if ctx.get("first_party") else 0,
            }
        )
    return rows


def _insert_domain_observation_rows(rows: list[dict[str, Any]], *, query_name: str) -> int:
    if not rows:
        return 0
    sql = """
        INSERT INTO dynamic_domain_observations (
          dynamic_run_id,
          package_name,
          indicator_type,
          observed_domain,
          root_domain,
          indicator_count,
          indicator_source,
          owner_class,
          role_class,
          confidence,
          classification_basis,
          package_name_scope,
          match_type,
          is_first_party
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    data = [
        (
            row.get("dynamic_run_id"),
            row.get("package_name"),
            row.get("indicator_type"),
            row.get("observed_domain"),
            row.get("root_domain"),
            row.get("indicator_count"),
            row.get("indicator_source"),
            row.get("owner_class"),
            row.get("role_class"),
            row.get("confidence"),
            row.get("classification_basis"),
            row.get("package_name_scope"),
            row.get("match_type"),
            row.get("is_first_party"),
        )
        for row in rows
    ]
    core_q.run_sql_many(sql, data, query_name=query_name)
    return len(data)


def index_dynamic_domain_context_for_run(
    dynamic_run_id: str,
    package_name: str,
    run_dir: Path,
    *,
    references: tuple[DomainReference, ...] | None = None,
) -> int:
    report = _read_json(run_dir / "analysis" / "pcap_report.json")
    if not report:
        return 0
    rows = build_domain_observation_rows_from_pcap_report(
        report,
        dynamic_run_id=dynamic_run_id,
        package_name=package_name,
        references=references or load_domain_references_from_db(),
    )
    if not rows:
        return 0
    core_q.run_sql_write(
        "DELETE FROM dynamic_domain_observations WHERE dynamic_run_id = %s",
        (dynamic_run_id,),
        query_name="dynamic.domain_context.delete_run",
    )
    return _insert_domain_observation_rows(rows, query_name="dynamic.domain_context.insert")


def index_dynamic_domain_context_from_network_indicators(*, only_missing: bool = True) -> dict[str, Any]:
    references = load_domain_references_from_db()
    missing_clause = """
      AND NOT EXISTS (
        SELECT 1
        FROM dynamic_domain_observations ddo
        WHERE ddo.dynamic_run_id = ds.dynamic_run_id
        LIMIT 1
      )
    """ if only_missing else ""
    run_rows = core_q.run_sql(
        f"""
        SELECT
          ds.dynamic_run_id,
          ds.package_name,
          COUNT(*) AS indicator_rows
        FROM dynamic_sessions ds
        JOIN dynamic_network_indicators dni
          ON dni.dynamic_run_id = ds.dynamic_run_id
        WHERE dni.indicator_type IN ('dns', 'sni')
          {missing_clause}
        GROUP BY ds.dynamic_run_id, ds.package_name
        ORDER BY ds.package_name, ds.dynamic_run_id
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic.domain_context.indicator_candidate_runs",
    ) or []
    scanned = 0
    indexed = 0
    errors = 0
    for run in run_rows:
        if not isinstance(run, Mapping):
            continue
        dynamic_run_id = str(run.get("dynamic_run_id") or "").strip()
        package_name = str(run.get("package_name") or "").strip()
        if not dynamic_run_id or not package_name:
            continue
        scanned += 1
        try:
            indicators = core_q.run_sql(
                """
                SELECT
                  indicator_type,
                  indicator_value,
                  SUM(COALESCE(indicator_count, 0)) AS indicator_count,
                  MIN(COALESCE(indicator_source, 'dynamic_network_indicators')) AS indicator_source
                FROM dynamic_network_indicators
                WHERE dynamic_run_id = %s
                  AND indicator_type IN ('dns', 'sni')
                GROUP BY indicator_type, indicator_value
                ORDER BY indicator_type, indicator_value
                """,
                (dynamic_run_id,),
                fetch="all",
                dictionary=True,
                query_name="dynamic.domain_context.indicator_rows_for_run",
            ) or []
            rows = build_domain_observation_rows_from_network_indicators(
                [row for row in indicators if isinstance(row, Mapping)],
                dynamic_run_id=dynamic_run_id,
                package_name=package_name,
                references=references,
            )
            indexed += _insert_domain_observation_rows(
                rows,
                query_name="dynamic.domain_context.insert_from_indicators",
            )
        except Exception:
            errors += 1
            continue
    return {"scanned": scanned, "indexed_rows": indexed, "errors": errors, "only_missing": only_missing}


def refresh_dynamic_domain_observation_classifications(*, unknown_only: bool = True) -> dict[str, Any]:
    references = load_domain_references_from_db()
    where_sql = "WHERE LOWER(TRIM(COALESCE(owner_class, ''))) = 'unknown'" if unknown_only else ""
    rows = core_q.run_sql(
        f"""
        SELECT
          observation_id,
          dynamic_run_id,
          package_name,
          observed_domain,
          root_domain,
          owner_class,
          role_class,
          confidence,
          classification_basis,
          package_name_scope,
          match_type,
          is_first_party
        FROM dynamic_domain_observations
        {where_sql}
        ORDER BY package_name, observed_domain, observation_id
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic.domain_context.refresh_candidates",
    ) or []
    scanned = 0
    updated = 0
    errors = 0
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        scanned += 1
        try:
            observation_id = row.get("observation_id")
            package_name = str(row.get("package_name") or "").strip()
            domain = str(row.get("observed_domain") or "").strip()
            if not observation_id or not package_name or not domain:
                continue
            ctx = classify_domain(domain, package_name=package_name, references=references)
            if ctx.get("owner_class") == "unknown":
                continue
            next_values = {
                "root_domain": str(ctx.get("root_domain") or ""),
                "owner_class": str(ctx.get("owner_class") or ""),
                "role_class": str(ctx.get("role_class") or ""),
                "confidence": str(ctx.get("confidence") or ""),
                "classification_basis": str(ctx.get("basis") or ""),
                "package_name_scope": str(ctx.get("package_name_scope") or ""),
                "match_type": str(ctx.get("match_type") or ""),
                "is_first_party": 1 if ctx.get("first_party") else 0,
            }
            current_values = {
                "root_domain": str(row.get("root_domain") or ""),
                "owner_class": str(row.get("owner_class") or ""),
                "role_class": str(row.get("role_class") or ""),
                "confidence": str(row.get("confidence") or ""),
                "classification_basis": str(row.get("classification_basis") or ""),
                "package_name_scope": str(row.get("package_name_scope") or ""),
                "match_type": str(row.get("match_type") or ""),
                "is_first_party": int(row.get("is_first_party") or 0),
            }
            if current_values == next_values:
                continue
            core_q.run_sql_write(
                """
                UPDATE dynamic_domain_observations
                SET
                  root_domain = %s,
                  owner_class = %s,
                  role_class = %s,
                  confidence = %s,
                  classification_basis = %s,
                  package_name_scope = %s,
                  match_type = %s,
                  is_first_party = %s
                WHERE observation_id = %s
                """,
                (
                    next_values["root_domain"],
                    next_values["owner_class"],
                    next_values["role_class"],
                    next_values["confidence"],
                    next_values["classification_basis"],
                    next_values["package_name_scope"],
                    next_values["match_type"],
                    next_values["is_first_party"],
                    observation_id,
                ),
                query_name="dynamic.domain_context.refresh_observation",
            )
            updated += 1
        except Exception:
            errors += 1
            continue
    return {"scanned": scanned, "updated_rows": updated, "errors": errors, "unknown_only": unknown_only}


def index_dynamic_domain_context_from_evidence_packs(root: Path) -> dict[str, Any]:
    manifests = sorted(root.glob("*/run_manifest.json"))
    scanned = 0
    indexed = 0
    errors = 0
    references = load_domain_references_from_db()
    for manifest_path in manifests:
        scanned += 1
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                continue
            dynamic_run_id = str(manifest.get("dynamic_run_id") or manifest_path.parent.name).strip()
            target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
            package_name = str((target or {}).get("package_name") or "").strip()
            if not dynamic_run_id or not package_name:
                continue
            row = core_q.run_sql(
                "SELECT dynamic_run_id FROM dynamic_sessions WHERE dynamic_run_id = %s",
                (dynamic_run_id,),
                fetch="one",
                query_name="dynamic.domain_context.session_exists",
            )
            if not row:
                continue
            indexed += index_dynamic_domain_context_for_run(
                dynamic_run_id,
                package_name,
                manifest_path.parent,
                references=references,
            )
        except Exception:
            errors += 1
            continue
    return {"scanned": scanned, "indexed_rows": indexed, "errors": errors}


__all__ = [
    "build_domain_observation_rows_from_network_indicators",
    "build_domain_observation_rows_from_pcap_report",
    "index_dynamic_domain_context_from_network_indicators",
    "index_dynamic_domain_context_for_run",
    "index_dynamic_domain_context_from_evidence_packs",
    "load_domain_references_from_db",
    "refresh_dynamic_domain_observation_classifications",
]
