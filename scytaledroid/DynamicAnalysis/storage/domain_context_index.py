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
    core_q.run_sql_many(sql, data, query_name="dynamic.domain_context.insert")
    return len(data)


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
    "build_domain_observation_rows_from_pcap_report",
    "index_dynamic_domain_context_for_run",
    "index_dynamic_domain_context_from_evidence_packs",
    "load_domain_references_from_db",
]
