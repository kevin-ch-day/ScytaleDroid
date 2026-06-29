#!/usr/bin/env python3
"""Read-only report over dynamic service/provider context and observed runtime domains."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", action="append", default=[], help="Restrict to one or more package names.")
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    return parser


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fields:
                fields.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fields})


def _load_network_context_coverage(packages: list[str] | None = None) -> list[dict[str, Any]]:
    from scripts.db import report_dynamic_legacy_corpus as legacy_report

    db_rows = legacy_report._load_db_rows(packages)
    local_rows = legacy_report._scan_local_evidence_packs(packages)
    per_run_rows = [
        legacy_report._finalize_record(row)
        for row in legacy_report._merge_records(db_rows, local_rows)
    ]
    return legacy_report._build_per_app_rollup(per_run_rows)


def generate_report(*, packages: list[str] | None = None, output_dir: Path | None = None) -> dict[str, Any]:
    from scytaledroid.Database.db_core import db_queries as core_q
    from scytaledroid.DynamicAnalysis.service_context import (
        default_service_catalog_seed_rows,
        default_service_domain_map_seed_rows,
        resolve_service_for_domain,
    )
    from scripts.db._dynamic_service_seed_overlay import (
        merge_missing_seed_service_maps,
        merge_missing_seed_services,
    )

    package_filters = [str(value or "").strip().lower() for value in (packages or []) if str(value or "").strip()]
    if package_filters:
        placeholders = ", ".join(["%s"] * len(package_filters))
        obs_sql = f"""
            SELECT package_name, display_name, domain, root_domain, owner_class, role_class, total_hits, observed_run_count
            FROM (
              SELECT
                ddo.package_name,
                COALESCE(a.display_name, ddo.package_name) AS display_name,
                ddo.observed_domain AS domain,
                ddo.root_domain,
                ddo.owner_class,
                ddo.role_class,
                SUM(COALESCE(ddo.indicator_count, 0)) AS total_hits,
                COUNT(DISTINCT ddo.dynamic_run_id) AS observed_run_count
              FROM dynamic_domain_observations ddo
              LEFT JOIN apps a
                ON a.package_name = ddo.package_name
              WHERE ddo.package_name IN ({placeholders})
              GROUP BY ddo.package_name, COALESCE(a.display_name, ddo.package_name), ddo.observed_domain, ddo.root_domain, ddo.owner_class, ddo.role_class
            ) q
            ORDER BY package_name, total_hits DESC, domain
        """
        obs_params: tuple[object, ...] = tuple(package_filters)
    else:
        obs_sql = """
            SELECT
              ddo.package_name,
              COALESCE(a.display_name, ddo.package_name) AS display_name,
              ddo.observed_domain AS domain,
              ddo.root_domain,
              ddo.owner_class,
              ddo.role_class,
              SUM(COALESCE(ddo.indicator_count, 0)) AS total_hits,
              COUNT(DISTINCT ddo.dynamic_run_id) AS observed_run_count
            FROM dynamic_domain_observations ddo
            LEFT JOIN apps a
              ON a.package_name = ddo.package_name
            GROUP BY ddo.package_name, COALESCE(a.display_name, ddo.package_name), ddo.observed_domain, ddo.root_domain, ddo.owner_class, ddo.role_class
            ORDER BY ddo.package_name, total_hits DESC, ddo.observed_domain
        """
        obs_params = ()

    service_rows = core_q.run_sql(
        """
        SELECT
          service_key,
          display_name,
          owner_name,
          owner_class,
          service_category,
          primary_use_case,
          documentation_url,
          privacy_policy_url,
          source_url,
          confidence
        FROM dynamic_service_catalog
        WHERE is_active = 1
        ORDER BY owner_class, service_category, service_key
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic.service_context.report.services",
    ) or []
    domain_map_rows = core_q.run_sql(
        """
        SELECT
          dsc.service_key,
          dsdm.package_name_scope,
          dsdm.domain_pattern,
          dsdm.match_type,
          dsdm.role_class,
          dsdm.source_url,
          dsdm.confidence
        FROM dynamic_service_domain_map dsdm
        JOIN dynamic_service_catalog dsc
          ON dsc.service_id = dsdm.service_id
        WHERE dsdm.is_active = 1
          AND dsc.is_active = 1
        ORDER BY dsc.service_key, dsdm.package_name_scope, dsdm.match_type, dsdm.domain_pattern
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic.service_context.report.maps",
    ) or []
    service_rows = merge_missing_seed_services(service_rows, default_service_catalog_seed_rows())
    domain_map_rows = merge_missing_seed_service_maps(domain_map_rows, default_service_domain_map_seed_rows())
    obs_rows = core_q.run_sql(
        obs_sql,
        obs_params,
        fetch="all",
        dictionary=True,
        query_name="dynamic.service_context.report.observations",
    ) or []

    service_tuple = tuple(dict(row) for row in service_rows if isinstance(row, Mapping))
    domain_map_tuple = tuple(dict(row) for row in domain_map_rows if isinstance(row, Mapping))
    network_context_rows = _load_network_context_coverage(package_filters or None)
    network_context_by_package = {
        str(row.get("package_name") or "").strip().lower(): dict(row)
        for row in network_context_rows
        if isinstance(row, Mapping) and str(row.get("package_name") or "").strip()
    }

    package_service_rows: list[dict[str, Any]] = []
    unresolved_rows: list[dict[str, Any]] = []
    service_counts = Counter()
    package_counts: dict[str, Counter[str]] = defaultdict(Counter)

    for row in obs_rows:
        if not isinstance(row, Mapping):
            continue
        package_name = str(row.get("package_name") or "").strip().lower()
        domain = str(row.get("domain") or "").strip().lower()
        resolved = resolve_service_for_domain(
            domain,
            package_name=package_name,
            service_rows=service_tuple,
            map_rows=domain_map_tuple,
        )
        out_row = {
            "package_name": package_name,
            "display_name": row.get("display_name"),
            "domain": domain,
            "root_domain": row.get("root_domain"),
            "observed_owner_class": row.get("owner_class"),
            "observed_role_class": row.get("role_class"),
            "service_key": resolved.get("service_key"),
            "service_display_name": resolved.get("service_display_name"),
            "service_owner_name": resolved.get("owner_name"),
            "service_owner_class": resolved.get("owner_class"),
            "service_category": resolved.get("service_category"),
            "primary_use_case": resolved.get("primary_use_case"),
            "service_role_class": resolved.get("role_class"),
            "service_confidence": resolved.get("confidence"),
            "service_source_url": resolved.get("source_url"),
            "total_hits": int(row.get("total_hits") or 0),
            "observed_run_count": int(row.get("observed_run_count") or 0),
        }
        package_service_rows.append(out_row)
        if resolved.get("service_key"):
            service_key = str(resolved.get("service_key"))
            service_counts[service_key] += 1
            package_counts[package_name][service_key] += 1
        else:
            unresolved_rows.append(out_row)

    package_summary_rows: list[dict[str, Any]] = []
    for package_name in sorted(package_counts):
        counts = package_counts[package_name]
        top = counts.most_common(5)
        context = network_context_by_package.get(package_name, {})
        package_summary_rows.append(
            {
                "package_name": package_name,
                "resolved_service_count": sum(counts.values()),
                "distinct_services": len(counts),
                "top_services": ",".join(f"{key}:{value}" for key, value in top),
                "network_context_state": context.get("network_context_state", ""),
                "ingest_guidance": context.get("ingest_guidance", ""),
                "domain_indexed_runs": context.get("domain_indexed_runs", ""),
                "feature_context_runs": context.get("feature_context_runs", ""),
                "indicator_context_runs": context.get("indicator_context_runs", ""),
                "raw_pcap_runs": context.get("raw_pcap_runs", ""),
            }
        )

    output_root = output_dir or (_REPO_ROOT / "output" / "audit" / "dynamic_service_context" / datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S"))
    output_root.mkdir(parents=True, exist_ok=True)
    _write_csv(output_root / "package_service_context.csv", package_service_rows)
    _write_csv(output_root / "package_service_summary.csv", package_summary_rows)
    _write_csv(output_root / "package_network_context_coverage.csv", network_context_rows)
    _write_csv(output_root / "unresolved_domains.csv", unresolved_rows)

    summary = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "repo_root": str(_REPO_ROOT),
        "service_catalog_count": len(service_tuple),
        "service_domain_map_count": len(domain_map_tuple),
        "observed_domain_rows": len(package_service_rows),
        "unresolved_domain_rows": len(unresolved_rows),
        "packages_scanned": len({row["package_name"] for row in package_service_rows}),
        "packages_with_network_context_coverage": len(network_context_rows),
        "network_context_state_counts": dict(
            sorted(
                Counter(
                    str(row.get("network_context_state") or "").strip()
                    for row in network_context_rows
                    if str(row.get("network_context_state") or "").strip()
                ).items()
            )
        ),
        "service_key_counts": dict(sorted(service_counts.items())),
        "output_files": {
            "package_service_context_csv": str((output_root / "package_service_context.csv").resolve()),
            "package_service_summary_csv": str((output_root / "package_service_summary.csv").resolve()),
            "package_network_context_coverage_csv": str((output_root / "package_network_context_coverage.csv").resolve()),
            "unresolved_domains_csv": str((output_root / "unresolved_domains.csv").resolve()),
            "summary_json": str((output_root / "summary.json").resolve()),
        },
        "no_db_writes": True,
        "experimental_audit": True,
    }
    (output_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    summary = generate_report(packages=args.package, output_dir=output_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
