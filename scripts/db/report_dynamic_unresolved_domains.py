#!/usr/bin/env python3
"""Read-only triage report for unresolved dynamic domains.

This report focuses on rows already ingested into ``dynamic_domain_observations``
that remain unresolved by the curated domain-context layer. It helps prioritize
new curation work by grouping unknown observations by package, root domain, and
candidate service/provider context.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
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


def _norm_text(value: object) -> str:
    return str(value or "").strip()


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
    where_clauses = [
        "LOWER(TRIM(COALESCE(ddo.owner_class, ''))) = 'unknown'",
    ]
    params: list[object] = []
    if package_filters:
        placeholders = ", ".join(["%s"] * len(package_filters))
        where_clauses.append(f"LOWER(TRIM(COALESCE(ddo.package_name, ''))) IN ({placeholders})")
        params.extend(package_filters)
    where_sql = " AND ".join(where_clauses)

    unresolved_rows = core_q.run_sql(
        f"""
        SELECT
          ddo.package_name,
          COALESCE(a.display_name, ddo.package_name) AS display_name,
          ddo.observed_domain,
          ddo.root_domain,
          ddo.indicator_type,
          ddo.indicator_source,
          ddo.classification_basis,
          SUM(COALESCE(ddo.indicator_count, 0)) AS total_hits,
          COUNT(*) AS observation_rows,
          COUNT(DISTINCT ddo.dynamic_run_id) AS observed_run_count,
          MIN(ds.started_at_utc) AS first_seen_at_utc,
          MAX(COALESCE(ds.ended_at_utc, ds.started_at_utc)) AS last_seen_at_utc
        FROM dynamic_domain_observations ddo
        LEFT JOIN dynamic_sessions ds
          ON ds.dynamic_run_id = ddo.dynamic_run_id
        LEFT JOIN apps a
          ON CONVERT(a.package_name USING utf8mb4) COLLATE utf8mb4_general_ci =
             CONVERT(ddo.package_name USING utf8mb4) COLLATE utf8mb4_general_ci
        WHERE {where_sql}
        GROUP BY
          ddo.package_name,
          COALESCE(a.display_name, ddo.package_name),
          ddo.observed_domain,
          ddo.root_domain,
          ddo.indicator_type,
          ddo.indicator_source,
          ddo.classification_basis
        ORDER BY total_hits DESC, observed_run_count DESC, ddo.package_name, ddo.observed_domain
        """,
        tuple(params),
        fetch="all",
        dictionary=True,
        query_name="dynamic.unresolved_domains.rows",
    ) or []

    service_rows = tuple(
        dict(row)
        for row in (
            core_q.run_sql(
                """
                SELECT
                  service_key,
                  display_name,
                  owner_name,
                  owner_class,
                  service_category,
                  primary_use_case,
                  source_url,
                  confidence
                FROM dynamic_service_catalog
                WHERE is_active = 1
                ORDER BY owner_class, service_category, service_key
                """,
                (),
                fetch="all",
                dictionary=True,
                query_name="dynamic.unresolved_domains.services",
            )
            or []
        )
        if isinstance(row, Mapping)
    )
    map_rows = tuple(
        dict(row)
        for row in (
            core_q.run_sql(
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
                query_name="dynamic.unresolved_domains.maps",
            )
            or []
        )
        if isinstance(row, Mapping)
    )
    service_rows = tuple(
        merge_missing_seed_services(
            list(service_rows),
            default_service_catalog_seed_rows(),
        )
    )
    map_rows = tuple(
        merge_missing_seed_service_maps(
            list(map_rows),
            default_service_domain_map_seed_rows(),
        )
    )

    unresolved_domain_rows: list[dict[str, Any]] = []
    unresolved_root_rollups: dict[str, dict[str, Any]] = {}
    package_summary_rollups: dict[str, dict[str, Any]] = {}
    candidate_counter: Counter[str] = Counter()
    candidate_gap_counter: Counter[str] = Counter()

    for row in unresolved_rows:
        if not isinstance(row, Mapping):
            continue
        package_name = _norm_text(row.get("package_name")).lower()
        observed_domain = _norm_text(row.get("observed_domain")).lower()
        root_domain = _norm_text(row.get("root_domain")).lower()
        display_name = _norm_text(row.get("display_name")) or package_name
        candidate = resolve_service_for_domain(
            observed_domain,
            package_name=package_name,
            service_rows=service_rows,
            map_rows=map_rows,
        )
        candidate_service_key = candidate.get("service_key")
        candidate_match_status = "candidate_service_match" if candidate_service_key else "no_service_match"
        if candidate_service_key:
            candidate_counter[str(candidate_service_key)] += 1
            candidate_gap_counter[str(candidate_service_key)] += int(row.get("total_hits") or 0)

        out_row = {
            "package_name": package_name,
            "display_name": display_name,
            "observed_domain": observed_domain,
            "root_domain": root_domain,
            "indicator_type": row.get("indicator_type"),
            "indicator_source": row.get("indicator_source"),
            "classification_basis": row.get("classification_basis"),
            "total_hits": int(row.get("total_hits") or 0),
            "observation_rows": int(row.get("observation_rows") or 0),
            "observed_run_count": int(row.get("observed_run_count") or 0),
            "first_seen_at_utc": row.get("first_seen_at_utc"),
            "last_seen_at_utc": row.get("last_seen_at_utc"),
            "candidate_match_status": candidate_match_status,
            "candidate_service_key": candidate_service_key,
            "candidate_service_display_name": candidate.get("service_display_name"),
            "candidate_owner_name": candidate.get("owner_name"),
            "candidate_service_category": candidate.get("service_category"),
            "candidate_primary_use_case": candidate.get("primary_use_case"),
            "candidate_role_class": candidate.get("role_class"),
            "candidate_confidence": candidate.get("confidence"),
            "candidate_match_type": candidate.get("match_type"),
            "candidate_package_scope": candidate.get("package_name_scope"),
            "candidate_source_url": candidate.get("source_url"),
        }
        unresolved_domain_rows.append(out_row)

        root_rollup = unresolved_root_rollups.setdefault(
            root_domain or observed_domain,
            {
                "root_domain": root_domain or observed_domain,
                "observed_domains": set(),
                "packages": set(),
                "runs": 0,
                "hits": 0,
                "candidate_services": Counter(),
                "first_seen_at_utc": row.get("first_seen_at_utc"),
                "last_seen_at_utc": row.get("last_seen_at_utc"),
            },
        )
        root_rollup["observed_domains"].add(observed_domain)
        root_rollup["packages"].add(package_name)
        root_rollup["runs"] += int(row.get("observed_run_count") or 0)
        root_rollup["hits"] += int(row.get("total_hits") or 0)
        if candidate_service_key:
            root_rollup["candidate_services"][str(candidate_service_key)] += int(row.get("total_hits") or 0)
        if row.get("first_seen_at_utc") and (
            not root_rollup["first_seen_at_utc"] or str(row.get("first_seen_at_utc")) < str(root_rollup["first_seen_at_utc"])
        ):
            root_rollup["first_seen_at_utc"] = row.get("first_seen_at_utc")
        if row.get("last_seen_at_utc") and (
            not root_rollup["last_seen_at_utc"] or str(row.get("last_seen_at_utc")) > str(root_rollup["last_seen_at_utc"])
        ):
            root_rollup["last_seen_at_utc"] = row.get("last_seen_at_utc")

        package_rollup = package_summary_rollups.setdefault(
            package_name,
            {
                "package_name": package_name,
                "display_name": display_name,
                "unresolved_domain_count": 0,
                "unresolved_root_domain_count": set(),
                "observed_run_total": 0,
                "total_hits": 0,
                "candidate_service_counter": Counter(),
            },
        )
        package_rollup["unresolved_domain_count"] += 1
        package_rollup["unresolved_root_domain_count"].add(root_domain or observed_domain)
        package_rollup["observed_run_total"] += int(row.get("observed_run_count") or 0)
        package_rollup["total_hits"] += int(row.get("total_hits") or 0)
        if candidate_service_key:
            package_rollup["candidate_service_counter"][str(candidate_service_key)] += int(row.get("total_hits") or 0)

    root_domain_rows = [
        {
            "root_domain": root_key,
            "observed_domain_count": len(rollup["observed_domains"]),
            "package_count": len(rollup["packages"]),
            "packages_csv": ",".join(sorted(rollup["packages"])),
            "observed_run_total": int(rollup["runs"]),
            "total_hits": int(rollup["hits"]),
            "candidate_services_csv": ",".join(
                f"{service}:{hits}" for service, hits in rollup["candidate_services"].most_common()
            ),
            "first_seen_at_utc": rollup["first_seen_at_utc"],
            "last_seen_at_utc": rollup["last_seen_at_utc"],
        }
        for root_key, rollup in sorted(
            unresolved_root_rollups.items(),
            key=lambda item: (-int(item[1]["hits"]), -len(item[1]["packages"]), item[0]),
        )
    ]

    package_summary_rows = [
        {
            "package_name": package_name,
            "display_name": rollup["display_name"],
            "unresolved_domain_count": int(rollup["unresolved_domain_count"]),
            "unresolved_root_domain_count": len(rollup["unresolved_root_domain_count"]),
            "observed_run_total": int(rollup["observed_run_total"]),
            "total_hits": int(rollup["total_hits"]),
            "candidate_services_csv": ",".join(
                f"{service}:{hits}" for service, hits in rollup["candidate_service_counter"].most_common()
            ),
        }
        for package_name, rollup in sorted(
            package_summary_rollups.items(),
            key=lambda item: (-int(item[1]["total_hits"]), item[0]),
        )
    ]

    output_root = output_dir or (_REPO_ROOT / "output" / "audit" / "dynamic_unresolved_domains" / datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S"))
    output_root.mkdir(parents=True, exist_ok=True)
    _write_csv(output_root / "unresolved_domain_rows.csv", unresolved_domain_rows)
    _write_csv(output_root / "unresolved_root_domains.csv", root_domain_rows)
    _write_csv(output_root / "package_unresolved_summary.csv", package_summary_rows)

    summary = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "repo_root": str(_REPO_ROOT),
        "unresolved_domain_rows": len(unresolved_domain_rows),
        "unresolved_root_domain_rows": len(root_domain_rows),
        "packages_with_unresolved_domains": len(package_summary_rows),
        "candidate_service_match_rows": int(sum(1 for row in unresolved_domain_rows if row.get("candidate_service_key"))),
        "no_service_match_rows": int(sum(1 for row in unresolved_domain_rows if not row.get("candidate_service_key"))),
        "candidate_service_counts": dict(candidate_counter.most_common()),
        "candidate_service_hit_totals": dict(candidate_gap_counter.most_common()),
        "output_files": {
            "unresolved_domain_rows_csv": str((output_root / "unresolved_domain_rows.csv").resolve()),
            "unresolved_root_domains_csv": str((output_root / "unresolved_root_domains.csv").resolve()),
            "package_unresolved_summary_csv": str((output_root / "package_unresolved_summary.csv").resolve()),
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
