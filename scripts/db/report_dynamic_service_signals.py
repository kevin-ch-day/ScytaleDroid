#!/usr/bin/env python3
"""Read-only report over dynamic privacy/security/context signals derived from service context."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
        for key in row:
            if key not in fields:
                fields.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fields})


def generate_report(*, packages: list[str] | None = None, output_dir: Path | None = None) -> dict[str, Any]:
    from scytaledroid.Database.db_core import db_queries as core_q
    from scytaledroid.DynamicAnalysis.service_context import (
        default_service_catalog_seed_rows,
        default_service_domain_map_seed_rows,
        resolve_service_for_domain,
    )
    from scytaledroid.DynamicAnalysis.service_signals import (
        default_service_signal_map_seed_rows,
        default_signal_catalog_seed_rows,
    )

    from scripts.db._dynamic_service_seed_overlay import (
        merge_missing_seed_service_maps,
        merge_missing_seed_services,
    )

    package_filters = [str(value or "").strip().lower() for value in (packages or []) if str(value or "").strip()]
    where_sql = ""
    params: tuple[object, ...] = ()
    if package_filters:
        placeholders = ", ".join(["%s"] * len(package_filters))
        where_sql = f"WHERE ddo.package_name IN ({placeholders})"
        params = tuple(package_filters)

    observation_rows = core_q.run_sql(
        f"""
        SELECT
          ddo.package_name,
          COALESCE(a.display_name, ddo.package_name) AS display_name,
          ddo.observed_domain AS domain,
          ddo.root_domain,
          ddo.owner_class AS observed_owner_class,
          ddo.role_class AS observed_role_class,
          SUM(COALESCE(ddo.indicator_count, 0)) AS total_hits,
          COUNT(DISTINCT ddo.dynamic_run_id) AS observed_run_count
        FROM dynamic_domain_observations ddo
        LEFT JOIN apps a
          ON a.package_name = ddo.package_name
        {where_sql}
        GROUP BY ddo.package_name, COALESCE(a.display_name, ddo.package_name), ddo.observed_domain, ddo.root_domain, ddo.owner_class, ddo.role_class
        ORDER BY ddo.package_name, total_hits DESC, ddo.observed_domain
        """,
        params,
        fetch="all",
        dictionary=True,
        query_name="dynamic.service_signals.report.observations",
    ) or []

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
          source_url,
          confidence
        FROM dynamic_service_catalog
        WHERE is_active = 1
        ORDER BY service_key
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic.service_signals.report.services",
    ) or []
    service_map_rows = core_q.run_sql(
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
        query_name="dynamic.service_signals.report.service_maps",
    ) or []
    signal_rows = core_q.run_sql(
        """
        SELECT
          signal_key,
          display_name,
          signal_family,
          focus_area,
          severity_hint,
          description,
          analyst_guidance,
          source_url
        FROM dynamic_signal_catalog
        WHERE is_active = 1
        ORDER BY focus_area, severity_hint, signal_key
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic.service_signals.report.signals",
    ) or []
    service_signal_rows = core_q.run_sql(
        """
        SELECT
          dsc.service_key,
          dsg.signal_key,
          dssm.signal_strength,
          dssm.confidence,
          dssm.rationale
        FROM dynamic_service_signal_map dssm
        JOIN dynamic_service_catalog dsc
          ON dsc.service_id = dssm.service_id
        JOIN dynamic_signal_catalog dsg
          ON dsg.signal_id = dssm.signal_id
        WHERE dssm.is_active = 1
          AND dsc.is_active = 1
          AND dsg.is_active = 1
        ORDER BY dsc.service_key, dsg.signal_key
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="dynamic.service_signals.report.service_signal_maps",
    ) or []

    service_rows = merge_missing_seed_services(service_rows, default_service_catalog_seed_rows())
    service_map_rows = merge_missing_seed_service_maps(service_map_rows, default_service_domain_map_seed_rows())
    signal_rows = _merge_missing_seed_signals(signal_rows, default_signal_catalog_seed_rows())
    service_signal_rows = _merge_missing_seed_service_signal_maps(
        service_signal_rows,
        default_service_signal_map_seed_rows(),
    )

    service_tuple = tuple(dict(row) for row in service_rows if isinstance(row, Mapping))
    service_map_tuple = tuple(dict(row) for row in service_map_rows if isinstance(row, Mapping))
    signals_by_key = {str(row.get("signal_key") or ""): dict(row) for row in signal_rows if isinstance(row, Mapping)}
    signals_by_service: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in service_signal_rows:
        if isinstance(row, Mapping):
            signals_by_service[str(row.get("service_key") or "")].append(dict(row))

    signal_observation_rows: list[dict[str, Any]] = []
    services_without_signal_mappings_rows: list[dict[str, Any]] = []
    package_summary: dict[str, Counter[str]] = defaultdict(Counter)
    focus_area_counts = Counter()
    severity_counts = Counter()

    for row in observation_rows:
        if not isinstance(row, Mapping):
            continue
        package_name = str(row.get("package_name") or "").strip().lower()
        domain = str(row.get("domain") or "").strip().lower()
        resolved = resolve_service_for_domain(
            domain,
            package_name=package_name,
            service_rows=service_tuple,
            map_rows=service_map_tuple,
        )
        service_key = str(resolved.get("service_key") or "")
        if not service_key:
            services_without_signal_mappings_rows.append(dict(row))
            continue
        signal_maps = signals_by_service.get(service_key) or []
        if not signal_maps:
            services_without_signal_mappings_rows.append(
                {**dict(row), "service_key": service_key, "service_display_name": resolved.get("service_display_name")}
            )
            continue
        for signal_map in signal_maps:
            signal = signals_by_key.get(str(signal_map.get("signal_key") or ""))
            if not signal:
                continue
            out_row = {
                "package_name": package_name,
                "display_name": row.get("display_name"),
                "domain": domain,
                "root_domain": row.get("root_domain"),
                "service_key": service_key,
                "service_display_name": resolved.get("service_display_name"),
                "service_category": resolved.get("service_category"),
                "signal_key": signal.get("signal_key"),
                "signal_display_name": signal.get("display_name"),
                "signal_family": signal.get("signal_family"),
                "focus_area": signal.get("focus_area"),
                "severity_hint": signal.get("severity_hint"),
                "signal_strength": signal_map.get("signal_strength"),
                "signal_confidence": signal_map.get("confidence"),
                "signal_description": signal.get("description"),
                "analyst_guidance": signal.get("analyst_guidance"),
                "signal_source_url": signal.get("source_url"),
                "total_hits": int(row.get("total_hits") or 0),
                "observed_run_count": int(row.get("observed_run_count") or 0),
            }
            signal_observation_rows.append(out_row)
            package_summary[package_name][str(signal.get("signal_key") or "")] += int(row.get("total_hits") or 0)
            focus_area_counts[str(signal.get("focus_area") or "")] += int(row.get("total_hits") or 0)
            severity_counts[str(signal.get("severity_hint") or "")] += int(row.get("total_hits") or 0)

    package_summary_rows: list[dict[str, Any]] = []
    for package_name in sorted(package_summary):
        counts = package_summary[package_name]
        top = counts.most_common(8)
        package_summary_rows.append(
            {
                "package_name": package_name,
                "distinct_signals": len(counts),
                "signal_hits_total": sum(counts.values()),
                "top_signals": ",".join(f"{key}:{value}" for key, value in top),
            }
        )

    output_root = output_dir or (_REPO_ROOT / "output" / "audit" / "dynamic_service_signals" / datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S"))
    output_root.mkdir(parents=True, exist_ok=True)
    _write_csv(output_root / "package_signal_rows.csv", signal_observation_rows)
    _write_csv(output_root / "package_signal_summary.csv", package_summary_rows)
    _write_csv(output_root / "services_without_signal_mappings.csv", services_without_signal_mappings_rows)

    summary = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "repo_root": str(_REPO_ROOT),
        "packages_scanned": len({str(row.get('package_name') or '') for row in observation_rows}),
        "observation_rows": len(observation_rows),
        "signal_observation_rows": len(signal_observation_rows),
        "services_without_signal_mappings": len(services_without_signal_mappings_rows),
        "focus_area_hit_counts": dict(sorted(focus_area_counts.items())),
        "severity_hit_counts": dict(sorted(severity_counts.items())),
        "output_files": {
            "package_signal_rows_csv": str((output_root / "package_signal_rows.csv").resolve()),
            "package_signal_summary_csv": str((output_root / "package_signal_summary.csv").resolve()),
            "services_without_signal_mappings_csv": str((output_root / "services_without_signal_mappings.csv").resolve()),
            "summary_json": str((output_root / "summary.json").resolve()),
        },
        "no_db_writes": True,
        "experimental_audit": True,
    }
    (output_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def _merge_missing_seed_signals(
    db_rows: list[dict[str, Any]],
    seed_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = [dict(row) for row in db_rows if isinstance(row, Mapping)]
    seen = {str(row.get("signal_key") or "") for row in merged}
    for row in seed_rows:
        signal_key = str(row.get("signal_key") or "")
        if signal_key and signal_key not in seen:
            merged.append(dict(row))
            seen.add(signal_key)
    merged.sort(key=lambda row: (str(row.get("focus_area") or ""), str(row.get("severity_hint") or ""), str(row.get("signal_key") or "")))
    return merged


def _merge_missing_seed_service_signal_maps(
    db_rows: list[dict[str, Any]],
    seed_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = [dict(row) for row in db_rows if isinstance(row, Mapping)]
    seen = {
        (
            str(row.get("service_key") or ""),
            str(row.get("signal_key") or ""),
            str(row.get("signal_strength") or ""),
        )
        for row in merged
    }
    for row in seed_rows:
        key = (
            str(row.get("service_key") or ""),
            str(row.get("signal_key") or ""),
            str(row.get("signal_strength") or ""),
        )
        if key[0] and key[1] and key not in seen:
            merged.append(dict(row))
            seen.add(key)
    merged.sort(key=lambda row: (str(row.get("service_key") or ""), str(row.get("signal_key") or ""), str(row.get("signal_strength") or "")))
    return merged


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    summary = generate_report(packages=args.package, output_dir=output_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
