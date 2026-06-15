#!/usr/bin/env python3
"""Read-only package-level tracker context overlap from external tracker intel.

This audit correlates repo-owned external tracker reference data with existing
static string endpoint evidence. It is intentionally conservative:

- external data comes from `external_sdk_tracker_intel`
- local evidence comes from `static_string_selected_samples.root_domain`
- overlaps are contextual, not proof of embedded tracker SDK presence

Because the current selected string samples store root domains rather than full
hostnames/URLs for endpoint rows, the report separates specific overlaps from
generic-root or infrastructure-root overlaps.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

COMMON_TWO_PART_SUFFIXES = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "co.jp",
    "com.br",
}
GENERIC_ROOT_DOMAINS = {
    "amazon.com",
    "android.com",
    "apple.com",
    "facebook.com",
    "fb.com",
    "google.com",
    "linkedin.com",
    "meta.com",
    "microsoft.com",
    "tiktok.com",
    "uber.com",
    "youtube.com",
}
GENERIC_INFRASTRUCTURE_ROOTS = {
    "akamaihd.net",
    "amazonaws.com",
    "cloudfront.net",
    "doubleclick.net",
    "gstatic.com",
    "googleapis.com",
}


@dataclass(frozen=True)
class RunPackage:
    static_run_id: int
    package_name: str
    display_name: str
    session_stamp: str | None
    session_label: str | None
    scope_label: str | None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", help="Restrict to one static session_stamp. Default is latest preferred run per package.")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Write outputs to this directory instead of output/audit/external_tracker_context/<stamp>/.",
    )
    parser.add_argument("--verbose", action="store_true", help="Print compact progress to stderr.")
    return parser


def _log(verbose: bool, message: str) -> None:
    if verbose:
        sys.stderr.write(f"{message}\n")


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _norm_text_or_none(value: Any) -> str | None:
    text = _norm_text(value)
    return text or None


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    row_list = list(rows)
    if not row_list:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    for row in row_list:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in row_list:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _table_exists(core_q: Any, name: str) -> bool:
    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS c
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name = %s
        """,
        (name,),
        fetch="one",
        dictionary=True,
        query_name="report.external_tracker_context.table_exists",
    ) or {}
    return bool(int(row.get("c") or 0))


def _latest_runs_sql() -> str:
    return """
    SELECT
      sar.id AS static_run_id,
      a.package_name,
      COALESCE(NULLIF(a.display_name, ''), a.package_name) AS display_name,
      sar.session_stamp,
      sar.session_label,
      sar.scope_label
    FROM static_analysis_runs sar
    JOIN app_versions av ON av.id = sar.app_version_id
    JOIN apps a ON a.id = av.app_id
    JOIN (
      SELECT
        a2.package_name,
        COALESCE(
          MAX(CASE
            WHEN UPPER(COALESCE(sar2.status, '')) = 'COMPLETED'
             AND UPPER(COALESCE(sar2.run_class, '')) = 'CANONICAL'
            THEN sar2.id
          END),
          MAX(CASE
            WHEN UPPER(COALESCE(sar2.status, '')) = 'COMPLETED'
            THEN sar2.id
          END),
          MAX(sar2.id)
        ) AS preferred_static_run_id
      FROM static_analysis_runs sar2
      JOIN app_versions av2 ON av2.id = sar2.app_version_id
      JOIN apps a2 ON a2.id = av2.app_id
      GROUP BY a2.package_name
    ) preferred
      ON preferred.package_name = a.package_name
     AND preferred.preferred_static_run_id = sar.id
    ORDER BY a.package_name ASC, sar.id ASC
    """


def _session_runs_sql() -> str:
    return """
    SELECT
      sar.id AS static_run_id,
      a.package_name,
      COALESCE(NULLIF(a.display_name, ''), a.package_name) AS display_name,
      sar.session_stamp,
      sar.session_label,
      sar.scope_label
    FROM static_analysis_runs sar
    JOIN app_versions av ON av.id = sar.app_version_id
    JOIN apps a ON a.id = av.app_id
    WHERE sar.session_stamp = %s
      AND UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
    ORDER BY a.package_name ASC, sar.id ASC
    """


def _load_runs(core_q: Any, *, session: str | None) -> list[RunPackage]:
    if session:
        rows = core_q.run_sql(
            _session_runs_sql(),
            (session,),
            fetch="all",
            dictionary=True,
            query_name="report.external_tracker_context.session_runs",
        ) or []
    else:
        rows = core_q.run_sql(
            _latest_runs_sql(),
            (),
            fetch="all",
            dictionary=True,
            query_name="report.external_tracker_context.latest_runs",
        ) or []
    out: list[RunPackage] = []
    for row in rows:
        out.append(
            RunPackage(
                static_run_id=int(row["static_run_id"]),
                package_name=_norm_text(row.get("package_name")).lower(),
                display_name=_norm_text(row.get("display_name")) or _norm_text(row.get("package_name")).lower(),
                session_stamp=_norm_text_or_none(row.get("session_stamp")),
                session_label=_norm_text_or_none(row.get("session_label")),
                scope_label=_norm_text_or_none(row.get("scope_label")),
            )
        )
    return out


def _ids_sql(run_ids: Sequence[int]) -> tuple[str, tuple[Any, ...]]:
    placeholders = ",".join(["%s"] * len(run_ids))
    return placeholders, tuple(int(run_id) for run_id in run_ids)


def _approx_root_domain(host: str) -> str:
    text = _norm_text(host).lower().strip(".")
    if "." not in text:
        return text
    parts = [part for part in text.split(".") if part]
    if len(parts) < 2:
        return text
    tail = ".".join(parts[-2:])
    if len(parts) >= 3 and tail in COMMON_TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return tail


def _extract_domain_tokens(network_signature: Any) -> list[str]:
    tokens: set[str] = set()
    for raw in str(network_signature or "").split("|"):
        text = raw.strip()
        if not text:
            continue
        text = text.replace("\\.", ".").replace("\\-", "-").replace("\\_", "_")
        text = text.replace(".*.", "").replace(".*", "")
        text = text.lstrip(".^").rstrip("$").replace("\\", "").strip(". ")
        if not text or "." not in text:
            continue
        if not re.fullmatch(r"[a-z0-9._-]+", text):
            continue
        root = _approx_root_domain(text)
        if root:
            tokens.add(root)
    return sorted(tokens)


def _classify_overlap_confidence(root_domain: str) -> tuple[str, str]:
    root = _approx_root_domain(root_domain)
    if root in GENERIC_ROOT_DOMAINS:
        return "low", "generic_root_overlap"
    if root in GENERIC_INFRASTRUCTURE_ROOTS:
        return "low", "generic_infrastructure_overlap"
    return "medium", "specific_root_overlap"


def _load_external_tracker_domains(core_q: Any) -> tuple[list[dict[str, Any]], list[str], str | None]:
    if not _table_exists(core_q, "external_sdk_tracker_intel"):
        return [], ["missing_table:external_sdk_tracker_intel"], None
    snapshot_row = core_q.run_sql(
        "SELECT MAX(snapshot_date) AS snapshot_date FROM external_sdk_tracker_intel",
        (),
        fetch="one",
        dictionary=True,
        query_name="report.external_tracker_context.latest_snapshot",
    ) or {}
    snapshot_date = _norm_text_or_none(snapshot_row.get("snapshot_date"))
    if not snapshot_date:
        return [], ["no_snapshot_rows:external_sdk_tracker_intel"], None
    rows = core_q.run_sql(
        """
        SELECT
          tracker_name,
          tracker_id_external,
          network_signature,
          code_signature,
          website,
          categories_json
        FROM external_sdk_tracker_intel
        WHERE snapshot_date = %s
        ORDER BY tracker_name ASC, tracker_id_external ASC
        """,
        (snapshot_date,),
        fetch="all",
        dictionary=True,
        query_name="report.external_tracker_context.external_trackers",
    ) or []
    warnings: list[str] = []
    out: list[dict[str, Any]] = []
    for row in rows:
        tokens = _extract_domain_tokens(row.get("network_signature"))
        if row.get("network_signature") and not tokens:
            warnings.append(f"no_domain_tokens:{_norm_text(row.get('tracker_name'))}")
        categories: list[str] = []
        raw_categories = row.get("categories_json")
        if isinstance(raw_categories, str) and raw_categories.strip():
            try:
                parsed = json.loads(raw_categories)
            except json.JSONDecodeError:
                parsed = []
            if isinstance(parsed, list):
                categories = [str(item).strip() for item in parsed if str(item).strip()]
        out.append(
            {
                "tracker_name": _norm_text(row.get("tracker_name")),
                "tracker_id_external": _norm_text(row.get("tracker_id_external")),
                "domain_tokens": tokens,
                "code_signature": _norm_text_or_none(row.get("code_signature")),
                "website": _norm_text_or_none(row.get("website")),
                "categories": categories,
            }
        )
    return out, warnings, snapshot_date


def _load_package_domains(core_q: Any, run_ids: Sequence[int]) -> list[dict[str, Any]]:
    if not run_ids:
        return []
    table_name = "static_string_selected_samples" if _table_exists(core_q, "static_string_selected_samples") else "static_string_samples"
    ids_sql, params = _ids_sql(run_ids)
    rows = core_q.run_sql(
        f"""
        SELECT
          sample.static_run_id AS static_run_id,
          summary.package_name,
          sample.root_domain,
          COUNT(*) AS sample_count,
          SUM(CASE WHEN sample.scheme = 'http' THEN 1 ELSE 0 END) AS http_sample_count,
          SUM(CASE WHEN sample.scheme = 'https' THEN 1 ELSE 0 END) AS https_sample_count
        FROM {table_name} sample
        JOIN static_string_summary summary ON summary.id = sample.summary_id
        WHERE sample.static_run_id IN ({ids_sql})
          AND sample.root_domain IS NOT NULL
          AND TRIM(sample.root_domain) <> ''
        GROUP BY sample.static_run_id, summary.package_name, sample.root_domain
        ORDER BY summary.package_name ASC, sample.root_domain ASC
        """,
        params,
        fetch="all",
        dictionary=True,
        query_name="report.external_tracker_context.package_domains",
    ) or []
    return [dict(row) for row in rows]


def _build_overlap_rows(
    runs: Sequence[RunPackage],
    package_domains: Sequence[Mapping[str, Any]],
    tracker_rows: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    run_by_id = {run.static_run_id: run for run in runs}
    token_to_trackers: dict[str, list[dict[str, Any]]] = defaultdict(list)
    tracker_inventory_rows: list[dict[str, Any]] = []
    for tracker in tracker_rows:
        tokens = tracker.get("domain_tokens") or []
        if not isinstance(tokens, list):
            continue
        if not tokens:
            tracker_inventory_rows.append(
                {
                    "tracker_name": tracker.get("tracker_name"),
                    "tracker_id_external": tracker.get("tracker_id_external"),
                    "domain_token": None,
                    "domain_token_confidence": None,
                    "website": tracker.get("website"),
                    "categories": ", ".join(tracker.get("categories") or []),
                    "code_signature_present": bool(tracker.get("code_signature")),
                }
            )
            continue
        for token in tokens:
            confidence, reason = _classify_overlap_confidence(token)
            token_to_trackers[token].append(dict(tracker))
            tracker_inventory_rows.append(
                {
                    "tracker_name": tracker.get("tracker_name"),
                    "tracker_id_external": tracker.get("tracker_id_external"),
                    "domain_token": token,
                    "domain_token_confidence": confidence,
                    "domain_token_reason": reason,
                    "website": tracker.get("website"),
                    "categories": ", ".join(tracker.get("categories") or []),
                    "code_signature_present": bool(tracker.get("code_signature")),
                }
            )

    overlap_rows: list[dict[str, Any]] = []
    unmatched_rows: list[dict[str, Any]] = []
    for row in package_domains:
        run_id = int(row.get("static_run_id") or 0)
        run = run_by_id.get(run_id)
        if run is None:
            continue
        root_domain = _norm_text(row.get("root_domain")).lower()
        matched = token_to_trackers.get(root_domain) or []
        if not matched:
            unmatched_rows.append(
                {
                    "static_run_id": run.static_run_id,
                    "package_name": run.package_name,
                    "display_name": run.display_name,
                    "root_domain": root_domain,
                    "sample_count": int(row.get("sample_count") or 0),
                    "http_sample_count": int(row.get("http_sample_count") or 0),
                    "https_sample_count": int(row.get("https_sample_count") or 0),
                }
            )
            continue
        for tracker in matched:
            confidence, reason = _classify_overlap_confidence(root_domain)
            overlap_rows.append(
                {
                    "static_run_id": run.static_run_id,
                    "package_name": run.package_name,
                    "display_name": run.display_name,
                    "session_stamp": run.session_stamp,
                    "session_label": run.session_label,
                    "scope_label": run.scope_label,
                    "root_domain": root_domain,
                    "sample_count": int(row.get("sample_count") or 0),
                    "http_sample_count": int(row.get("http_sample_count") or 0),
                    "https_sample_count": int(row.get("https_sample_count") or 0),
                    "tracker_name": tracker.get("tracker_name"),
                    "tracker_id_external": tracker.get("tracker_id_external"),
                    "overlap_confidence": confidence,
                    "overlap_reason": reason,
                    "tracker_categories": ", ".join(tracker.get("categories") or []),
                    "tracker_website": tracker.get("website"),
                    "code_signature_present": bool(tracker.get("code_signature")),
                }
            )
    return overlap_rows, unmatched_rows, tracker_inventory_rows


def _summarize_overlap_rows(overlap_rows: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    package_rollup: dict[tuple[int, str], dict[str, Any]] = {}
    tracker_rollup: dict[tuple[str, str], dict[str, Any]] = {}
    for row in overlap_rows:
        package_key = (int(row.get("static_run_id") or 0), _norm_text(row.get("package_name")).lower())
        package_entry = package_rollup.setdefault(
            package_key,
            {
                "static_run_id": row.get("static_run_id"),
                "package_name": row.get("package_name"),
                "display_name": row.get("display_name"),
                "session_stamp": row.get("session_stamp"),
                "matched_tracker_names": set(),
                "matched_root_domains": set(),
                "confidence_levels": set(),
                "http_sample_count": 0,
                "https_sample_count": 0,
            },
        )
        package_entry["matched_tracker_names"].add(_norm_text(row.get("tracker_name")))
        package_entry["matched_root_domains"].add(_norm_text(row.get("root_domain")).lower())
        package_entry["confidence_levels"].add(_norm_text(row.get("overlap_confidence")))
        package_entry["http_sample_count"] += int(row.get("http_sample_count") or 0)
        package_entry["https_sample_count"] += int(row.get("https_sample_count") or 0)

        tracker_key = (_norm_text(row.get("tracker_name")), _norm_text(row.get("overlap_confidence")))
        tracker_entry = tracker_rollup.setdefault(
            tracker_key,
            {
                "tracker_name": row.get("tracker_name"),
                "overlap_confidence": row.get("overlap_confidence"),
                "package_names": set(),
                "root_domains": set(),
                "sample_rows": 0,
            },
        )
        tracker_entry["package_names"].add(_norm_text(row.get("package_name")).lower())
        tracker_entry["root_domains"].add(_norm_text(row.get("root_domain")).lower())
        tracker_entry["sample_rows"] += int(row.get("sample_count") or 0)

    package_rows: list[dict[str, Any]] = []
    for entry in package_rollup.values():
        package_rows.append(
            {
                "static_run_id": entry["static_run_id"],
                "package_name": entry["package_name"],
                "display_name": entry["display_name"],
                "session_stamp": entry["session_stamp"],
                "matched_tracker_count": len(entry["matched_tracker_names"]),
                "matched_root_domain_count": len(entry["matched_root_domains"]),
                "confidence_levels": ", ".join(sorted(entry["confidence_levels"])),
                "matched_tracker_names": ", ".join(sorted(entry["matched_tracker_names"])),
                "matched_root_domains": ", ".join(sorted(entry["matched_root_domains"])),
                "http_sample_count": entry["http_sample_count"],
                "https_sample_count": entry["https_sample_count"],
            }
        )
    package_rows.sort(key=lambda row: (-int(row["matched_tracker_count"]), str(row["package_name"])))

    tracker_rows: list[dict[str, Any]] = []
    for entry in tracker_rollup.values():
        tracker_rows.append(
            {
                "tracker_name": entry["tracker_name"],
                "overlap_confidence": entry["overlap_confidence"],
                "matched_package_count": len(entry["package_names"]),
                "matched_root_domain_count": len(entry["root_domains"]),
                "sample_rows": entry["sample_rows"],
                "package_names": ", ".join(sorted(entry["package_names"])),
                "root_domains": ", ".join(sorted(entry["root_domains"])),
            }
        )
    tracker_rows.sort(key=lambda row: (-int(row["matched_package_count"]), str(row["tracker_name"])))
    return package_rows, tracker_rows


def _summarize_unmatched_domains(unmatched_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rollup: dict[str, dict[str, Any]] = {}
    for row in unmatched_rows:
        domain = _norm_text(row.get("root_domain")).lower()
        entry = rollup.setdefault(
            domain,
            {
                "root_domain": domain,
                "package_names": set(),
                "sample_rows": 0,
                "http_sample_count": 0,
                "https_sample_count": 0,
            },
        )
        entry["package_names"].add(_norm_text(row.get("package_name")).lower())
        entry["sample_rows"] += int(row.get("sample_count") or 0)
        entry["http_sample_count"] += int(row.get("http_sample_count") or 0)
        entry["https_sample_count"] += int(row.get("https_sample_count") or 0)
    rows: list[dict[str, Any]] = []
    for entry in rollup.values():
        rows.append(
            {
                "root_domain": entry["root_domain"],
                "package_count": len(entry["package_names"]),
                "sample_rows": entry["sample_rows"],
                "http_sample_count": entry["http_sample_count"],
                "https_sample_count": entry["https_sample_count"],
                "example_packages": ", ".join(sorted(list(entry["package_names"]))[:10]),
            }
        )
    rows.sort(key=lambda row: (-int(row["package_count"]), -int(row["sample_rows"]), str(row["root_domain"])))
    return rows


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    runs = _load_runs(core_q, session=args.session)
    run_ids = [run.static_run_id for run in runs]
    _log(args.verbose, f"selected_runs={len(run_ids)}")

    package_domains = _load_package_domains(core_q, run_ids)
    tracker_rows, warnings, snapshot_date = _load_external_tracker_domains(core_q)
    overlap_rows, unmatched_rows, tracker_inventory_rows = _build_overlap_rows(runs, package_domains, tracker_rows)
    package_rollup_rows, tracker_rollup_rows = _summarize_overlap_rows(overlap_rows)
    unmatched_domain_rows = _summarize_unmatched_domains(unmatched_rows)

    confidence_counts = Counter(_norm_text(row.get("overlap_confidence")) for row in overlap_rows if row.get("overlap_confidence"))
    tracker_domain_token_count = sum(len(row.get("domain_tokens") or []) for row in tracker_rows)

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.output_dir) if args.output_dir else (_REPO_ROOT / "output" / "audit" / "external_tracker_context" / stamp)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "snapshot_date": snapshot_date,
        "report_scope": "session" if args.session else "latest_preferred_per_package",
        "session": args.session,
        "package_count": len(runs),
        "selected_endpoint_domain_rows": len(package_domains),
        "distinct_root_domain_count": len({_norm_text(row.get('root_domain')).lower() for row in package_domains if row.get('root_domain')}),
        "external_tracker_count": len(tracker_rows),
        "tracker_domain_token_count": tracker_domain_token_count,
        "package_with_any_overlap_count": len(package_rollup_rows),
        "package_with_medium_overlap_count": sum(1 for row in package_rollup_rows if "medium" in _norm_text(row.get("confidence_levels")).split(", ")),
        "package_with_low_overlap_count": sum(1 for row in package_rollup_rows if "low" in _norm_text(row.get("confidence_levels")).split(", ")),
        "overlap_row_count": len(overlap_rows),
        "overlap_confidence_counts": dict(sorted(confidence_counts.items())),
        "top_trackers": tracker_rollup_rows[:15],
        "warnings": sorted(set(warnings)),
        "assumptions": [
            "Matches are contextual overlays derived from selected static endpoint root domains.",
            "Current selected endpoint evidence stores root domains, not full hostnames or URLs.",
            "Generic-root and infrastructure-root overlaps are intentionally labeled low confidence.",
            "No DB writes were performed by this report.",
        ],
        "no_db_writes": True,
        "experimental_audit": True,
        "output_files": [
            "summary.json",
            "package_tracker_context.csv",
            "tracker_context_rollup.csv",
            "tracker_context_overlaps.csv",
            "unmatched_root_domains.csv",
            "tracker_domain_inventory.csv",
        ],
    }

    _write_json(out_dir / "summary.json", summary)
    _write_csv(out_dir / "package_tracker_context.csv", package_rollup_rows)
    _write_csv(out_dir / "tracker_context_rollup.csv", tracker_rollup_rows)
    _write_csv(out_dir / "tracker_context_overlaps.csv", overlap_rows)
    _write_csv(out_dir / "unmatched_root_domains.csv", unmatched_domain_rows)
    _write_csv(out_dir / "tracker_domain_inventory.csv", tracker_inventory_rows)

    print("# external tracker context")
    print(f"snapshot_date: {snapshot_date or 'unknown'}")
    print(f"package_count: {summary['package_count']}")
    print(f"selected_endpoint_domain_rows: {summary['selected_endpoint_domain_rows']}")
    print(f"external_tracker_count: {summary['external_tracker_count']}")
    print(f"tracker_domain_token_count: {summary['tracker_domain_token_count']}")
    print(f"package_with_any_overlap_count: {summary['package_with_any_overlap_count']}")
    print(f"package_with_medium_overlap_count: {summary['package_with_medium_overlap_count']}")
    print(f"package_with_low_overlap_count: {summary['package_with_low_overlap_count']}")
    print(f"overlap_confidence_counts: {json.dumps(summary['overlap_confidence_counts'], sort_keys=True)}")
    print(f"output_dir: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
