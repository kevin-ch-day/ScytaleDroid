#!/usr/bin/env python3
"""Read-only audit of static string enrichment vs dynamic network evidence.

Scans existing dynamic evidence packs and their embedded static dynamic plans to
measure how often higher-context static string signals are corroborated by
observed runtime DNS/SNI activity.

This is filesystem-first and DB-free by design.

Examples:

  PYTHONPATH=. python scripts/db/report_static_string_dynamic_corroboration.py
  PYTHONPATH=. python scripts/db/report_static_string_dynamic_corroboration.py --verbose
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@dataclass(frozen=True)
class CorroborationRow:
    dynamic_run_id: str
    package_name: str | None
    static_run_id: int | None
    static_handoff_hash: str | None
    static_domains_total: int
    static_domains_actionable: int
    static_domains_exploratory: int
    dynamic_domains_total: int
    corroborated_domains_total: int
    corroborated_actionable_domains: int
    corroborated_exploratory_domains: int
    corroborated_pair_groups: tuple[str, ...]
    enriched_domain_metadata_present: bool
    overlap_report_present: bool
    plan_path: str | None
    report_path: str | None
    overlap_path: str | None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Write outputs to this directory instead of output/audit/static_string_dynamic_corroboration/<stamp>/.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print compact progress to stderr.",
    )
    return parser


def _log(verbose: bool, message: str) -> None:
    if verbose:
        sys.stderr.write(f"{message}\n")


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _norm_text_or_none(value: Any) -> str | None:
    text = _norm_text(value)
    return text or None


def _safe_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


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


def _repo_rel(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(_REPO_ROOT.resolve()))
    except Exception:
        return str(path)


def _normalize_domain(value: Any) -> str:
    raw = _norm_text(value).lower()
    if not raw:
        return ""
    raw = raw.strip(" \t\r\n\"'()[]{}<>")
    raw = raw.rstrip(").,;")
    if raw.startswith("*."):
        raw = raw[2:]
    if "%" in raw or " " in raw:
        return ""
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]
    raw = raw.split("?", 1)[0]
    raw = raw.split("#", 1)[0]
    if ":" in raw:
        host, maybe_port = raw.rsplit(":", 1)
        if maybe_port.isdigit():
            raw = host
    if "." not in raw or ".." in raw:
        return ""
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    if any(ch not in allowed for ch in raw):
        return ""
    if raw.startswith(".") or raw.endswith(".") or raw.startswith("-") or raw.endswith("-"):
        return ""
    return raw


def _dynamic_run_dirs(output_root: Path) -> list[Path]:
    evidence_root = output_root / "evidence" / "dynamic"
    if not evidence_root.exists():
        return []
    return sorted(
        path for path in evidence_root.iterdir() if path.is_dir() and (path / "run_manifest.json").exists()
    )


def _dynamic_domains_from_report(report: Mapping[str, Any] | None) -> set[str]:
    domains: set[str] = set()
    if not isinstance(report, Mapping):
        return domains
    for key in ("top_dns", "top_sni"):
        rows = report.get(key)
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
            continue
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            domain = _normalize_domain(row.get("value"))
            if domain:
                domains.add(domain)
    return domains


def _domain_sources(plan: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(plan, Mapping):
        return []
    network = plan.get("network_targets")
    if not isinstance(network, Mapping):
        return []
    rows = network.get("domain_sources")
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
        return []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _row_to_sets(row: Mapping[str, Any]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for key in (
        "sources",
        "postures",
        "ownership_classes",
        "api_contexts",
        "pair_groups",
        "verification_statuses",
        "buckets",
    ):
        values = row.get(key)
        bucket: set[str] = set()
        if isinstance(values, Sequence) and not isinstance(values, (str, bytes, bytearray)):
            bucket.update(str(value) for value in values if _norm_text(value))
        elif key == "sources":
            singular = _norm_text(row.get("source"))
            if singular:
                bucket.add(singular)
        out[key] = bucket
    return out


def _corroboration_row(run_dir: Path) -> CorroborationRow | None:
    manifest = _read_json(run_dir / "run_manifest.json")
    if not isinstance(manifest, Mapping):
        return None
    plan_path = run_dir / "inputs" / "static_dynamic_plan.json"
    report_path = run_dir / "analysis" / "pcap_report.json"
    overlap_path = run_dir / "analysis" / "static_dynamic_overlap.json"
    plan = _read_json(plan_path)
    report = _read_json(report_path)

    dynamic_domains = _dynamic_domains_from_report(report)
    domain_rows = _domain_sources(plan)
    static_domains_total = 0
    static_domains_actionable = 0
    static_domains_exploratory = 0
    corroborated_domains_total = 0
    corroborated_actionable_domains = 0
    corroborated_exploratory_domains = 0
    corroborated_pair_groups: set[str] = set()
    enriched_domain_metadata_present = False

    for row in domain_rows:
        domain = _normalize_domain(row.get("domain"))
        if not domain:
            continue
        static_domains_total += 1
        parsed = _row_to_sets(row)
        postures = parsed.get("postures") or set()
        pair_groups = parsed.get("pair_groups") or set()
        if postures or pair_groups or parsed.get("ownership_classes") or parsed.get("api_contexts"):
            enriched_domain_metadata_present = True
        if "actionable" in postures:
            static_domains_actionable += 1
        if "exploratory" in postures:
            static_domains_exploratory += 1
        if domain in dynamic_domains:
            corroborated_domains_total += 1
            if "actionable" in postures:
                corroborated_actionable_domains += 1
            if "exploratory" in postures:
                corroborated_exploratory_domains += 1
            corroborated_pair_groups.update(pair_groups)

    target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
    identity = plan.get("run_identity") if isinstance(plan, Mapping) and isinstance(plan.get("run_identity"), Mapping) else {}
    return CorroborationRow(
        dynamic_run_id=_norm_text(manifest.get("dynamic_run_id")),
        package_name=_norm_text_or_none(target.get("package_name")),
        static_run_id=_safe_int(target.get("static_run_id") or identity.get("static_run_id")),
        static_handoff_hash=_norm_text_or_none(target.get("static_handoff_hash") or identity.get("static_handoff_hash")),
        static_domains_total=static_domains_total,
        static_domains_actionable=static_domains_actionable,
        static_domains_exploratory=static_domains_exploratory,
        dynamic_domains_total=len(dynamic_domains),
        corroborated_domains_total=corroborated_domains_total,
        corroborated_actionable_domains=corroborated_actionable_domains,
        corroborated_exploratory_domains=corroborated_exploratory_domains,
        corroborated_pair_groups=tuple(sorted(corroborated_pair_groups)),
        enriched_domain_metadata_present=enriched_domain_metadata_present,
        overlap_report_present=overlap_path.exists(),
        plan_path=_repo_rel(plan_path) if plan_path.exists() else None,
        report_path=_repo_rel(report_path) if report_path.exists() else None,
        overlap_path=_repo_rel(overlap_path) if overlap_path.exists() else None,
    )


def _summary(rows: Sequence[CorroborationRow]) -> dict[str, Any]:
    run_count = len(rows)
    enriched_runs = sum(1 for row in rows if row.enriched_domain_metadata_present)
    overlap_present_runs = sum(1 for row in rows if row.overlap_report_present)
    runs_with_any_corroboration = sum(1 for row in rows if row.corroborated_domains_total > 0)
    runs_with_actionable_corroboration = sum(
        1 for row in rows if row.corroborated_actionable_domains > 0
    )
    packages_with_actionable = sum(1 for row in rows if row.static_domains_actionable > 0)
    packages_with_actionable_corroboration = sum(
        1 for row in rows if row.corroborated_actionable_domains > 0
    )
    corroborated_pair_group_counter: Counter[str] = Counter()
    for row in rows:
        corroborated_pair_group_counter.update(row.corroborated_pair_groups)
    missing_enriched = [
        {
            "dynamic_run_id": row.dynamic_run_id,
            "package_name": row.package_name,
            "plan_path": row.plan_path,
        }
        for row in rows
        if not row.enriched_domain_metadata_present
    ]
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "report_type": "static_string_dynamic_corroboration",
        "repo_root": str(_REPO_ROOT),
        "dynamic_evidence_root": str((_REPO_ROOT / "output" / "evidence" / "dynamic").resolve()),
        "dynamic_runs_scanned": run_count,
        "runs_with_embedded_static_plan": sum(1 for row in rows if row.plan_path),
        "runs_with_dynamic_report": sum(1 for row in rows if row.report_path),
        "runs_with_overlap_report": overlap_present_runs,
        "runs_with_enriched_domain_metadata": enriched_runs,
        "runs_with_any_corroboration": runs_with_any_corroboration,
        "runs_with_actionable_corroboration": runs_with_actionable_corroboration,
        "packages_with_actionable_static_domains": packages_with_actionable,
        "packages_with_actionable_corroboration": packages_with_actionable_corroboration,
        "actionable_corroboration_rate": (
            packages_with_actionable_corroboration / float(packages_with_actionable)
            if packages_with_actionable
            else None
        ),
        "total_static_domains": sum(row.static_domains_total for row in rows),
        "total_dynamic_domains": sum(row.dynamic_domains_total for row in rows),
        "total_corroborated_domains": sum(row.corroborated_domains_total for row in rows),
        "total_actionable_static_domains": sum(row.static_domains_actionable for row in rows),
        "total_actionable_corroborated_domains": sum(
            row.corroborated_actionable_domains for row in rows
        ),
        "top_corroborated_pair_groups": [
            {"pair_group": pair_group, "run_count": count}
            for pair_group, count in corroborated_pair_group_counter.most_common(10)
        ],
        "runs_missing_enriched_domain_metadata": len(missing_enriched),
        "missing_enriched_domain_metadata_sample": missing_enriched[:10],
        "assumptions": [
            "filesystem_first_inputs",
            "embedded_static_dynamic_plan_required_for_static_domain_counts",
            "pcap_report_top_dns_top_sni_only",
            "actionable_corroboration_is_not_secret_validity_proof",
        ],
        "no_db_writes": True,
        "experimental_audit": True,
        "notes": [
            "This audit uses embedded static dynamic plans plus pcap_report top_dns/top_sni only.",
            "Actionable corroboration is stronger than exploratory overlap but is still not proof of secret validity or exploitation.",
            "Runs created before enriched string domain metadata existed will appear as missing enriched metadata.",
        ],
    }


def _row_dict(row: CorroborationRow) -> dict[str, Any]:
    return {
        "dynamic_run_id": row.dynamic_run_id,
        "package_name": row.package_name,
        "static_run_id": row.static_run_id,
        "static_handoff_hash": row.static_handoff_hash,
        "static_domains_total": row.static_domains_total,
        "static_domains_actionable": row.static_domains_actionable,
        "static_domains_exploratory": row.static_domains_exploratory,
        "dynamic_domains_total": row.dynamic_domains_total,
        "corroborated_domains_total": row.corroborated_domains_total,
        "corroborated_actionable_domains": row.corroborated_actionable_domains,
        "corroborated_exploratory_domains": row.corroborated_exploratory_domains,
        "corroborated_pair_group_count": len(row.corroborated_pair_groups),
        "corroborated_pair_groups": ";".join(row.corroborated_pair_groups),
        "enriched_domain_metadata_present": int(row.enriched_domain_metadata_present),
        "overlap_report_present": int(row.overlap_report_present),
        "plan_path": row.plan_path,
        "report_path": row.report_path,
        "overlap_path": row.overlap_path,
    }


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Config import app_config
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    output_root = Path(app_config.OUTPUT_DIR)
    if args.output_dir:
        out_dir = Path(args.output_dir)
    else:
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        out_dir = output_root / "audit" / "static_string_dynamic_corroboration" / stamp
    out_dir.mkdir(parents=True, exist_ok=True)

    rows: list[CorroborationRow] = []
    for run_dir in _dynamic_run_dirs(output_root):
        _log(args.verbose, f"scan {run_dir.name}")
        row = _corroboration_row(run_dir)
        if row is not None:
            rows.append(row)

    summary = _summary(rows)
    row_dicts = [_row_dict(row) for row in rows]
    actionable_rows = [row for row in row_dicts if int(row.get("corroborated_actionable_domains") or 0) > 0]
    pair_rows = [
        {
            "dynamic_run_id": row.dynamic_run_id,
            "package_name": row.package_name,
            "pair_group": pair_group,
        }
        for row in rows
        for pair_group in row.corroborated_pair_groups
    ]

    _write_json(out_dir / "summary.json", summary)
    _write_csv(out_dir / "corroboration_matrix.csv", row_dicts)
    _write_csv(out_dir / "actionable_corroboration.csv", actionable_rows)
    _write_csv(out_dir / "pair_group_corroboration.csv", pair_rows)

    summary["output_dir"] = str(out_dir)
    summary["output_files"] = {
        "summary_json": str(out_dir / "summary.json"),
        "corroboration_matrix_csv": str(out_dir / "corroboration_matrix.csv"),
        "actionable_corroboration_csv": str(out_dir / "actionable_corroboration.csv"),
        "pair_group_corroboration_csv": str(out_dir / "pair_group_corroboration.csv"),
    }
    _write_json(out_dir / "summary.json", summary)

    print(json.dumps(summary, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
