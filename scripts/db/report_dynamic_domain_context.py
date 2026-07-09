#!/usr/bin/env python3
"""Read-only domain-context report over dynamic evidence packs.

This audit is filesystem-first and DB-optional. It helps interpret dynamic
network evidence by classifying observed DNS/SNI indicators into coarse context
buckets such as first-party publisher, engagement/push, analytics/measurement,
adtech, attribution, experimentation, and unknown.

It is intentionally conservative:

- It does not inspect payloads or decrypt traffic.
- It treats exact/curated suffix matches as stronger than package-root hints.
- It separates quota/accounting state from contextual interpretation.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scytaledroid.DynamicAnalysis.domain_context import (
    classify_domain,
    normalize_domain,
    root_domain,
    suffix_match,
)
from scytaledroid.DynamicAnalysis.ip_context import classify_ip_destination, normalize_ip


@dataclass(frozen=True)
class RunRow:
    run_dir_name: str
    run_id: str
    package_name: str
    display_name: str
    run_profile: str
    valid_dataset_run: bool | None
    paper_eligible: bool | None
    countable: bool | None
    ended_at: str | None
    sampling_seconds: float | None
    pcap_bytes: int | None
    packet_count: int | None
    unique_dns_count: int | None
    unique_sni_count: int | None
    domains_per_min: float | None
    top_dns: tuple[tuple[str, int], ...]
    top_sni: tuple[tuple[str, int], ...]
    top_ip_dst: tuple[tuple[str, int], ...]
    static_domains_count: int | None
    dynamic_domains_count: int | None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package",
        action="append",
        default=[],
        help="Restrict to one or more package names.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Write outputs to this directory instead of output/audit/dynamic_domain_context/<stamp>/.",
    )
    parser.add_argument("--verbose", action="store_true", help="Print compact progress to stderr.")
    return parser


def _log(verbose: bool, message: str) -> None:
    if verbose:
        sys.stderr.write(f"{message}\n")


def _utcnow_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _norm_text_or_none(value: Any) -> str | None:
    text = _norm_text(value)
    return text or None


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


def _normalize_domain(value: Any) -> str:
    return normalize_domain(value)


def _root_domain(host: str) -> str:
    return root_domain(host)


def _suffix_match(domain: str, suffix: str) -> bool:
    return suffix_match(domain, suffix)


def _context_for_domain(domain: str, *, package_name: str) -> dict[str, str | bool]:
    return classify_domain(domain, package_name=package_name)


def _context_for_ip_destination(value: str, *, package_name: str) -> dict[str, str | bool]:
    return classify_ip_destination(value, package_name=package_name)


def _dynamic_root() -> Path:
    from scytaledroid.Config import app_config

    return Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"


def _iter_run_dirs(*, packages: set[str]) -> list[Path]:
    root = _dynamic_root()
    if not root.exists():
        return []
    out: list[Path] = []
    for path in sorted(root.iterdir()):
        if not path.is_dir():
            continue
        manifest = _read_json(path / "run_manifest.json")
        if not isinstance(manifest, Mapping):
            continue
        target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
        pkg = _norm_text(target.get("package_name")).lower()
        if packages and pkg not in packages:
            continue
        out.append(path)
    return out


def _display_name_from_dep(run_dir: Path, package_name: str) -> str:
    dep = _read_json(run_dir / "artifacts" / "dep" / "dep.json")
    if isinstance(dep, Mapping):
        display = _norm_text(dep.get("display_name") or dep.get("app_label"))
        if display:
            return display
    return package_name


def _safe_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _median(values: Sequence[int | float | None]) -> float | None:
    xs = sorted(float(v) for v in values if v is not None)
    if not xs:
        return None
    n = len(xs)
    mid = n // 2
    if n % 2 == 1:
        return float(xs[mid])
    return float((xs[mid - 1] + xs[mid]) / 2.0)


def _run_domain_set(row: RunRow) -> set[str]:
    return (
        {domain for domain, _count in row.top_dns}
        | {domain for domain, _count in row.top_sni}
        | {ip for ip, _count in row.top_ip_dst}
    )


def _top_values(report: Mapping[str, Any] | None, key: str) -> tuple[tuple[str, int], ...]:
    if not isinstance(report, Mapping):
        return ()
    items = report.get(key)
    if not isinstance(items, Sequence) or isinstance(items, (str, bytes, bytearray)):
        return ()
    out: list[tuple[str, int]] = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        value = _normalize_domain(item.get("value"))
        if not value:
            continue
        try:
            count = int(item.get("count") or 0)
        except (TypeError, ValueError):
            count = 0
        out.append((value, count))
    return tuple(out)


def _endpoint_host(value: object) -> str:
    text = _norm_text(value)
    if not text:
        return ""
    if text.startswith("[") and "]" in text:
        return text[1 : text.index("]")]
    if ":" in text and text.count(":") == 1:
        host, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            return host
    return text


def _top_ip_destinations(report: Mapping[str, Any] | None, *, package_name: str) -> tuple[tuple[str, int], ...]:
    if not isinstance(report, Mapping):
        return ()
    flow_summary = report.get("flow_summary")
    top_flows = flow_summary.get("top_flows") if isinstance(flow_summary, Mapping) else None
    if not isinstance(top_flows, Sequence) or isinstance(top_flows, (str, bytes, bytearray)):
        return ()
    out: dict[str, int] = {}
    for flow in top_flows:
        if not isinstance(flow, Mapping):
            continue
        for endpoint_key in ("endpoint_b", "endpoint_a"):
            ip_text = normalize_ip(_endpoint_host(flow.get(endpoint_key)))
            if not ip_text:
                continue
            ctx = _context_for_ip_destination(ip_text, package_name=package_name)
            if not ctx.get("first_party"):
                continue
            out[ip_text] = out.get(ip_text, 0) + int(_safe_int(flow.get("packets")) or 0)
            break
    return tuple(sorted(out.items()))


def _load_run_row(run_dir: Path) -> RunRow | None:
    manifest = _read_json(run_dir / "run_manifest.json")
    if not isinstance(manifest, Mapping):
        return None
    report = _read_json(run_dir / "analysis" / "pcap_report.json")
    overlap = _read_json(run_dir / "analysis" / "static_dynamic_overlap.json")
    target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
    dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), Mapping) else {}
    operator = manifest.get("operator") if isinstance(manifest.get("operator"), Mapping) else {}
    features = _read_json(run_dir / "analysis" / "pcap_features.json")
    proxies = features.get("proxies") if isinstance(features, Mapping) and isinstance(features.get("proxies"), Mapping) else {}
    package_name = _norm_text(target.get("package_name")).lower()
    if not package_name:
        return None
    return RunRow(
        run_dir_name=run_dir.name,
        run_id=_norm_text(manifest.get("dynamic_run_id") or manifest.get("run_id") or run_dir.name),
        package_name=package_name,
        display_name=_norm_text(target.get("display_name") or _display_name_from_dep(run_dir, package_name)),
        run_profile=_norm_text(dataset.get("run_profile") or operator.get("run_profile")),
        valid_dataset_run=dataset.get("valid_dataset_run") if isinstance(dataset.get("valid_dataset_run"), bool) else None,
        paper_eligible=dataset.get("paper_eligible") if isinstance(dataset.get("paper_eligible"), bool) else None,
        countable=dataset.get("countable") if isinstance(dataset.get("countable"), bool) else None,
        ended_at=_norm_text_or_none(manifest.get("ended_at")),
        sampling_seconds=_safe_float(dataset.get("actual_sampling_seconds") or dataset.get("sampling_duration_seconds")),
        pcap_bytes=_safe_int(report.get("pcap_size_bytes") if isinstance(report, Mapping) else None) or _safe_int(report.get("bytes_total") if isinstance(report, Mapping) else None) or _safe_int(report.get("data_bytes_total") if isinstance(report, Mapping) else None),
        packet_count=_safe_int(report.get("packet_count") if isinstance(report, Mapping) else None) or _safe_int(report.get("packets_total") if isinstance(report, Mapping) else None),
        unique_dns_count=_safe_int(report.get("dns_unique_count") if isinstance(report, Mapping) else None),
        unique_sni_count=_safe_int(report.get("sni_unique_count") if isinstance(report, Mapping) else None),
        domains_per_min=_safe_float(proxies.get("domains_per_min") if isinstance(proxies, Mapping) else None),
        top_dns=_top_values(report, "top_dns"),
        top_sni=_top_values(report, "top_sni"),
        top_ip_dst=_top_ip_destinations(report, package_name=package_name),
        static_domains_count=int(overlap.get("static_domains_count")) if isinstance(overlap, Mapping) and overlap.get("static_domains_count") is not None else None,
        dynamic_domains_count=int(overlap.get("dynamic_domains_count")) if isinstance(overlap, Mapping) and overlap.get("dynamic_domains_count") is not None else None,
    )


def _load_state_rows(packages: set[str]) -> dict[str, dict[str, Any]]:
    from scytaledroid.DynamicAnalysis.services.dataset_run_state import load_dataset_run_state

    out: dict[str, dict[str, Any]] = {}
    for package_name in sorted(packages):
        state = load_dataset_run_state(package_name)
        counts = state.counts
        out[package_name] = {
            "quota_counted_local": int(state.quota_counted_local),
            "paper_eligible_local": int(state.paper_eligible_local),
            "baseline_valid_runs": int(counts.baseline_valid_runs),
            "interactive_valid_runs": int(counts.interactive_valid_runs),
            "extra_valid_runs": int(counts.extra_valid_runs),
            "quota_met": bool(counts.quota_met),
            "suggested_profile": _norm_text_or_none(state.effective_suggested_profile),
            "suggested_slot": int(state.suggested_slot) if state.suggested_slot is not None else None,
        }
    return out


def _package_run_rows(rows: Sequence[RunRow], *, state_rows: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[RunRow]] = defaultdict(list)
    for row in rows:
        grouped[row.package_name].append(row)

    out: list[dict[str, Any]] = []
    for package_name in sorted(grouped):
        pkg_rows = grouped[package_name]
        latest_row = max(
            pkg_rows,
            key=lambda row: (
                _norm_text(row.ended_at),
                _norm_text(row.run_id),
                _norm_text(row.run_dir_name),
            ),
        )
        baseline_runs = sum(1 for row in pkg_rows if row.run_profile.startswith("baseline"))
        manual_runs = sum(1 for row in pkg_rows if row.run_profile == "interaction_manual")
        valid_runs = sum(1 for row in pkg_rows if row.valid_dataset_run is True)
        paper_runs = sum(1 for row in pkg_rows if row.paper_eligible is True)
        overlap_gap = any(
            (row.static_domains_count == 0 or row.static_domains_count is None)
            and (row.dynamic_domains_count or 0) > 0
            for row in pkg_rows
        )
        state = dict(state_rows.get(package_name) or {})
        out.append(
            {
                "package_name": package_name,
                "display_name": next((row.display_name for row in pkg_rows if row.display_name), package_name),
                "runs_total": len(pkg_rows),
                "baseline_runs": baseline_runs,
                "manual_runs": manual_runs,
                "valid_runs": valid_runs,
                "paper_eligible_runs": paper_runs,
                "quota_counted_local": state.get("quota_counted_local"),
                "paper_eligible_local": state.get("paper_eligible_local"),
                "extra_valid_runs": state.get("extra_valid_runs"),
                "quota_met": state.get("quota_met"),
                "suggested_profile": state.get("suggested_profile"),
                "static_dynamic_domain_gap": overlap_gap,
                "latest_run_id": latest_row.run_id,
                "latest_ended_at": latest_row.ended_at,
            }
        )
    return out


def _domain_rows(rows: Sequence[RunRow]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    package_run_counts = Counter(row.package_name for row in rows)
    for row in rows:
        for source_key, entries in (("dns", row.top_dns), ("sni", row.top_sni), ("ip_dst", row.top_ip_dst)):
            for domain, count in entries:
                key = (row.package_name, domain)
                slot = grouped.setdefault(
                    key,
                    {
                        "package_name": row.package_name,
                        "display_name": row.display_name,
                        "domain": domain,
                        "dns_hits": 0,
                        "sni_hits": 0,
                        "ip_hits": 0,
                        "total_hits": 0,
                        "runs_seen": set(),
                        "profiles_seen": set(),
                    },
                )
                slot["total_hits"] += int(count)
                slot["runs_seen"].add(row.run_id)
                slot["profiles_seen"].add(row.run_profile)
                if source_key == "dns":
                    slot["dns_hits"] += int(count)
                elif source_key == "sni":
                    slot["sni_hits"] += int(count)
                else:
                    slot["ip_hits"] += int(count)

    out: list[dict[str, Any]] = []
    for (package_name, domain), row in sorted(grouped.items()):
        ip_ctx = _context_for_ip_destination(domain, package_name=package_name)
        ctx = ip_ctx if ip_ctx.get("first_party") else _context_for_domain(domain, package_name=package_name)
        root_value = ctx.get("root_domain") or ctx.get("cidr") or ctx.get("ip") or domain
        runs_seen = sorted(str(value) for value in row["runs_seen"])
        profiles_seen = sorted(str(value) for value in row["profiles_seen"] if _norm_text(value))
        total_pkg_runs = int(package_run_counts.get(package_name, 0))
        observed_runs = len(runs_seen)
        out.append(
            {
                "package_name": package_name,
                "display_name": row["display_name"],
                "domain": domain,
                "root_domain": root_value,
                "owner_class": ctx["owner_class"],
                "role_class": ctx["role_class"],
                "confidence": ctx["confidence"],
                "basis": ctx["basis"],
                "first_party": int(bool(ctx["first_party"])),
                "dns_hits": int(row["dns_hits"]),
                "sni_hits": int(row["sni_hits"]),
                "ip_hits": int(row["ip_hits"]),
                "total_hits": int(row["total_hits"]),
                "observed_run_count": observed_runs,
                "package_run_count": total_pkg_runs,
                "observed_run_ratio": round((observed_runs / total_pkg_runs), 4) if total_pkg_runs > 0 else None,
                "stability_bucket": (
                    "stable"
                    if total_pkg_runs > 0 and observed_runs == total_pkg_runs
                    else "recurring"
                    if total_pkg_runs > 0 and observed_runs >= max(2, (total_pkg_runs + 1) // 2)
                    else "sporadic"
                ),
                "profiles_seen": ",".join(profiles_seen),
                "runs_seen": ",".join(runs_seen),
            }
        )
    return out


def _gap_rows(package_rows: Sequence[Mapping[str, Any]], domain_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    unknown_counts: Counter[str] = Counter()
    third_party_counts: Counter[str] = Counter()
    for row in domain_rows:
        package_name = _norm_text(row.get("package_name")).lower()
        if row.get("owner_class") == "unknown":
            unknown_counts[package_name] += 1
        if row.get("owner_class") == "third_party":
            third_party_counts[package_name] += 1
    out: list[dict[str, Any]] = []
    for row in package_rows:
        package_name = _norm_text(row.get("package_name")).lower()
        notes: list[str] = []
        if int(row.get("manual_runs") or 0) == 0:
            notes.append("manual_runs_missing")
        if bool(row.get("static_dynamic_domain_gap")):
            notes.append("runtime_domains_exceed_static_domain_context")
        if int(unknown_counts.get(package_name, 0)) > 0:
            notes.append(f"unknown_domains={int(unknown_counts[package_name])}")
        out.append(
            {
                "package_name": package_name,
                "display_name": row.get("display_name"),
                "needs_context": int(bool(notes)),
                "unknown_domain_count": int(unknown_counts.get(package_name, 0)),
                "third_party_domain_count": int(third_party_counts.get(package_name, 0)),
                "notes": ";".join(notes),
            }
        )
    return out


def _profile_contrast_rows(rows: Sequence[RunRow]) -> list[dict[str, Any]]:
    grouped: dict[str, list[RunRow]] = defaultdict(list)
    for row in rows:
        grouped[row.package_name].append(row)

    out: list[dict[str, Any]] = []
    for package_name in sorted(grouped):
        pkg_rows = grouped[package_name]
        baseline_rows = [row for row in pkg_rows if row.run_profile.startswith("baseline")]
        manual_rows = [row for row in pkg_rows if row.run_profile == "interaction_manual"]
        baseline_domain_union = set().union(*(_run_domain_set(row) for row in baseline_rows)) if baseline_rows else set()
        manual_domain_union = set().union(*(_run_domain_set(row) for row in manual_rows)) if manual_rows else set()
        manual_only = sorted(manual_domain_union - baseline_domain_union)
        baseline_only = sorted(baseline_domain_union - manual_domain_union)
        shared = sorted(baseline_domain_union & manual_domain_union)
        out.append(
            {
                "package_name": package_name,
                "display_name": next((row.display_name for row in pkg_rows if row.display_name), package_name),
                "baseline_run_count": len(baseline_rows),
                "manual_run_count": len(manual_rows),
                "baseline_bytes_median": _median([row.pcap_bytes for row in baseline_rows]),
                "manual_bytes_median": _median([row.pcap_bytes for row in manual_rows]),
                "baseline_packets_median": _median([row.packet_count for row in baseline_rows]),
                "manual_packets_median": _median([row.packet_count for row in manual_rows]),
                "baseline_dns_unique_median": _median([row.unique_dns_count for row in baseline_rows]),
                "manual_dns_unique_median": _median([row.unique_dns_count for row in manual_rows]),
                "baseline_sni_unique_median": _median([row.unique_sni_count for row in baseline_rows]),
                "manual_sni_unique_median": _median([row.unique_sni_count for row in manual_rows]),
                "baseline_domains_per_min_median": _median([row.domains_per_min for row in baseline_rows]),
                "manual_domains_per_min_median": _median([row.domains_per_min for row in manual_rows]),
                "baseline_domain_union_count": len(baseline_domain_union),
                "manual_domain_union_count": len(manual_domain_union),
                "shared_domain_count": len(shared),
                "manual_only_domain_count": len(manual_only),
                "baseline_only_domain_count": len(baseline_only),
                "manual_only_domains_top10": ",".join(manual_only[:10]),
                "baseline_only_domains_top10": ",".join(baseline_only[:10]),
                "shared_domains_top10": ",".join(shared[:10]),
            }
        )
    return out


def _summary(
    run_rows: Sequence[RunRow],
    package_rows: Sequence[Mapping[str, Any]],
    domain_rows: Sequence[Mapping[str, Any]],
    gap_rows: Sequence[Mapping[str, Any]],
    contrast_rows: Sequence[Mapping[str, Any]],
    *,
    output_dir: Path,
) -> dict[str, Any]:
    role_counts = Counter(_norm_text(row.get("role_class")) for row in domain_rows)
    owner_counts = Counter(_norm_text(row.get("owner_class")) for row in domain_rows)
    basis_counts = Counter(_norm_text(row.get("basis")) for row in domain_rows)
    stability_counts = Counter(_norm_text(row.get("stability_bucket")) for row in domain_rows)
    return {
        "generated_at": _utcnow_iso(),
        "repo_root": str(_REPO_ROOT),
        "dynamic_evidence_root": str(_dynamic_root()),
        "dynamic_runs_scanned": len(run_rows),
        "packages_scanned": len(package_rows),
        "packages_with_manual_runs": sum(1 for row in package_rows if int(row.get("manual_runs") or 0) > 0),
        "packages_with_quota_met": sum(1 for row in package_rows if bool(row.get("quota_met"))),
        "packages_with_context_gaps": sum(1 for row in gap_rows if int(row.get("needs_context") or 0) > 0),
        "packages_with_baseline_manual_contrast": sum(1 for row in contrast_rows if int(row.get("baseline_run_count") or 0) > 0 and int(row.get("manual_run_count") or 0) > 0),
        "observed_domains_total": len(domain_rows),
        "owner_class_counts": dict(sorted(owner_counts.items())),
        "role_class_counts": dict(sorted(role_counts.items())),
        "classification_basis_counts": dict(sorted(basis_counts.items())),
        "stability_bucket_counts": dict(sorted(stability_counts.items())),
        "output_files": {
            "package_run_overview_csv": str(output_dir / "package_run_overview.csv"),
            "package_domain_context_csv": str(output_dir / "package_domain_context.csv"),
            "package_context_gaps_csv": str(output_dir / "package_context_gaps.csv"),
            "package_profile_contrast_csv": str(output_dir / "package_profile_contrast.csv"),
            "run_inventory_csv": str(output_dir / "run_inventory.csv"),
            "summary_json": str(output_dir / "summary.json"),
        },
        "assumptions": [
            "filesystem_first_inputs",
            "pcap_report_top_dns_top_sni_plus_curated_direct_ip_context",
            "curated_exact_and_suffix_classification",
            "package_root_first_party_hints_are_advisory",
        ],
        "no_db_writes": True,
        "experimental_audit": True,
    }


def generate_dynamic_domain_context_report(
    *,
    packages: Sequence[str] | None = None,
    output_dir: Path | None = None,
    verbose: bool = False,
) -> dict[str, Any]:
    package_set = {_norm_text(value).lower() for value in (packages or []) if _norm_text(value)}
    run_dirs = _iter_run_dirs(packages=package_set)
    _log(verbose, f"run_dirs={len(run_dirs)}")
    run_rows = [row for path in run_dirs if (row := _load_run_row(path)) is not None]
    observed_packages = {row.package_name for row in run_rows}
    state_rows = _load_state_rows(observed_packages) if observed_packages else {}
    package_rows = _package_run_rows(run_rows, state_rows=state_rows)
    domain_rows = _domain_rows(run_rows)
    gap_rows = _gap_rows(package_rows, domain_rows)
    contrast_rows = _profile_contrast_rows(run_rows)

    out_dir = output_dir or (_REPO_ROOT / "output" / "audit" / "dynamic_domain_context" / datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S"))
    out_dir.mkdir(parents=True, exist_ok=True)

    _write_csv(
        out_dir / "run_inventory.csv",
        [
            {
                "run_dir_name": row.run_dir_name,
                "run_id": row.run_id,
                "package_name": row.package_name,
                "display_name": row.display_name,
                "run_profile": row.run_profile,
                "valid_dataset_run": row.valid_dataset_run,
                "paper_eligible": row.paper_eligible,
                "countable": row.countable,
                "ended_at": row.ended_at,
                "top_dns_1": row.top_dns[0][0] if row.top_dns else None,
                "top_sni_1": row.top_sni[0][0] if row.top_sni else None,
                "static_domains_count": row.static_domains_count,
                "dynamic_domains_count": row.dynamic_domains_count,
            }
            for row in run_rows
        ],
    )
    _write_csv(out_dir / "package_run_overview.csv", package_rows)
    _write_csv(out_dir / "package_domain_context.csv", domain_rows)
    _write_csv(out_dir / "package_context_gaps.csv", gap_rows)
    _write_csv(out_dir / "package_profile_contrast.csv", contrast_rows)
    summary = _summary(run_rows, package_rows, domain_rows, gap_rows, contrast_rows, output_dir=out_dir)
    _write_json(out_dir / "summary.json", summary)
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    summary = generate_dynamic_domain_context_report(
        packages=args.package,
        output_dir=output_dir,
        verbose=bool(args.verbose),
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
