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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scytaledroid.StaticAnalysis.modules.string_analysis.parsing.host_normalizer import (
    registrable_domain,
)


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
    plan_source: str = "embedded"
    overlay_static_report_path: str | None = None
    host_exact_corroborated_domains: int = 0
    root_corroborated_domains: int = 0
    actionable_host_exact_corroborated_domains: int = 0
    actionable_root_corroborated_domains: int = 0
    weak_generic_corroborations: int = 0
    static_only_domains: int = 0
    dynamic_only_domains: int = 0


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
    parser.add_argument(
        "--package",
        dest="package_name",
        default=None,
        help="Only scan dynamic evidence packs for this package name.",
    )
    parser.add_argument(
        "--overlay-latest-static",
        action="store_true",
        help=(
            "Read-only reanalysis mode: synthesize a temporary static plan from the latest "
            "matching stored static report instead of relying only on the embedded dynamic evidence plan."
        ),
    )
    parser.add_argument(
        "--overlay-reanalyse-strings",
        action="store_true",
        help=(
            "Read-only overlay refinement: rebuild a temporary string payload from the latest "
            "matching static report APK path before synthesizing the overlay plan. Implies "
            "--overlay-latest-static and does not mutate stored reports or dynamic evidence packs."
        ),
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


def _write_csv(
    path: Path,
    rows: Sequence[Mapping[str, Any]],
    *,
    fieldnames: Sequence[str] | None = None,
) -> None:
    row_list = list(rows)
    resolved_fieldnames: list[str] = [str(key) for key in (fieldnames or ())]
    for row in row_list:
        for key in row.keys():
            if key not in resolved_fieldnames:
                resolved_fieldnames.append(str(key))
    if not resolved_fieldnames:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=resolved_fieldnames)
        writer.writeheader()
        for row in row_list:
            writer.writerow({key: row.get(key) for key in resolved_fieldnames})


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


def _run_dir_package_name(run_dir: Path) -> str | None:
    manifest = _read_json(run_dir / "run_manifest.json")
    if not isinstance(manifest, Mapping):
        return None
    target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
    package_name = _norm_text_or_none(target.get("package_name"))
    return package_name.lower() if package_name else None


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
                root_domain = registrable_domain(domain)
                if root_domain:
                    domains.add(root_domain)
    return domains


def _dynamic_observations_from_report(report: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    observations: dict[str, dict[str, Any]] = {}
    if not isinstance(report, Mapping):
        return []
    for key in ("top_dns", "top_sni"):
        rows = report.get(key)
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
            continue
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            host = _normalize_domain(row.get("value"))
            if not host:
                continue
            root = registrable_domain(host) or host
            try:
                count = int(row.get("count") or 0)
            except (TypeError, ValueError):
                count = 0
            bucket = observations.setdefault(
                host,
                {
                    "dynamic_host": host,
                    "dynamic_root_domain": root,
                    "total_hits": 0,
                    "indicator_sources": set(),
                },
            )
            bucket["total_hits"] = int(bucket.get("total_hits") or 0) + max(count, 0)
            bucket["indicator_sources"].add(key)
    out: list[dict[str, Any]] = []
    for row in observations.values():
        out.append(
            {
                "dynamic_host": row["dynamic_host"],
                "dynamic_root_domain": row["dynamic_root_domain"],
                "total_hits": int(row.get("total_hits") or 0),
                "indicator_sources": sorted(row.get("indicator_sources") or []),
            }
        )
    out.sort(key=lambda item: (-int(item.get("total_hits") or 0), str(item.get("dynamic_host") or "")))
    return out


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


def _identity_map(plan: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if not isinstance(plan, Mapping):
        return {}
    identity = plan.get("run_identity")
    return identity if isinstance(identity, Mapping) else {}


_OVERLAY_REPORT_CACHE: dict[str, tuple[object, ...]] = {}


def _select_overlay_report(
    package_name: str | None,
    *,
    embedded_plan: Mapping[str, Any] | None,
) -> tuple[object | None, str | None]:
    package_norm = _norm_text_or_none(package_name)
    if not package_norm:
        return None, None

    from scytaledroid.StaticAnalysis.persistence.reports import reports_for_package

    cache_key = package_norm.lower()
    stored_reports = _OVERLAY_REPORT_CACHE.get(cache_key)
    if stored_reports is None:
        stored_reports = tuple(reports_for_package(package_norm))
        _OVERLAY_REPORT_CACHE[cache_key] = stored_reports
    if not stored_reports:
        return None, None

    identity = _identity_map(embedded_plan)
    target_base_sha = _norm_text_or_none(identity.get("base_apk_sha256"))
    target_artifact_hash = _norm_text_or_none(identity.get("artifact_set_hash"))
    target_run_signature = _norm_text_or_none(identity.get("run_signature"))

    def _match(report_obj: object) -> tuple[int, int, int]:
        metadata = getattr(report_obj, "metadata", None)
        metadata = metadata if isinstance(metadata, Mapping) else {}
        score_base = int(
            bool(target_base_sha and _norm_text_or_none(metadata.get("base_apk_sha256")) == target_base_sha)
        )
        score_artifact = int(
            bool(target_artifact_hash and _norm_text_or_none(metadata.get("artifact_set_hash")) == target_artifact_hash)
        )
        score_signature = int(
            bool(target_run_signature and _norm_text_or_none(metadata.get("run_signature")) == target_run_signature)
        )
        return score_base, score_artifact, score_signature

    best = stored_reports[0]
    best_score = _match(best.report)
    for candidate in stored_reports[1:]:
        candidate_score = _match(candidate.report)
        if candidate_score > best_score:
            best = candidate
            best_score = candidate_score

    return best, _repo_rel(best.path)


_OVERLAY_PLAN_CACHE: dict[tuple[str, bool, int | None], tuple[dict[str, Any] | None, str | None, str]] = {}


def _reanalyse_string_payload_from_report(
    report_obj: object,
    *,
    package_name: str | None,
) -> Mapping[str, Any] | None:
    from scytaledroid.StaticAnalysis.engine.strings import analyse_strings

    metadata = getattr(report_obj, "metadata", None)
    metadata = metadata if isinstance(metadata, Mapping) else {}
    apk_path_value = _norm_text_or_none(metadata.get("apk_path")) or _norm_text_or_none(
        getattr(report_obj, "file_path", None)
    )
    if not apk_path_value:
        return None
    apk_path = Path(apk_path_value)
    if not apk_path.exists():
        return None
    payload = analyse_strings(
        str(apk_path),
        artifact_context={"package_name": package_name} if package_name else None,
    )
    return payload if isinstance(payload, Mapping) else None


def _overlay_plan_from_static_report(
    package_name: str | None,
    *,
    embedded_plan: Mapping[str, Any] | None,
    static_run_id: int | None,
    reanalyse_strings: bool = False,
) -> tuple[dict[str, Any] | None, str | None, str]:
    stored, rel_path = _select_overlay_report(package_name, embedded_plan=embedded_plan)
    if stored is None:
        return None, None, "embedded"

    cache_key = (str(stored.path), bool(reanalyse_strings), static_run_id)
    cached = _OVERLAY_PLAN_CACHE.get(cache_key)
    if cached is not None:
        return cached

    from scytaledroid.StaticAnalysis.cli.views.renderers.dynamic_plan import build_dynamic_plan
    from scytaledroid.StaticAnalysis.cli.views.renderers.summary_render import render_app_result

    report_obj = stored.report
    metadata = getattr(report_obj, "metadata", None)
    metadata = metadata if isinstance(metadata, Mapping) else {}
    string_payload = (
        _reanalyse_string_payload_from_report(report_obj, package_name=package_name)
        if reanalyse_strings
        else metadata.get("post_run_string_payload")
    )
    if not isinstance(string_payload, Mapping):
        fallback_payload = metadata.get("post_run_string_payload")
        if not isinstance(fallback_payload, Mapping):
            result = (None, rel_path, "embedded")
            _OVERLAY_PLAN_CACHE[cache_key] = result
            return result
        string_payload = fallback_payload
        reanalyse_strings = False

    _lines, payload, _totals = render_app_result(
        report_obj,
        signer=None,
        split_count=1,
        string_data=string_payload,
        duration_seconds=0.0,
    )
    plan = build_dynamic_plan(
        report_obj,
        payload,
        static_run_id=static_run_id,
        schema_version=_norm_text_or_none(metadata.get("schema_version")),
    )
    if (
        reanalyse_strings
        and not _domain_sources(plan)
        and _domain_sources(embedded_plan)
        and not isinstance(metadata.get("post_run_string_payload"), Mapping)
    ):
        result = (None, rel_path, "embedded")
        _OVERLAY_PLAN_CACHE[cache_key] = result
        return result
    source = "overlay_string_reanalysis" if reanalyse_strings else "overlay_latest_static"
    result = (dict(plan), rel_path, source)
    _OVERLAY_PLAN_CACHE[cache_key] = result
    return result


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


def _service_context_bundle(
    report: Mapping[str, Any] | None,
    *,
    package_name: str | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(report, Mapping):
        return [], []
    try:
        from scytaledroid.DynamicAnalysis.pcap.context_summary import summarize_pcap_service_context
    except Exception:
        return [], []
    bundle = summarize_pcap_service_context(report, package_name=str(package_name or ""))
    service_context = bundle.get("service_context") if isinstance(bundle, Mapping) else {}
    service_signals = bundle.get("service_signals") if isinstance(bundle, Mapping) else {}
    service_rows = [dict(row) for row in (service_context.get("services") or []) if isinstance(row, Mapping)]
    signal_rows = [dict(row) for row in (service_signals.get("signals") or []) if isinstance(row, Mapping)]
    return service_rows, signal_rows


def _service_rows_for_static_domain(
    static_domain: str,
    service_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    matched: list[dict[str, Any]] = []
    for row in service_rows:
        domains = row.get("domains") if isinstance(row.get("domains"), Sequence) else []
        for item in domains:
            if not isinstance(item, Mapping):
                continue
            observed = _normalize_domain(item.get("domain"))
            observed_root = _normalize_domain(item.get("root_domain")) or (registrable_domain(observed) or observed)
            if static_domain and (observed == static_domain or observed_root == static_domain):
                matched.append(dict(row))
                break
    return matched


def _signal_keys_for_service_rows(
    service_rows: Sequence[Mapping[str, Any]],
    signal_rows: Sequence[Mapping[str, Any]],
) -> list[str]:
    service_keys = {
        _norm_text(row.get("service_key"))
        for row in service_rows
        if _norm_text(row.get("service_key"))
    }
    signal_keys: list[str] = []
    for row in signal_rows:
        services = row.get("services") if isinstance(row.get("services"), Sequence) else []
        for item in services:
            if not isinstance(item, Mapping):
                continue
            if _norm_text(item.get("service_key")) in service_keys:
                key = _norm_text(row.get("signal_key"))
                if key and key not in signal_keys:
                    signal_keys.append(key)
                break
    return sorted(signal_keys)


def _is_generic_infrastructure_match(
    *,
    static_domain: str,
    static_ownerships: set[str],
    service_rows: Sequence[Mapping[str, Any]],
) -> bool:
    if static_ownerships & {"cdn", "cloud_storage", "documentary", "generic_platform", "platform"}:
        return True
    generic_domains = {
        "doubleclick.net",
        "googlesyndication.com",
        "googletagservices.com",
        "googleapis.com",
        "gstatic.com",
        "appsflyersdk.com",
        "urbanairship.com",
        "chartbeat.net",
        "scorecardresearch.com",
        "permutive.app",
        "admaster.cc",
        "optimizely.com",
    }
    if static_domain in generic_domains:
        return True
    for row in service_rows:
        owner_class = _norm_text(row.get("owner_class")).lower()
        service_category = _norm_text(row.get("service_category")).lower()
        service_key = _norm_text(row.get("service_key")).lower()
        if owner_class in {"platform", "third_party"} and service_category in {
            "adtech",
            "analytics",
            "cdn",
            "measurement",
            "platform",
            "infrastructure",
        }:
            return True
        if service_key.startswith(("google_", "meta_", "microsoft_", "adobe_", "urbanairship_")):
            return True
    return False


def _match_classification(
    *,
    static_domain: str,
    parsed: Mapping[str, set[str]],
    matched_observations: Sequence[Mapping[str, Any]],
    matched_service_rows: Sequence[Mapping[str, Any]],
) -> tuple[str, str, str]:
    host_exact = any(_norm_text(item.get("dynamic_host")) == static_domain for item in matched_observations)
    root_match = any(_norm_text(item.get("dynamic_root_domain")) == static_domain for item in matched_observations)
    service_context_match = bool(matched_service_rows)
    static_ownerships = parsed.get("ownership_classes") or set()
    postures = parsed.get("postures") or set()
    first_party = any(_norm_text(row.get("owner_class")).lower() == "first_party" for row in matched_service_rows)
    generic = _is_generic_infrastructure_match(
        static_domain=static_domain,
        static_ownerships=static_ownerships,
        service_rows=matched_service_rows,
    )
    if host_exact and not generic:
        strength = "strong" if ("actionable" in postures or first_party) else "medium"
        return "host_exact_match", strength, "Static domain exactly observed in runtime host indicators."
    if root_match and not generic:
        strength = "strong" if ("actionable" in postures and first_party) else "medium"
        return "root_domain_match", strength, "Static root domain matched observed runtime subdomain(s)."
    if service_context_match and not generic:
        strength = "medium" if ("actionable" in postures or first_party) else "weak"
        return "service_context_match", strength, "Static domain aligned with resolved dynamic service context."
    if host_exact or root_match or service_context_match:
        strength = "noisy" if static_ownerships & {"documentary"} else "weak"
        return "weak_generic_match", strength, "Overlap is present but appears to be generic infrastructure or third-party platform traffic."
    return "static_only", "weak", "Static domain was not observed in the current dynamic top DNS/SNI indicators."


def _detail_rows_for_run(
    *,
    row: CorroborationRow,
    plan: Mapping[str, Any] | None,
    report: Mapping[str, Any] | None,
    package_name: str | None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    dynamic_observations = _dynamic_observations_from_report(report)
    service_rows, signal_rows = _service_context_bundle(report, package_name=package_name)
    detail_rows: list[dict[str, Any]] = []
    matched_dynamic_hosts: set[str] = set()
    counts = {
        "host_exact_corroborated_domains": 0,
        "root_corroborated_domains": 0,
        "actionable_host_exact_corroborated_domains": 0,
        "actionable_root_corroborated_domains": 0,
        "weak_generic_corroborations": 0,
        "static_only_domains": 0,
        "dynamic_only_domains": 0,
    }

    for domain_row in _domain_sources(plan):
        static_domain = _normalize_domain(domain_row.get("domain"))
        if not static_domain:
            continue
        parsed = _row_to_sets(domain_row)
        matched_observations = [
            obs
            for obs in dynamic_observations
            if _norm_text(obs.get("dynamic_host")) == static_domain
            or _norm_text(obs.get("dynamic_root_domain")) == static_domain
        ]
        for obs in matched_observations:
            matched_dynamic_hosts.add(_norm_text(obs.get("dynamic_host")))
        matched_service_rows = _service_rows_for_static_domain(static_domain, service_rows)
        signal_keys = _signal_keys_for_service_rows(matched_service_rows, signal_rows)
        match_type, strength, explanation = _match_classification(
            static_domain=static_domain,
            parsed=parsed,
            matched_observations=matched_observations,
            matched_service_rows=matched_service_rows,
        )
        host_exact = any(_norm_text(item.get("dynamic_host")) == static_domain for item in matched_observations)
        root_match = any(_norm_text(item.get("dynamic_root_domain")) == static_domain for item in matched_observations)
        if host_exact:
            counts["host_exact_corroborated_domains"] += 1
        if root_match:
            counts["root_corroborated_domains"] += 1
        if "actionable" in (parsed.get("postures") or set()) and host_exact:
            counts["actionable_host_exact_corroborated_domains"] += 1
        if "actionable" in (parsed.get("postures") or set()) and root_match:
            counts["actionable_root_corroborated_domains"] += 1
        if match_type == "weak_generic_match":
            counts["weak_generic_corroborations"] += 1
        if match_type == "static_only":
            counts["static_only_domains"] += 1
        service_keys = sorted(
            {
                _norm_text(service_row.get("service_key"))
                for service_row in matched_service_rows
                if _norm_text(service_row.get("service_key"))
            }
        )
        owner_classes = sorted(
            {
                _norm_text(service_row.get("owner_class"))
                for service_row in matched_service_rows
                if _norm_text(service_row.get("owner_class"))
            }
        )
        detail_rows.append(
            {
                "dynamic_run_id": row.dynamic_run_id,
                "package_name": row.package_name,
                "static_run_id": row.static_run_id,
                "plan_source": row.plan_source,
                "corroboration_match_type": match_type,
                "corroboration_strength": strength,
                "static_domain": static_domain,
                "dynamic_host": ";".join(_norm_text(item.get("dynamic_host")) for item in matched_observations if _norm_text(item.get("dynamic_host"))),
                "dynamic_root_domain": ";".join(sorted({_norm_text(item.get("dynamic_root_domain")) for item in matched_observations if _norm_text(item.get("dynamic_root_domain"))})),
                "host_level_exact_match": int(host_exact),
                "root_domain_match": int(root_match),
                "service_context_match": int(bool(matched_service_rows)),
                "static_bucket": ";".join(sorted(parsed.get("buckets") or set())),
                "static_posture": ";".join(sorted(parsed.get("postures") or set())),
                "static_ownership_class": ";".join(sorted(parsed.get("ownership_classes") or set())),
                "static_api_context": ";".join(sorted(parsed.get("api_contexts") or set())),
                "static_pair_group": ";".join(sorted(parsed.get("pair_groups") or set())),
                "dynamic_service_key": ";".join(service_keys),
                "dynamic_signal_key": ";".join(signal_keys),
                "dynamic_owner_class": ";".join(owner_classes),
                "dynamic_source": ";".join(sorted({src for item in matched_observations for src in (item.get("indicator_sources") or []) if _norm_text(src)})),
                "is_first_party_match": int("first_party" in {owner.lower() for owner in owner_classes}),
                "is_third_party_match": int("third_party" in {owner.lower() for owner in owner_classes}),
                "is_generic_infrastructure_match": int(match_type == "weak_generic_match"),
                "is_actionable_match": int("actionable" in (parsed.get("postures") or set()) and match_type != "static_only"),
                "match_explanation": explanation,
            }
        )

    static_domains = {
        _normalize_domain(domain_row.get("domain"))
        for domain_row in _domain_sources(plan)
        if _normalize_domain(domain_row.get("domain"))
    }
    for observation in dynamic_observations:
        dynamic_host = _norm_text(observation.get("dynamic_host"))
        dynamic_root = _norm_text(observation.get("dynamic_root_domain"))
        if dynamic_host in matched_dynamic_hosts or dynamic_root in static_domains:
            continue
        counts["dynamic_only_domains"] += 1
        matched_service_rows = _service_rows_for_static_domain(dynamic_root, service_rows)
        signal_keys = _signal_keys_for_service_rows(matched_service_rows, signal_rows)
        owner_classes = sorted(
            {
                _norm_text(service_row.get("owner_class"))
                for service_row in matched_service_rows
                if _norm_text(service_row.get("owner_class"))
            }
        )
        detail_rows.append(
            {
                "dynamic_run_id": row.dynamic_run_id,
                "package_name": row.package_name,
                "static_run_id": row.static_run_id,
                "plan_source": row.plan_source,
                "corroboration_match_type": "dynamic_only",
                "corroboration_strength": "weak",
                "static_domain": "",
                "dynamic_host": dynamic_host,
                "dynamic_root_domain": dynamic_root,
                "host_level_exact_match": 0,
                "root_domain_match": 0,
                "service_context_match": int(bool(matched_service_rows)),
                "static_bucket": "",
                "static_posture": "",
                "static_ownership_class": "",
                "static_api_context": "",
                "static_pair_group": "",
                "dynamic_service_key": ";".join(
                    sorted(
                        {
                            _norm_text(service_row.get("service_key"))
                            for service_row in matched_service_rows
                            if _norm_text(service_row.get("service_key"))
                        }
                    )
                ),
                "dynamic_signal_key": ";".join(signal_keys),
                "dynamic_owner_class": ";".join(owner_classes),
                "dynamic_source": ";".join(observation.get("indicator_sources") or []),
                "is_first_party_match": int("first_party" in {owner.lower() for owner in owner_classes}),
                "is_third_party_match": int("third_party" in {owner.lower() for owner in owner_classes}),
                "is_generic_infrastructure_match": int(_is_generic_infrastructure_match(static_domain=dynamic_root, static_ownerships=set(), service_rows=matched_service_rows)),
                "is_actionable_match": 0,
                "match_explanation": "Dynamic observed domain/root was not present in the current static domain inventory.",
            }
        )
    return detail_rows, counts


def _detail_rows_for_run_dir(
    run_dir: Path,
    row: CorroborationRow,
    *,
    overlay_latest_static: bool = False,
    overlay_reanalyse_strings: bool = False,
) -> list[dict[str, Any]]:
    manifest = _read_json(run_dir / "run_manifest.json") or {}
    report = _read_json(run_dir / "analysis" / "pcap_report.json")
    embedded_plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json")
    target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
    package_name = _norm_text_or_none(target.get("package_name"))
    static_run_id = _safe_int(target.get("static_run_id") or _identity_map(embedded_plan).get("static_run_id"))
    plan = embedded_plan
    if overlay_latest_static or overlay_reanalyse_strings:
        overlaid_plan, _path, _source = _overlay_plan_from_static_report(
            package_name,
            embedded_plan=embedded_plan,
            static_run_id=static_run_id,
            reanalyse_strings=bool(overlay_reanalyse_strings),
        )
        if isinstance(overlaid_plan, Mapping):
            plan = overlaid_plan
    detail_rows, _counts = _detail_rows_for_run(
        row=row,
        plan=plan,
        report=report,
        package_name=package_name,
    )
    return detail_rows


def _corroboration_row(
    run_dir: Path,
    *,
    overlay_latest_static: bool = False,
    overlay_reanalyse_strings: bool = False,
) -> CorroborationRow | None:
    manifest = _read_json(run_dir / "run_manifest.json")
    if not isinstance(manifest, Mapping):
        return None
    plan_path = run_dir / "inputs" / "static_dynamic_plan.json"
    report_path = run_dir / "analysis" / "pcap_report.json"
    overlap_path = run_dir / "analysis" / "static_dynamic_overlap.json"
    embedded_plan = _read_json(plan_path)
    report = _read_json(report_path)
    target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
    identity = _identity_map(embedded_plan)
    static_run_id = _safe_int(target.get("static_run_id") or identity.get("static_run_id"))
    package_name = _norm_text_or_none(target.get("package_name"))

    plan = embedded_plan
    plan_source = "embedded"
    overlay_static_report_path = None
    if overlay_latest_static or overlay_reanalyse_strings:
        overlaid_plan, overlay_static_report_path, plan_source = _overlay_plan_from_static_report(
            package_name,
            embedded_plan=embedded_plan,
            static_run_id=static_run_id,
            reanalyse_strings=bool(overlay_reanalyse_strings),
        )
        if isinstance(overlaid_plan, Mapping):
            plan = overlaid_plan
        else:
            plan_source = "embedded"
            overlay_static_report_path = None

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

    base_row = CorroborationRow(
        dynamic_run_id=_norm_text(manifest.get("dynamic_run_id")),
        package_name=package_name,
        static_run_id=static_run_id,
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
        plan_source=plan_source,
        overlay_static_report_path=overlay_static_report_path,
    )
    _detail_rows, detail_counts = _detail_rows_for_run(
        row=base_row,
        plan=plan,
        report=report,
        package_name=package_name,
    )
    return replace(
        base_row,
        host_exact_corroborated_domains=int(detail_counts.get("host_exact_corroborated_domains") or 0),
        root_corroborated_domains=int(detail_counts.get("root_corroborated_domains") or 0),
        actionable_host_exact_corroborated_domains=int(detail_counts.get("actionable_host_exact_corroborated_domains") or 0),
        actionable_root_corroborated_domains=int(detail_counts.get("actionable_root_corroborated_domains") or 0),
        weak_generic_corroborations=int(detail_counts.get("weak_generic_corroborations") or 0),
        static_only_domains=int(detail_counts.get("static_only_domains") or 0),
        dynamic_only_domains=int(detail_counts.get("dynamic_only_domains") or 0),
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
        "runs_using_overlay_latest_static": sum(1 for row in rows if row.plan_source == "overlay_latest_static"),
        "runs_using_overlay_string_reanalysis": sum(1 for row in rows if row.plan_source == "overlay_string_reanalysis"),
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
        "host_exact_corroborated_domains": sum(row.host_exact_corroborated_domains for row in rows),
        "root_corroborated_domains": sum(row.root_corroborated_domains for row in rows),
        "actionable_host_exact_corroborated_domains": sum(
            row.actionable_host_exact_corroborated_domains for row in rows
        ),
        "actionable_root_corroborated_domains": sum(
            row.actionable_root_corroborated_domains for row in rows
        ),
        "weak_generic_corroborations": sum(row.weak_generic_corroborations for row in rows),
        "static_only_domains": sum(row.static_only_domains for row in rows),
        "dynamic_only_domains": sum(row.dynamic_only_domains for row in rows),
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
        "host_exact_corroborated_domains": row.host_exact_corroborated_domains,
        "root_corroborated_domains": row.root_corroborated_domains,
        "actionable_host_exact_corroborated_domains": row.actionable_host_exact_corroborated_domains,
        "actionable_root_corroborated_domains": row.actionable_root_corroborated_domains,
        "weak_generic_corroborations": row.weak_generic_corroborations,
        "static_only_domains": row.static_only_domains,
        "dynamic_only_domains": row.dynamic_only_domains,
        "corroborated_pair_group_count": len(row.corroborated_pair_groups),
        "corroborated_pair_groups": ";".join(row.corroborated_pair_groups),
        "enriched_domain_metadata_present": int(row.enriched_domain_metadata_present),
        "overlap_report_present": int(row.overlap_report_present),
        "plan_source": row.plan_source,
        "plan_path": row.plan_path,
        "overlay_static_report_path": row.overlay_static_report_path,
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
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
        out_dir = output_root / "audit" / "static_string_dynamic_corroboration" / stamp
    out_dir.mkdir(parents=True, exist_ok=True)

    rows: list[CorroborationRow] = []
    run_dirs_for_rows: list[tuple[Path, CorroborationRow]] = []
    package_filter = _norm_text_or_none(args.package_name)
    package_filter_lc = package_filter.lower() if package_filter else None
    for run_dir in _dynamic_run_dirs(output_root):
        if package_filter_lc and _run_dir_package_name(run_dir) != package_filter_lc:
            continue
        _log(args.verbose, f"scan {run_dir.name}")
        row = _corroboration_row(
            run_dir,
            overlay_latest_static=bool(args.overlay_latest_static or args.overlay_reanalyse_strings),
            overlay_reanalyse_strings=bool(args.overlay_reanalyse_strings),
        )
        if row is not None:
            rows.append(row)
            run_dirs_for_rows.append((run_dir, row))

    summary = _summary(rows)
    if package_filter:
        summary["package_filter"] = package_filter
    if args.overlay_latest_static:
        summary["assumptions"] = list(summary.get("assumptions") or []) + [
            "overlay_latest_static_reports_read_only",
            "historical_embedded_plans_left_unchanged",
        ]
        summary["notes"] = list(summary.get("notes") or []) + [
            "Overlay mode synthesizes temporary static plans from current stored static reports and does not modify historical dynamic evidence packs.",
        ]
    if args.overlay_reanalyse_strings:
        summary["assumptions"] = list(summary.get("assumptions") or []) + [
            "overlay_string_reanalysis_uses_current_apk_path_read_only",
        ]
        summary["notes"] = list(summary.get("notes") or []) + [
            "String reanalysis overlay rebuilds temporary static endpoint/domain inventory from the latest stored static report APK path without mutating stored reports or historical dynamic evidence packs.",
        ]
    row_dicts = [_row_dict(row) for row in rows]
    row_fieldnames = list(row_dicts[0].keys()) if row_dicts else []
    detail_rows: list[dict[str, Any]] = []
    for run_dir, row in run_dirs_for_rows:
        detail_rows.extend(
            _detail_rows_for_run_dir(
                run_dir,
                row,
                overlay_latest_static=bool(args.overlay_latest_static or args.overlay_reanalyse_strings),
                overlay_reanalyse_strings=bool(args.overlay_reanalyse_strings),
            )
        )
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
    _write_csv(out_dir / "corroboration_detail.csv", detail_rows)
    _write_csv(out_dir / "actionable_corroboration.csv", actionable_rows, fieldnames=row_fieldnames)
    _write_csv(
        out_dir / "pair_group_corroboration.csv",
        pair_rows,
        fieldnames=("dynamic_run_id", "package_name", "pair_group"),
    )

    summary["output_dir"] = str(out_dir)
    summary["output_files"] = {
        "summary_json": str(out_dir / "summary.json"),
        "corroboration_matrix_csv": str(out_dir / "corroboration_matrix.csv"),
        "corroboration_detail_csv": str(out_dir / "corroboration_detail.csv"),
        "actionable_corroboration_csv": str(out_dir / "actionable_corroboration.csv"),
        "pair_group_corroboration_csv": str(out_dir / "pair_group_corroboration.csv"),
    }
    _write_json(out_dir / "summary.json", summary)

    print(json.dumps(summary, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
