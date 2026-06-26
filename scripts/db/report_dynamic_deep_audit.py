#!/usr/bin/env python3
"""Read-only deep audit over dynamic evidence quality, readiness, and static guidance gaps."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

QUALITY_WEIGHTS = {
    "artifact_integrity": 25,
    "capture_health": 15,
    "dataset_validity": 15,
    "protocol_quality": 10,
    "network_visibility": 15,
    "context_resolution": 10,
    "static_guidance_bridge": 10,
}

QUALITY_TIER_DEFINITIONS = {
    "A+": "95-100 excellent / publication-grade",
    "A": "90-94 paper-ready",
    "B+": "85-89 strong evidence, minor gaps",
    "B": "80-84 usable evidence, some limitations",
    "C+": "70-79 partial but research-useful",
    "C": "60-69 partial / needs improvement",
    "D": "40-59 diagnostic only",
    "F": "0-39 invalid / excluded",
}

READINESS_WEIGHTS = {
    "evidence_base": 35,
    "coverage_completeness": 25,
    "static_bridge_completeness": 20,
    "resolution_robustness": 10,
    "capture_reliability": 10,
}

KNOWN_LIMITATIONS = [
    "provider_authority_status depends on persisted static_provider_acl coverage and may expose join/persistence debt rather than a real absence of provider surface.",
    "phase-aware service/signal attribution is not implemented; phase coverage is timeline/transport only.",
    "static endpoint inventory is only as complete as the embedded plan plus current static string persistence surfaces.",
    "service_mapping_gap_audit reports unresolved observed domains conservatively and does not invent service mappings.",
    "quality/readiness scores are audit heuristics for prioritization and paper readiness, not vulnerability severity scores.",
]


@dataclass(frozen=True)
class RunPhaseCoverage:
    template_id: str | None
    timeline_available: bool
    timeline_complete: bool
    phase_count: int
    transport_phase_rows: int
    phase_attribution_status: str
    recommended_action: str


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    parser.add_argument(
        "--overlay-latest-static",
        action="store_true",
        help=(
            "Read-only reanalysis mode: synthesize a temporary static plan from the latest "
            "matching stored static report instead of relying only on the embedded dynamic evidence plan."
        ),
    )
    return parser


def _dynamic_root() -> Path:
    from scytaledroid.Config import app_config

    return Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    row_list = list(rows)
    if not row_list:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    for row in row_list:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in row_list:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_domain(value: Any) -> str:
    from scytaledroid.DynamicAnalysis.domain_context import normalize_domain

    return normalize_domain(value)


def _root_domain(value: Any) -> str:
    from scytaledroid.DynamicAnalysis.domain_context import root_domain

    return root_domain(value)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value in (None, ""):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _interaction_mode(run_profile: str, interaction_level: str) -> str:
    profile = str(run_profile or "").strip().lower()
    level = str(interaction_level or "").strip().lower()
    if "baseline" in profile:
        return "baseline"
    if "manual" in profile:
        return "manual"
    if "script" in profile:
        return "scripted"
    if level:
        return level
    return "unknown"


def _quality_tier(score: float) -> str:
    if score >= 95.0:
        return "A+"
    if score >= 90.0:
        return "A"
    if score >= 85.0:
        return "B+"
    if score >= 80.0:
        return "B"
    if score >= 70.0:
        return "C+"
    if score >= 60.0:
        return "C"
    if score >= 40.0:
        return "D"
    return "F"


def _pairwise_jaccard(values: Sequence[set[str]]) -> float | None:
    normalized = [set(value) for value in values if value]
    if len(normalized) < 2:
        return None
    scores: list[float] = []
    for idx in range(len(normalized)):
        for jdx in range(idx + 1, len(normalized)):
            left = normalized[idx]
            right = normalized[jdx]
            union = left | right
            if not union:
                continue
            scores.append(len(left & right) / float(len(union)))
    if not scores:
        return None
    return sum(scores) / float(len(scores))


def _set_jaccard(left: set[str], right: set[str]) -> float | None:
    union = left | right
    if not union:
        return None
    return len(left & right) / float(len(union))


def _load_app_profiles(packages: Iterable[str]) -> dict[str, dict[str, str]]:
    normalized = sorted({_norm_text(package).lower() for package in packages if _norm_text(package)})
    if not normalized:
        return {}
    try:
        from scytaledroid.Database.db_core import db_queries as core_q

        placeholders = ", ".join(["%s"] * len(normalized))
        rows = core_q.run_sql(
            f"""
            SELECT LOWER(TRIM(package_name)) AS package_name,
                   NULLIF(display_name, '') AS display_name,
                   NULLIF(profile_key, '') AS profile_key
            FROM apps
            WHERE LOWER(TRIM(package_name)) IN ({placeholders})
            """,
            tuple(normalized),
            fetch="all",
            dictionary=True,
            query_name="dynamic.deep_audit.app_profiles",
        ) or []
    except Exception:
        return {}
    out: dict[str, dict[str, str]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        package = _norm_text(row.get("package_name")).lower()
        if not package:
            continue
        out[package] = {
            "display_name": _norm_text(row.get("display_name")),
            "profile_key": _norm_text(row.get("profile_key")),
        }
    return out


def _run_domain_roots(run: Mapping[str, Any]) -> set[str]:
    dynamic_domains = run.get("dynamic_domains")
    if not isinstance(dynamic_domains, set):
        return set()
    return {str(value) for value in dynamic_domains if str(value).strip()}


def _run_service_keys(run: Mapping[str, Any]) -> set[str]:
    return {
        _norm_text(row.get("service_key"))
        for row in (run.get("service_rows") or [])
        if isinstance(row, Mapping) and _norm_text(row.get("service_key"))
    }


def _run_signal_keys(run: Mapping[str, Any]) -> set[str]:
    return {
        _norm_text(row.get("signal_key"))
        for row in (run.get("signal_rows") or [])
        if isinstance(row, Mapping) and _norm_text(row.get("signal_key"))
    }


def _collect_dynamic_domains(report: Mapping[str, Any] | None) -> set[str]:
    domains: set[str] = set()
    if not isinstance(report, Mapping):
        return domains
    for key in ("top_dns", "top_sni"):
        rows = report.get(key)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            domain = _normalize_domain(row.get("value"))
            if domain:
                domains.add(_root_domain(domain))
    return {value for value in domains if value}


def _plan_enrichment(plan: Mapping[str, Any] | None) -> dict[str, Any]:
    network = plan.get("network_targets") if isinstance(plan, Mapping) and isinstance(plan.get("network_targets"), dict) else {}
    domain_sources = network.get("domain_sources") if isinstance(network.get("domain_sources"), list) else []
    domains = network.get("domains") if isinstance(network.get("domains"), list) else []
    cleartext_domains = network.get("cleartext_domains") if isinstance(network.get("cleartext_domains"), list) else []
    enriched = False
    actionable_count = 0
    exploratory_count = 0
    pair_group_count = 0
    domain_count = 0
    for row in domain_sources:
        if not isinstance(row, Mapping):
            continue
        domain = _normalize_domain(row.get("domain"))
        if not domain:
            continue
        domain_count += 1
        postures = row.get("postures") if isinstance(row.get("postures"), list) else []
        pair_groups = row.get("pair_groups") if isinstance(row.get("pair_groups"), list) else []
        ownership = row.get("ownership_classes") if isinstance(row.get("ownership_classes"), list) else []
        api_contexts = row.get("api_contexts") if isinstance(row.get("api_contexts"), list) else []
        if postures or pair_groups or ownership or api_contexts:
            enriched = True
        actionable_count += sum(1 for value in postures if str(value or "").strip() == "actionable")
        exploratory_count += sum(1 for value in postures if str(value or "").strip() == "exploratory")
        pair_group_count += len([value for value in pair_groups if str(value or "").strip()])
    if domain_count == 0:
        domain_count = len([_normalize_domain(item) for item in domains if _normalize_domain(item)])
    return {
        "plan_present": isinstance(plan, Mapping) and bool(plan),
        "static_domain_count": int(domain_count),
        "cleartext_domain_count": len([_normalize_domain(item) for item in cleartext_domains if _normalize_domain(item)]),
        "enriched_domain_metadata_present": bool(enriched),
        "actionable_static_domain_rows": int(actionable_count),
        "exploratory_static_domain_rows": int(exploratory_count),
        "pair_group_count": int(pair_group_count),
    }


def _corroboration_from_plan_and_report(
    *,
    run_id: str,
    package: str,
    plan: Mapping[str, Any] | None,
    report: Mapping[str, Any] | None,
    run_dir: Path,
) -> dict[str, Any]:
    enrichment = _plan_enrichment(plan)
    dynamic_domains: set[str] = set()
    if isinstance(report, Mapping):
        for key in ("top_dns", "top_sni"):
            rows = report.get(key)
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, Mapping):
                    continue
                domain = _normalize_domain(row.get("value"))
                if domain:
                    dynamic_domains.add(domain)
    network = plan.get("network_targets") if isinstance(plan, Mapping) and isinstance(plan.get("network_targets"), dict) else {}
    domain_sources = network.get("domain_sources") if isinstance(network.get("domain_sources"), list) else []
    corroborated_actionable = 0
    corroborated_total = 0
    for row in domain_sources:
        if not isinstance(row, Mapping):
            continue
        domain = _normalize_domain(row.get("domain"))
        if not domain:
            continue
        if domain not in dynamic_domains:
            continue
        corroborated_total += 1
        postures = row.get("postures") if isinstance(row.get("postures"), list) else []
        if any(str(value or "").strip() == "actionable" for value in postures):
            corroborated_actionable += 1
    return {
        "run_id": run_id,
        "package": package,
        "static_run_id": _safe_int(
            (plan.get("run_identity") or {}).get("static_run_id")
            if isinstance(plan, Mapping) and isinstance(plan.get("run_identity"), Mapping)
            else plan.get("static_run_id") if isinstance(plan, Mapping) else None,
            default=0,
        )
        or None,
        "overlap_report_present": (run_dir / "analysis" / "static_dynamic_overlap.json").exists(),
        "static_domains_total": enrichment["static_domain_count"],
        "enriched_domain_metadata_present": enrichment["enriched_domain_metadata_present"],
        "actionable_static_domain_rows": enrichment["actionable_static_domain_rows"],
        "corroborated_actionable_domains": int(corroborated_actionable),
        "corroborated_domains_total": int(corroborated_total),
    }


def _plan_overlay_bundle(
    *,
    package: str,
    embedded_plan: Mapping[str, Any] | None,
    static_run_id: int | None,
    overlay_latest_static: bool,
) -> dict[str, Any]:
    embedded_enrichment = _plan_enrichment(embedded_plan)
    bundle: dict[str, Any] = {
        "plan": embedded_plan if isinstance(embedded_plan, Mapping) else {},
        "plan_source": "embedded_plan",
        "overlay_static_report_path": None,
        "embedded_domains_count": int(embedded_enrichment["static_domain_count"]),
        "overlay_domains_count": int(embedded_enrichment["static_domain_count"]),
        "embedded_enriched_metadata_present": bool(embedded_enrichment["enriched_domain_metadata_present"]),
        "overlay_enriched_metadata_present": bool(embedded_enrichment["enriched_domain_metadata_present"]),
        "embedded_plan_stale": False,
        "overlay_applied": False,
    }
    if not overlay_latest_static:
        return bundle

    from scripts.db import report_static_string_dynamic_corroboration as corroboration_report

    overlay_plan, overlay_static_report_path, overlay_plan_source = corroboration_report._overlay_plan_from_static_report(
        package,
        embedded_plan=embedded_plan,
        static_run_id=static_run_id,
    )
    if not isinstance(overlay_plan, Mapping):
        return bundle

    overlay_enrichment = _plan_enrichment(overlay_plan)
    embedded_signature = (
        int(embedded_enrichment["static_domain_count"]),
        bool(embedded_enrichment["enriched_domain_metadata_present"]),
        int(embedded_enrichment["actionable_static_domain_rows"]),
        int(embedded_enrichment["exploratory_static_domain_rows"]),
        int(embedded_enrichment["pair_group_count"]),
    )
    overlay_signature = (
        int(overlay_enrichment["static_domain_count"]),
        bool(overlay_enrichment["enriched_domain_metadata_present"]),
        int(overlay_enrichment["actionable_static_domain_rows"]),
        int(overlay_enrichment["exploratory_static_domain_rows"]),
        int(overlay_enrichment["pair_group_count"]),
    )
    bundle.update(
        {
            "plan": dict(overlay_plan),
            "plan_source": str(overlay_plan_source or "overlay_latest_static"),
            "overlay_static_report_path": overlay_static_report_path,
            "overlay_domains_count": int(overlay_enrichment["static_domain_count"]),
            "overlay_enriched_metadata_present": bool(overlay_enrichment["enriched_domain_metadata_present"]),
            "embedded_plan_stale": embedded_signature != overlay_signature,
            "overlay_applied": True,
        }
    )
    return bundle


def _pcap_artifact_info(
    *,
    run_dir: Path,
    manifest: Mapping[str, Any],
    report: Mapping[str, Any] | None,
    summary_payload: Mapping[str, Any] | None,
    verify_row: Mapping[str, Any],
) -> dict[str, Any]:
    from scytaledroid.DynamicAnalysis.pcap.diagnostics import (
        canonical_pcap_failure_code,
        deep_audit_pcap_failure_detail,
        extract_verify_issue_codes,
    )

    artifact_rel = ""
    artifact_exists = False
    local_path: Path | None = None
    for artifact in manifest.get("artifacts") or []:
        if not isinstance(artifact, Mapping):
            continue
        if artifact.get("type") != "pcapdroid_capture":
            continue
        artifact_rel = str(artifact.get("relative_path") or "").strip()
        if artifact_rel:
            candidate = run_dir / artifact_rel
            if candidate.exists():
                artifact_exists = True
                local_path = candidate
            break
    meta_path = run_dir / "artifacts" / "pcapdroid_capture" / "pcapdroid_capture_meta.json"
    meta_payload = _read_json(meta_path)
    pcap_size_bytes = _safe_int(
        (report or {}).get("pcap_size_bytes"),
        _safe_int((summary_payload or {}).get("pcap_size_bytes"), _safe_int((meta_payload or {}).get("pcap_size_bytes"))),
    )
    if pcap_size_bytes <= 0 and local_path is not None and local_path.exists():
        pcap_size_bytes = _safe_int(local_path.stat().st_size)
    issue_codes = set(extract_verify_issue_codes(verify_row))
    canonical = canonical_pcap_failure_code(
        artifact_rel=artifact_rel,
        artifact_exists=artifact_exists,
        pcap_size_bytes=pcap_size_bytes,
        report_status=str((report or {}).get("report_status") or ""),
        invalid_reason_code=str(verify_row.get("invalid_reason_code") or ""),
        verify_row=verify_row,
    )
    detail = deep_audit_pcap_failure_detail(canonical)
    pcap_present = bool(artifact_exists and pcap_size_bytes > 0)
    return {
        "pcap_present": pcap_present,
        "pcap_size_bytes": int(max(pcap_size_bytes, 0)),
        "pcap_failure_detail": detail,
        "pcap_artifact_relative_path": artifact_rel,
        "pcap_local_path": str(local_path.resolve()) if local_path is not None and local_path.exists() else None,
        "capinfos_parsed": bool(((report or {}).get("capinfos") or {}).get("parsed")),
        "tshark_ok": str((report or {}).get("report_status") or "") == "ok",
        "report_present": isinstance(report, Mapping) and bool(report),
    }


def _telemetry_info(
    manifest: Mapping[str, Any],
    summary_payload: Mapping[str, Any] | None,
) -> dict[str, Any]:
    operator = manifest.get("operator") if isinstance(manifest.get("operator"), Mapping) else {}
    telemetry_stats = operator.get("telemetry_stats") if isinstance(operator.get("telemetry_stats"), Mapping) else {}
    if not telemetry_stats and isinstance(summary_payload, Mapping):
        telemetry = summary_payload.get("telemetry") if isinstance(summary_payload.get("telemetry"), Mapping) else {}
        telemetry_stats = telemetry.get("stats") if isinstance(telemetry.get("stats"), Mapping) else {}
    net_in = _safe_int(telemetry_stats.get("netstats_bytes_in_total"))
    net_out = _safe_int(telemetry_stats.get("netstats_bytes_out_total"))
    return {
        "netstats_available": bool(telemetry_stats.get("netstats_available")),
        "netstats_observed_bytes": int(net_in + net_out),
        "netstats_rows": _safe_int(telemetry_stats.get("netstats_rows")),
        "netstats_missing_rows": _safe_int(telemetry_stats.get("netstats_missing_rows")),
        "capture_ratio": _safe_float(telemetry_stats.get("capture_ratio")),
        "max_gap_s": _safe_float(telemetry_stats.get("max_gap_s"), _safe_float(telemetry_stats.get("sample_max_gap_s"))),
        "network_signal_quality": _norm_text(telemetry_stats.get("network_signal_quality")).lower(),
    }


def _pcap_netstats_consistency(*, pcap_present: bool, pcap_size_bytes: int, netstats_observed_bytes: int) -> str:
    if netstats_observed_bytes > 0 and (not pcap_present or pcap_size_bytes <= 0):
        return "netstats_seen_but_pcap_missing"
    if pcap_present and pcap_size_bytes > 0 and netstats_observed_bytes <= 0:
        return "pcap_present_but_netstats_empty"
    if pcap_present and pcap_size_bytes > 0 and netstats_observed_bytes > 0:
        return "consistent"
    if netstats_observed_bytes <= 0 and pcap_size_bytes <= 0:
        return "no_network_observed"
    return "unknown"


def _phase_coverage(
    *,
    run_dir: Path,
    manifest: Mapping[str, Any],
    pcap_present: bool,
) -> RunPhaseCoverage:
    from scytaledroid.DynamicAnalysis.pcap.interaction_phases import (
        build_interaction_timeline_from_run_dir,
        phase_packet_transport_summary,
    )

    operator = manifest.get("operator") if isinstance(manifest.get("operator"), Mapping) else {}
    run_profile = _norm_text(operator.get("run_profile")).lower()
    template_id = _norm_text(
        operator.get("template_id")
        or operator.get("scenario_template")
        or operator.get("template_id_actual")
    ) or None
    if run_profile != "interaction_scripted":
        return RunPhaseCoverage(
            template_id=template_id,
            timeline_available=False,
            timeline_complete=False,
            phase_count=0,
            transport_phase_rows=0,
            phase_attribution_status="not_applicable",
            recommended_action="none",
        )
    timeline = _read_json(run_dir / "analysis" / "interaction_timeline.json")
    if not isinstance(timeline, Mapping):
        timeline = build_interaction_timeline_from_run_dir(run_dir, manifest=manifest)
    if not isinstance(timeline, Mapping):
        return RunPhaseCoverage(
            template_id=template_id,
            timeline_available=False,
            timeline_complete=False,
            phase_count=0,
            transport_phase_rows=0,
            phase_attribution_status="timeline_missing",
            recommended_action="review_scripted_timeline",
        )
    transport_rows = phase_packet_transport_summary(run_dir, timeline=timeline, manifest=manifest)
    if not pcap_present:
        status = "timeline_only"
        action = "recollect_capture"
    elif transport_rows:
        status = "transport_only"
        action = "phase_service_attribution_not_supported"
    else:
        status = "transport_missing"
        action = "review_phase_transport_summary"
    return RunPhaseCoverage(
        template_id=template_id or _norm_text(timeline.get("template_id")) or None,
        timeline_available=True,
        timeline_complete=bool(timeline.get("timeline_complete")),
        phase_count=len([step for step in (timeline.get("steps") or []) if isinstance(step, Mapping)]),
        transport_phase_rows=len(transport_rows or []),
        phase_attribution_status=status,
        recommended_action=action,
    )


def _collect_run_records(output_root: Path, *, overlay_latest_static: bool = False) -> list[dict[str, Any]]:
    from scytaledroid.DynamicAnalysis.pcap.context_summary import summarize_pcap_service_context
    from scytaledroid.DynamicAnalysis.tools.evidence.verify_core import verify_dynamic_evidence_packs

    verify_report = verify_dynamic_evidence_packs(output_root)
    verify_by_run = {
        str(row.get("run_id") or ""): row
        for row in (verify_report.get("runs") or [])
        if isinstance(row, Mapping)
    }
    rows: list[dict[str, Any]] = []
    for manifest_path in sorted(output_root.glob("*/run_manifest.json")):
        run_dir = manifest_path.parent
        manifest = _read_json(manifest_path) or {}
        run_id = _norm_text(manifest.get("dynamic_run_id") or run_dir.name)
        target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
        operator = manifest.get("operator") if isinstance(manifest.get("operator"), Mapping) else {}
        dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), Mapping) else {}
        package = _norm_text(target.get("package_name")).lower() or "_unknown"
        app_label = _norm_text(target.get("display_name") or target.get("app_label") or package)
        run_profile = _norm_text(operator.get("run_profile") or dataset.get("run_profile"))
        interaction_mode = _interaction_mode(run_profile, _norm_text(operator.get("interaction_level")))
        report = _read_json(run_dir / "analysis" / "pcap_report.json") or {}
        features = _read_json(run_dir / "analysis" / "pcap_features.json") or {}
        summary_payload = _read_json(run_dir / "analysis" / "summary.json") or {}
        embedded_plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json") or {}
        verify_row = verify_by_run.get(run_id, {})
        evidence_status = _norm_text(verify_row.get("status"))
        if not evidence_status:
            evidence_status = "valid" if verify_row.get("valid_dataset_run") is True else "invalid"
        static_run_id = _safe_int(
            target.get("static_run_id")
            or (
                (embedded_plan.get("run_identity") or {}).get("static_run_id")
                if isinstance(embedded_plan, Mapping) and isinstance(embedded_plan.get("run_identity"), Mapping)
                else embedded_plan.get("static_run_id")
                if isinstance(embedded_plan, Mapping)
                else None
            )
        )
        plan_bundle = _plan_overlay_bundle(
            package=package,
            embedded_plan=embedded_plan,
            static_run_id=static_run_id,
            overlay_latest_static=overlay_latest_static,
        )
        plan = plan_bundle["plan"] if isinstance(plan_bundle.get("plan"), Mapping) else {}
        service_bundle = summarize_pcap_service_context(report, package_name=package)
        service_context = service_bundle.get("service_context") if isinstance(service_bundle.get("service_context"), Mapping) else {}
        service_signals = service_bundle.get("service_signals") if isinstance(service_bundle.get("service_signals"), Mapping) else {}
        signal_unmapped = [
            item
            for item in (service_signals.get("services_without_signal_mappings") or [])
            if _norm_text(item)
        ]
        pcap_info = _pcap_artifact_info(
            run_dir=run_dir,
            manifest=manifest,
            report=report,
            summary_payload=summary_payload,
            verify_row=verify_row,
        )
        telemetry = _telemetry_info(manifest, summary_payload)
        consistency = _pcap_netstats_consistency(
            pcap_present=pcap_info["pcap_present"],
            pcap_size_bytes=int(pcap_info["pcap_size_bytes"]),
            netstats_observed_bytes=int(telemetry["netstats_observed_bytes"]),
        )
        phase = _phase_coverage(run_dir=run_dir, manifest=manifest, pcap_present=bool(pcap_info["pcap_present"]))
        embedded_corroboration = _corroboration_from_plan_and_report(
            run_id=run_id,
            package=package,
            plan=embedded_plan,
            report=report,
            run_dir=run_dir,
        )
        overlay_corroboration = (
            _corroboration_from_plan_and_report(
                run_id=run_id,
                package=package,
                plan=plan,
                report=report,
                run_dir=run_dir,
            )
            if bool(plan_bundle.get("overlay_applied"))
            else None
        )
        corroboration = overlay_corroboration or embedded_corroboration
        dynamic_domains = _collect_dynamic_domains(report)
        service_rows = [dict(row) for row in (service_context.get("services") or []) if isinstance(row, Mapping)]
        signal_rows = [dict(row) for row in (service_signals.get("signals") or []) if isinstance(row, Mapping)]
        rows.append(
            {
                "run_id": run_id,
                "run_dir": run_dir,
                "package": package,
                "app_label": app_label,
                "manifest": manifest,
                "dataset": dataset,
                "target": target,
                "operator": operator,
                "run_profile": run_profile,
                "interaction_mode": interaction_mode,
                "evidence_status": evidence_status,
                "valid_pack": bool(verify_row.get("valid_dataset_run") is True and str(report.get("report_status") or "") == "ok"),
                "verify_row": verify_row,
                "report": report,
                "pcap_report": report,
                "features": features,
                "summary_payload": summary_payload,
                "plan": plan,
                "embedded_plan": embedded_plan,
                "static_plan": plan,
                "plan_source": str(plan_bundle.get("plan_source") or "embedded_plan"),
                "overlay_static_report_path": plan_bundle.get("overlay_static_report_path"),
                "embedded_plan_stale": bool(plan_bundle.get("embedded_plan_stale")),
                "embedded_domains_count": _safe_int(plan_bundle.get("embedded_domains_count"), default=0),
                "overlay_domains_count": _safe_int(plan_bundle.get("overlay_domains_count"), default=0),
                "embedded_enriched_metadata_present": bool(plan_bundle.get("embedded_enriched_metadata_present")),
                "overlay_enriched_metadata_present": bool(plan_bundle.get("overlay_enriched_metadata_present")),
                "pcap_info": pcap_info,
                "telemetry": telemetry,
                "pcap_netstats_consistency": consistency,
                "service_context": service_context,
                "service_signals": service_signals,
                "service_rows": service_rows,
                "signal_rows": signal_rows,
                "unresolved_service_count": _safe_int(service_context.get("unresolved_domain_count")),
                "unresolved_signal_count": len(signal_unmapped),
                "service_count": _safe_int(service_context.get("service_count")),
                "signal_count": _safe_int(service_signals.get("signal_count")),
                "dynamic_domains": dynamic_domains,
                "visibility_loss_flag": bool(
                    ((report.get("tls_quic_visibility") or {}).get("quic_candidate_packets") or 0) > 0
                    and not bool((report.get("tls_quic_visibility") or {}).get("tls_visible"))
                ),
                "http_observed": any(
                    str(item.get("protocol") or "").lower().startswith("http")
                    for item in (report.get("protocol_hierarchy") or [])
                    if isinstance(item, Mapping)
                ),
                "corroboration": corroboration,
                "embedded_corroboration": embedded_corroboration,
                "overlay_corroboration": overlay_corroboration,
                "phase": phase,
                "template_id": phase.template_id,
            }
        )
    return rows


def _build_static_join_and_candidates(package_runs: dict[str, list[dict[str, Any]]]) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    from scripts.db import report_dynamic_hidden_patterns as hidden

    static_seed, _, _ = hidden._build_static_rows(package_runs)
    join_rows = hidden._merge_dynamic_into_join(static_seed, package_runs)
    candidate_rows = hidden._build_hidden_pattern_candidates(join_rows)
    return (
        {str(row["package"]): dict(row) for row in join_rows},
        defaultdict(list, {str(row["package"]): [dict(item) for item in candidate_rows if str(item["package"]) == str(row["package"])] for row in join_rows}),
    )


def _artifact_integrity_score(run: Mapping[str, Any], limitations: list[str]) -> int:
    report = run.get("report") if isinstance(run.get("report"), Mapping) else {}
    features = run.get("features") if isinstance(run.get("features"), Mapping) else {}
    dataset = run.get("dataset") if isinstance(run.get("dataset"), Mapping) else {}
    pcap_info = run.get("pcap_info") if isinstance(run.get("pcap_info"), Mapping) else {}
    score = 0
    if pcap_info.get("pcap_present"):
        score += 8
    else:
        detail = _norm_text(pcap_info.get("pcap_failure_detail")).lower() or "pcap_missing"
        limitations.append(detail)
    min_pcap_bytes = _safe_int(dataset.get("min_pcap_bytes"), 50_000)
    if _safe_int(pcap_info.get("pcap_size_bytes")) >= min_pcap_bytes:
        score += 5
    elif _safe_int(pcap_info.get("pcap_size_bytes")) > 0:
        limitations.append("pcap_below_threshold")
    if bool(pcap_info.get("capinfos_parsed")):
        score += 4
    else:
        limitations.append("capinfos_parse_failed")
    if bool(pcap_info.get("tshark_ok")):
        score += 4
    else:
        limitations.append("tshark_parse_failed")
    if report:
        score += 2
    else:
        limitations.append("pcap_report_missing")
    if features:
        score += 2
    else:
        limitations.append("pcap_features_missing")
    return min(score, QUALITY_WEIGHTS["artifact_integrity"])


def _capture_health_score(run: Mapping[str, Any], limitations: list[str]) -> int:
    telemetry = run.get("telemetry") if isinstance(run.get("telemetry"), Mapping) else {}
    consistency = _norm_text(run.get("pcap_netstats_consistency")).lower()
    score = 0
    if telemetry.get("netstats_available"):
        score += 4
    else:
        limitations.append("netstats_missing")
    if _safe_int(telemetry.get("netstats_observed_bytes")) > 0:
        score += 3
    else:
        limitations.append("netstats_zero_bytes")
    if _safe_float(telemetry.get("capture_ratio")) >= 0.90:
        score += 3
    else:
        limitations.append("capture_ratio_low")
    max_gap = _safe_float(telemetry.get("max_gap_s"))
    if 0.0 < max_gap <= 5.0:
        score += 3
    elif max_gap > 5.0:
        limitations.append("telemetry_max_gap_high")
    observer_statuses = [
        _norm_text(obs.get("status")).lower()
        for obs in ((run.get("manifest") or {}).get("observers") or [])
        if isinstance(obs, Mapping)
    ]
    if observer_statuses and all(status in {"ok", "completed", "complete"} for status in observer_statuses):
        score += 2
    elif observer_statuses:
        limitations.append("observer_status_degraded")
    if consistency == "netstats_seen_but_pcap_missing":
        score = max(0, score - 4)
        limitations.append("netstats_seen_but_pcap_missing")
    elif consistency == "pcap_present_but_netstats_empty":
        score = max(0, score - 2)
        limitations.append("pcap_present_but_netstats_empty")
    return min(score, QUALITY_WEIGHTS["capture_health"])


def _dataset_validity_score(run: Mapping[str, Any], limitations: list[str]) -> int:
    verify_row = run.get("verify_row") if isinstance(run.get("verify_row"), Mapping) else {}
    dataset = run.get("dataset") if isinstance(run.get("dataset"), Mapping) else {}
    score = 0
    if verify_row.get("valid_dataset_run") is True:
        score += 10
    else:
        limitations.append("dataset_invalid_or_excluded")
    invalid_reason = _norm_text(dataset.get("invalid_reason_code") or verify_row.get("invalid_reason_code"))
    if not invalid_reason:
        score += 3
    else:
        limitations.append(f"invalid_reason:{invalid_reason.lower()}")
    issue_codes = {
        str(issue.get("code") or "")
        for issue in (verify_row.get("issues") or [])
        if isinstance(issue, Mapping)
    }
    if not any(code in {"missing_frozen_input", "pcap_artifact_missing", "pcap_file_missing"} for code in issue_codes):
        score += 2
    else:
        limitations.append("artifact_set_incomplete")
    return min(score, QUALITY_WEIGHTS["dataset_validity"])


def _protocol_quality_score(run: Mapping[str, Any], limitations: list[str]) -> int:
    dataset = run.get("dataset") if isinstance(run.get("dataset"), Mapping) else {}
    operator = run.get("operator") if isinstance(run.get("operator"), Mapping) else {}
    phase = run.get("phase")
    run_profile = _norm_text(run.get("run_profile"))
    interaction_mode = _norm_text(run.get("interaction_mode"))
    score = 0
    if run_profile:
        score += 2
    else:
        limitations.append("run_profile_unknown")
    if interaction_mode and interaction_mode != "unknown":
        score += 2
    else:
        limitations.append("interaction_mode_unknown")
    if _safe_float(operator.get("actual_duration_s")) > 0 or _safe_float(dataset.get("actual_sampling_seconds")) > 0:
        score += 2
    else:
        limitations.append("run_duration_missing")
    protocol_compliance = _norm_text(dataset.get("protocol_compliance") or operator.get("protocol_compliance")).lower()
    if protocol_compliance in {"compliant", "ok", "pass"}:
        score += 2
    elif protocol_compliance:
        limitations.append(f"protocol_compliance:{protocol_compliance}")
    if interaction_mode == "scripted":
        if getattr(phase, "timeline_available", False):
            score += 1
        else:
            limitations.append("scripted_timeline_missing")
        if getattr(phase, "timeline_complete", False):
            score += 1
        else:
            limitations.append("scripted_timeline_incomplete")
        if operator.get("script_timing_within_tolerance") is True:
            score += 1
        elif operator.get("script_timing_within_tolerance") is False:
            limitations.append("scripted_timing_out_of_tolerance")
    else:
        score += 2
    return min(score, QUALITY_WEIGHTS["protocol_quality"])


def _network_visibility_score(run: Mapping[str, Any], limitations: list[str]) -> int:
    report = run.get("report") if isinstance(run.get("report"), Mapping) else {}
    score = 0
    domain_count = _safe_int((run.get("service_context") or {}).get("observed_domain_count"))
    if domain_count > 0:
        score += 4
    else:
        limitations.append("no_dynamic_domains")
    if isinstance(report.get("protocol_hierarchy"), list) and report.get("protocol_hierarchy"):
        score += 3
    else:
        limitations.append("protocol_hierarchy_missing")
    if _safe_int(run.get("service_count")) > 0:
        score += 3
    else:
        limitations.append("service_context_empty")
    if _safe_int(run.get("signal_count")) > 0:
        score += 3
    else:
        limitations.append("signal_context_empty")
    if not bool(run.get("visibility_loss_flag")):
        score += 2
    else:
        limitations.append("visibility_loss_flag")
    return min(score, QUALITY_WEIGHTS["network_visibility"])


def _context_resolution_score(run: Mapping[str, Any], limitations: list[str]) -> tuple[int, float | None, float | None]:
    service_context = run.get("service_context") if isinstance(run.get("service_context"), Mapping) else {}
    service_rows = [row for row in (service_context.get("services") or []) if isinstance(row, Mapping)]
    signal_count = _safe_int(run.get("signal_count"))
    unresolved_service_count = _safe_int(run.get("unresolved_service_count"))
    unresolved_signal_count = _safe_int(run.get("unresolved_signal_count"))
    resolved_service_count = len(service_rows)
    service_rate = None
    if resolved_service_count + unresolved_service_count > 0:
        service_rate = resolved_service_count / float(resolved_service_count + unresolved_service_count)
    signal_rate = None
    if signal_count + unresolved_signal_count > 0:
        signal_rate = signal_count / float(signal_count + unresolved_signal_count)
    score = 0
    if service_rate is not None:
        score += round(5 * service_rate)
        if service_rate < 1.0:
            limitations.append("service_mapping_gaps")
    else:
        limitations.append("service_resolution_unknown")
    if signal_rate is not None:
        score += round(3 * signal_rate)
        if signal_rate < 1.0:
            limitations.append("signal_mapping_gaps")
    else:
        limitations.append("signal_resolution_unknown")
    owner_class_complete = bool(service_rows) and all(_norm_text(row.get("owner_class")) for row in service_rows)
    if owner_class_complete:
        score += 2
    elif service_rows:
        limitations.append("owner_class_missing")
    return min(score, QUALITY_WEIGHTS["context_resolution"]), service_rate, signal_rate


def _static_guidance_bridge_score(run: Mapping[str, Any], join_row: Mapping[str, Any] | None, limitations: list[str]) -> int:
    corroboration = run.get("corroboration") if isinstance(run.get("corroboration"), Mapping) else {}
    plan = run.get("plan") if isinstance(run.get("plan"), Mapping) else {}
    score = 0
    if plan:
        score += 3
    else:
        limitations.append("static_plan_missing")
    endpoint_status = _norm_text((join_row or {}).get("static_endpoint_inventory_status"))
    if endpoint_status == "present":
        score += 2
    elif endpoint_status == "missing":
        limitations.append("static_endpoint_inventory_missing")
    elif endpoint_status:
        score += 1
        limitations.append(f"static_endpoint_inventory_{endpoint_status.lower()}")
    else:
        limitations.append("static_endpoint_inventory_unknown")
    if bool(corroboration.get("enriched_domain_metadata_present")):
        score += 2
    else:
        limitations.append("enriched_domain_metadata_missing")
    if bool(corroboration.get("overlap_report_present")):
        score += 1
    else:
        limitations.append("static_dynamic_overlap_missing")
    if isinstance(plan.get("static_features"), Mapping) and plan.get("static_features"):
        score += 2
    else:
        limitations.append("static_features_missing")
    return min(score, QUALITY_WEIGHTS["static_guidance_bridge"])


def _provider_authority_status(join_row: Mapping[str, Any] | None) -> str:
    if not isinstance(join_row, Mapping):
        return "unknown"
    count = _safe_int(join_row.get("provider_authority_count"))
    providers_exported = _safe_int(join_row.get("providers_exported"), _safe_int(join_row.get("exported_component_total")))
    if count > 0:
        return "present"
    if providers_exported > 0:
        return "join_gap"
    return "missing"


def _score_run(run: Mapping[str, Any], join_row: Mapping[str, Any] | None) -> dict[str, Any]:
    limitations: list[str] = []
    artifact_score = _artifact_integrity_score(run, limitations)
    capture_score = _capture_health_score(run, limitations)
    dataset_score = _dataset_validity_score(run, limitations)
    protocol_score = _protocol_quality_score(run, limitations)
    network_score = _network_visibility_score(run, limitations)
    context_score, service_rate, signal_rate = _context_resolution_score(run, limitations)
    bridge_score = _static_guidance_bridge_score(run, join_row, limitations)
    if _provider_authority_status(join_row) == "join_gap":
        limitations.append("provider_authority_join_gap")
    phase = run.get("phase")
    if getattr(phase, "timeline_available", False):
        limitations.append("phase_service_attribution_not_supported")
    total = float(
        artifact_score
        + capture_score
        + dataset_score
        + protocol_score
        + network_score
        + context_score
        + bridge_score
    )
    deduped_limitations = sorted({item for item in limitations if item})
    pcap_info = run.get("pcap_info") if isinstance(run.get("pcap_info"), Mapping) else {}
    telemetry = run.get("telemetry") if isinstance(run.get("telemetry"), Mapping) else {}
    return {
        "run_id": run["run_id"],
        "package": run["package"],
        "app_label": run["app_label"],
        "run_profile": run["run_profile"],
        "interaction_mode": run["interaction_mode"],
        "evidence_status": run["evidence_status"],
        "valid_pack": int(bool(run["valid_pack"])),
        "dynamic_evidence_quality_score": round(total, 2),
        "dynamic_evidence_quality_tier": _quality_tier(total),
        "artifact_integrity_score": artifact_score,
        "capture_health_score": capture_score,
        "dataset_validity_score": dataset_score,
        "protocol_quality_score": protocol_score,
        "network_visibility_score": network_score,
        "context_resolution_score": context_score,
        "static_guidance_bridge_score": bridge_score,
        "pcap_present": int(bool(pcap_info.get("pcap_present"))),
        "pcap_size_bytes": _safe_int(pcap_info.get("pcap_size_bytes")),
        "netstats_observed_bytes": _safe_int(telemetry.get("netstats_observed_bytes")),
        "pcap_netstats_consistency": run.get("pcap_netstats_consistency"),
        "service_count": _safe_int(run.get("service_count")),
        "signal_count": _safe_int(run.get("signal_count")),
        "unresolved_service_count": _safe_int(run.get("unresolved_service_count")),
        "unresolved_signal_count": _safe_int(run.get("unresolved_signal_count")),
        "timeline_available": int(bool(getattr(phase, "timeline_available", False))),
        "timeline_complete": int(bool(getattr(phase, "timeline_complete", False))),
        "plan_source": _norm_text(run.get("plan_source")) or "embedded_plan",
        "overlay_static_report_path": _norm_text(run.get("overlay_static_report_path")),
        "embedded_plan_stale": int(bool(run.get("embedded_plan_stale"))),
        "embedded_domains_count": _safe_int(run.get("embedded_domains_count")),
        "overlay_domains_count": _safe_int(run.get("overlay_domains_count")),
        "embedded_enriched_metadata_present": int(bool(run.get("embedded_enriched_metadata_present"))),
        "overlay_enriched_metadata_present": int(bool(run.get("overlay_enriched_metadata_present"))),
        "dynamic_evidence_limitations": "; ".join(deduped_limitations),
        "pcap_failure_detail": _norm_text(pcap_info.get("pcap_failure_detail")),
        "service_resolution_rate": service_rate,
        "signal_resolution_rate": signal_rate,
    }


def _gap_class_for_key(key: str) -> str:
    if key in {"enriched_domain_metadata_missing", "actionable_corroboration_missing", "phase_service_attribution_not_supported"}:
        return "not_yet_supported"
    if key in {"provider_authority_join_gap"}:
        return "join_bug"
    if key in {"service_mapping_gaps"}:
        return "true_missing_data"
    if key in {"static_endpoint_inventory_missing"}:
        return "true_missing_data"
    if key in {"static_plan_missing"}:
        return "true_missing_data"
    if key in {"pcap_capture_gap"}:
        return "true_missing_data"
    return "not_yet_supported"


def _bridge_gaps_for_package(
    *,
    package: str,
    app_label: str,
    join_row: Mapping[str, Any] | None,
    runs: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    static_run_id = ""
    if isinstance(join_row, Mapping):
        static_run_id = str(join_row.get("static_run_id") or "")
    endpoint_status = _norm_text((join_row or {}).get("static_endpoint_inventory_status") or "unknown")
    if endpoint_status in {"missing", "unknown"}:
        rows.append(
            {
                "package": package,
                "app_label": app_label,
                "static_run_id": static_run_id,
                "gap_key": "static_endpoint_inventory_missing",
                "gap_class": "true_missing_data",
                "severity": "high" if endpoint_status == "missing" else "medium",
                "current_value": endpoint_status,
                "expected_value": "present",
                "source_surface": "static_dynamic_plan/network_targets",
                "recommended_followup": "repair_static_enrichment",
            }
        )
    if not any(bool((run.get("corroboration") or {}).get("enriched_domain_metadata_present")) for run in runs):
        rows.append(
            {
                "package": package,
                "app_label": app_label,
                "static_run_id": static_run_id,
                "gap_key": "enriched_domain_metadata_missing",
                "gap_class": "not_yet_supported",
                "severity": "high",
                "current_value": "missing",
                "expected_value": "present",
                "source_surface": "static_dynamic_plan/network_targets/domain_sources",
                "recommended_followup": "repair_static_enrichment",
            }
        )
    if any(_safe_int((run.get("corroboration") or {}).get("actionable_static_domain_rows")) > 0 for run in runs) and not any(
        _safe_int((run.get("corroboration") or {}).get("corroborated_actionable_domains")) > 0 for run in runs
    ):
        rows.append(
            {
                "package": package,
                "app_label": app_label,
                "static_run_id": static_run_id,
                "gap_key": "actionable_corroboration_missing",
                "gap_class": "not_yet_supported",
                "severity": "medium",
                "current_value": "0 corroborated actionable domains",
                "expected_value": ">=1 corroborated actionable domain when actionable static domains exist",
                "source_surface": "static_dynamic_overlap",
                "recommended_followup": "repair_static_enrichment",
            }
        )
    provider_status = _provider_authority_status(join_row)
    if provider_status == "join_gap":
        rows.append(
            {
                "package": package,
                "app_label": app_label,
                "static_run_id": static_run_id,
                "gap_key": "provider_authority_join_gap",
                "gap_class": "join_bug",
                "severity": "medium",
                "current_value": "0 persisted provider authorities",
                "expected_value": "provider authorities present when provider surface is exported/persisted",
                "source_surface": "static_provider_acl",
                "recommended_followup": "review_static_provider_join",
            }
        )
    if any(_safe_int(run.get("unresolved_service_count")) > 0 for run in runs):
        rows.append(
            {
                "package": package,
                "app_label": app_label,
                "static_run_id": static_run_id,
                "gap_key": "service_mapping_gaps",
                "gap_class": "true_missing_data",
                "severity": "medium",
                "current_value": str(sum(_safe_int(run.get("unresolved_service_count")) for run in runs)),
                "expected_value": "0 unresolved service rows",
                "source_surface": "pcap_report/service_context",
                "recommended_followup": "repair_service_mapping",
            }
        )
    if any(
        _norm_text((run.get("pcap_info") or {}).get("pcap_failure_detail"))
        and _safe_int((run.get("telemetry") or {}).get("netstats_observed_bytes")) > 0
        for run in runs
    ):
        rows.append(
            {
                "package": package,
                "app_label": app_label,
                "static_run_id": static_run_id,
                "gap_key": "pcap_capture_gap",
                "gap_class": "true_missing_data",
                "severity": "high",
                "current_value": "netstats traffic observed but PCAP missing/empty in at least one run",
                "expected_value": "PCAP available when traffic is observed",
                "source_surface": "pcapdroid_capture + telemetry",
                "recommended_followup": "recollect_capture",
            }
        )
    if any(getattr(run.get("phase"), "timeline_available", False) for run in runs):
        rows.append(
            {
                "package": package,
                "app_label": app_label,
                "static_run_id": static_run_id,
                "gap_key": "phase_service_attribution_not_supported",
                "gap_class": "not_yet_supported",
                "severity": "low",
                "current_value": "timeline and transport only",
                "expected_value": "phase-aware service/signal attribution",
                "source_surface": "interaction_timeline + phase_packet_transport_summary",
                "recommended_followup": "defer_phase_service_attribution",
            }
        )
    return rows


def _service_mapping_gap_rows(runs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    aggregate: dict[tuple[str, str], dict[str, Any]] = {}
    for run in runs:
        if not run.get("valid_pack"):
            continue
        package = str(run["package"])
        app_label = str(run["app_label"])
        service_context = run.get("service_context") if isinstance(run.get("service_context"), Mapping) else {}
        for row in service_context.get("unresolved_domains") or []:
            if not isinstance(row, Mapping):
                continue
            domain = _norm_text(row.get("domain")).lower()
            if not domain:
                continue
            key = (package, domain)
            slot = aggregate.setdefault(
                key,
                {
                    "package": package,
                    "app_label": app_label,
                    "domain": domain,
                    "root_domain": _norm_text(row.get("root_domain")) or _root_domain(domain),
                    "observed_count": 0,
                    "gap_type": "service_unresolved",
                    "suggested_service_key": "",
                    "confidence": "low",
                    "recommended_action": "repair_service_mapping",
                },
            )
            slot["observed_count"] = int(slot["observed_count"]) + _safe_int(row.get("total_hits"))
    return sorted(aggregate.values(), key=lambda row: (row["package"], -int(row["observed_count"]), row["domain"]))


def _static_enrichment_gap_rows(
    package_runs: dict[str, list[dict[str, Any]]],
    join_rows: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for package in sorted(package_runs):
        runs = package_runs[package]
        app_label = str(runs[0]["app_label"])
        join_row = join_rows.get(package) if isinstance(join_rows, Mapping) else None
        static_run_id = str((join_row or {}).get("static_run_id") or "")
        endpoint_status = _norm_text((join_row or {}).get("static_endpoint_inventory_status") or "unknown")
        plan_present = any(bool(run.get("plan")) for run in runs)
        enriched = any(bool((run.get("corroboration") or {}).get("enriched_domain_metadata_present")) for run in runs)
        actionable = any(_safe_int((run.get("corroboration") or {}).get("corroborated_actionable_domains")) > 0 for run in runs)
        if endpoint_status == "present" and enriched and actionable:
            continue
        if not plan_present:
            gap_type = "static_plan_missing"
            action = "repair_static_enrichment"
        elif endpoint_status in {"missing", "unknown"}:
            gap_type = "static_endpoint_inventory_missing"
            action = "repair_static_enrichment"
        elif not enriched:
            gap_type = "enriched_domain_metadata_missing"
            action = "repair_static_enrichment"
        else:
            gap_type = "actionable_corroboration_missing"
            action = "repair_static_enrichment"
        rows.append(
            {
                "package": package,
                "app_label": app_label,
                "static_run_id": static_run_id,
                "plan_present": int(plan_present),
                "endpoint_inventory_status": endpoint_status,
                "enriched_domain_metadata_present": int(enriched),
                "actionable_corroboration_present": int(actionable),
                "gap_type": gap_type,
                "recommended_action": action,
            }
        )
    return rows


def _phase_coverage_rows(runs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for run in runs:
        phase = run["phase"]
        rows.append(
            {
                "run_id": run["run_id"],
                "package": run["package"],
                "app_label": run["app_label"],
                "run_profile": run["run_profile"],
                "template_id": phase.template_id or "",
                "timeline_available": int(bool(phase.timeline_available)),
                "timeline_complete": int(bool(phase.timeline_complete)),
                "phase_count": int(phase.phase_count),
                "transport_phase_rows": int(phase.transport_phase_rows),
                "phase_attribution_status": phase.phase_attribution_status,
                "recommended_action": phase.recommended_action,
            }
        )
    return rows


def _template_label(package_name: str) -> str:
    from scytaledroid.DynamicAnalysis.scenarios.manual_templates import requested_script_template

    template_id = str(requested_script_template(package_name=package_name) or "").strip().lower()
    if template_id in {"", "unknown"}:
        return "none"
    if template_id == "news_reader_basic_v1":
        return "news"
    if template_id in {
        "facebook_basic_v2",
        "x_twitter_full_session_v1",
        "tiktok_basic_v1",
        "tiktok_basic_v2",
        "social_feed_basic_v2",
        "social_messaging_basic_v1",
        "snapchat_basic_v1",
        "whatsapp_idle_v1",
        "whatsapp_text_v1",
        "whatsapp_voice_v1",
        "whatsapp_video_v1",
        "messaging_idle_v1",
        "messaging_text_v1",
        "messaging_voice_v1",
        "messaging_video_v1",
        "messaging_call_basic_v1",
    }:
        return "acct"
    return "generic"


def _top_gap_for_app(
    *,
    baseline_valid_count: int,
    manual_valid_count: int,
    pcap_failure_count: int,
    static_endpoint_inventory_status: str,
    static_plan_enriched: bool,
    unresolved_service_total: int,
    provider_authority_status: str,
    scripted_phase_available: bool,
    template_label: str,
) -> str:
    if pcap_failure_count > 0 and baseline_valid_count + manual_valid_count == 0:
        return "capture_problem"
    if baseline_valid_count < 3:
        return "needs_baseline_runs"
    if manual_valid_count < 2:
        return "needs_manual_runs"
    if template_label != "none" and not scripted_phase_available:
        return "needs_scripted_validation"
    if static_endpoint_inventory_status != "present" or not static_plan_enriched:
        return "needs_static_enrichment"
    if unresolved_service_total > 0:
        return "needs_service_mapping"
    if provider_authority_status == "join_gap":
        return "provider_authority_join_gap"
    return "paper_ready"


def _recommend_for_app(
    *,
    package: str,
    app_label: str,
    join_row: Mapping[str, Any] | None,
    metrics: Mapping[str, Any],
) -> dict[str, Any]:
    template_label = _template_label(package)
    baseline_valid_count = int(metrics["baseline_valid_count"])
    manual_valid_count = int(metrics["manual_valid_count"])
    scripted_valid_count = int(metrics["scripted_valid_count"])
    pcap_failure_count = int(metrics["pcap_failure_count"])
    unresolved_service_total = int(metrics["unresolved_service_total"])
    static_endpoint_inventory_status = str(metrics["static_endpoint_inventory_status"])
    static_plan_enriched = bool(metrics["static_plan_enriched"])
    scripted_phase_available = bool(metrics["scripted_phase_available"])
    next_action = "review"
    recommended_template = ""
    recommended_phase = ""
    priority = "medium"
    reason = "review dynamic evidence manually"
    expected_observation = "clarify current evidence posture"
    evidence_source = "audit"
    if pcap_failure_count > 0 and int(metrics["valid_run_count"]) == 0:
        next_action = "recollect_capture"
        priority = "high"
        reason = "network telemetry exists but PCAP evidence is failing or absent"
        expected_observation = "valid PCAP artifact with parseable network evidence"
        evidence_source = "capture_failure_audit"
    elif baseline_valid_count < 3:
        next_action = "baseline"
        priority = "high"
        reason = f"baseline quota incomplete ({baseline_valid_count}/3)"
        expected_observation = "stable idle/background network baseline"
        evidence_source = "quota_state"
    elif manual_valid_count < 2:
        next_action = "manual_interaction"
        priority = "high"
        reason = f"manual interaction quota incomplete ({manual_valid_count}/2)"
        expected_observation = "feature-triggered provider and signal activation beyond baseline"
        evidence_source = "quota_state"
    elif template_label != "none" and not scripted_phase_available:
        next_action = "scripted_interaction"
        recommended_template = "news_reader_basic_v1" if template_label == "news" else template_label
        recommended_phase = "open_article" if template_label == "news" else "template_guided"
        priority = "medium"
        reason = "scripted template exists but no valid scripted phase coverage is present"
        expected_observation = "phase-bounded dynamic behavior under a repeatable template"
        evidence_source = "phase_coverage_audit"
    elif static_endpoint_inventory_status != "present" or not static_plan_enriched:
        next_action = "repair_static_enrichment"
        priority = "high"
        reason = "static endpoint or enriched domain context is incomplete"
        expected_observation = "richer static hypotheses embedded into dynamic plans"
        evidence_source = "static_bridge_gap"
    elif unresolved_service_total > 0:
        next_action = "repair_service_mapping"
        priority = "medium"
        reason = f"{unresolved_service_total} unresolved service observations remain"
        expected_observation = "resolved provider/service ownership for observed domains"
        evidence_source = "service_mapping_gap"
    elif bool((join_row or {}).get("uses_cleartext_traffic")) and _safe_int((join_row or {}).get("static_http_endpoint_root_count")) >= 1:
        next_action = "manual_interaction"
        priority = "low"
        reason = "cleartext is statically allowed and HTTP-like endpoints are present"
        expected_observation = "confirm whether runtime traffic matches static network policy"
        evidence_source = "network_policy_surface"
    elif _safe_int((join_row or {}).get("sdk_tracker_overlap_count")) > 0 and _safe_int((join_row or {}).get("dynamic_signal_count")) <= 1:
        next_action = "manual_interaction"
        priority = "low"
        reason = "static tracker/SDK indicators are present but dynamic signal activation is sparse"
        expected_observation = "feature-triggered third-party provider and signal activation"
        evidence_source = "sdk_tracker_surface"
    safety_notes = (
        "No exploit behavior, bypass logic, login automation, private content capture, MITM, root, Frida, or TLS decryption."
    )
    return {
        "package": package,
        "app_label": app_label,
        "recommended_run_intent": next_action,
        "recommended_template": recommended_template,
        "recommended_phase": recommended_phase,
        "recommendation_priority": priority,
        "reason": reason,
        "expected_observation": expected_observation,
        "safety_notes": safety_notes,
        "evidence_source": evidence_source,
    }


def _readiness_tier(
    *,
    avg_quality: float,
    baseline_valid_count: int,
    manual_valid_count: int,
    static_plan_enriched: bool,
    static_endpoint_inventory_status: str,
    unresolved_service_total: int,
    pcap_failure_count: int,
    valid_run_count: int,
    scripted_phase_available: bool,
    template_label: str,
) -> str:
    if valid_run_count == 0 and pcap_failure_count > 0:
        return "capture_problem"
    if valid_run_count == 0 and pcap_failure_count == 0:
        return "excluded_or_invalid"
    if baseline_valid_count < 3:
        return "needs_baseline_runs"
    if manual_valid_count < 2:
        return "needs_manual_runs"
    if (template_label != "none") and not scripted_phase_available:
        return "needs_scripted_validation"
    if static_endpoint_inventory_status != "present" or not static_plan_enriched:
        return "needs_static_enrichment"
    if unresolved_service_total > 0:
        return "needs_service_mapping"
    if avg_quality < 60.0 and pcap_failure_count > 0:
        return "capture_problem"
    if avg_quality >= 75.0:
        return "paper_ready"
    return "needs_service_mapping"


def _app_readiness_rows(
    *,
    package_runs: dict[str, list[dict[str, Any]]],
    scored_runs: Sequence[Mapping[str, Any]],
    join_rows: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    scored_by_run = {str(row["run_id"]): row for row in scored_runs}
    readiness_rows: list[dict[str, Any]] = []
    bridge_gap_rows: list[dict[str, Any]] = []
    recommendation_rows: list[dict[str, Any]] = []
    stability_rows: list[dict[str, Any]] = []
    for package in sorted(package_runs):
        runs = package_runs[package]
        app_label = str(runs[0]["app_label"])
        join_row = join_rows.get(package) if isinstance(join_rows, Mapping) else None
        valid_runs = [run for run in runs if run.get("valid_pack")]
        invalid_runs = [run for run in runs if not run.get("valid_pack")]
        baseline_runs = [run for run in valid_runs if run.get("interaction_mode") == "baseline"]
        manual_runs = [run for run in valid_runs if run.get("interaction_mode") == "manual"]
        scripted_runs = [run for run in valid_runs if run.get("interaction_mode") == "scripted"]
        baseline_valid_count = sum(1 for run in valid_runs if run.get("interaction_mode") == "baseline")
        manual_valid_count = sum(1 for run in valid_runs if run.get("interaction_mode") == "manual")
        scripted_valid_count = sum(1 for run in valid_runs if run.get("interaction_mode") == "scripted")
        avg_quality = (
            sum(float(scored_by_run[run["run_id"]]["dynamic_evidence_quality_score"]) for run in valid_runs) / float(len(valid_runs))
            if valid_runs
            else 0.0
        )
        pcap_failure_count = sum(1 for run in runs if _norm_text((run.get("pcap_info") or {}).get("pcap_failure_detail")))
        unresolved_service_total = sum(_safe_int(run.get("unresolved_service_count")) for run in valid_runs)
        unresolved_signal_total = sum(_safe_int(run.get("unresolved_signal_count")) for run in valid_runs)
        service_count_total = sum(_safe_int(run.get("service_count")) for run in valid_runs)
        signal_count_total = sum(_safe_int(run.get("signal_count")) for run in valid_runs)
        service_resolution_rate = None
        if service_count_total + unresolved_service_total > 0:
            service_resolution_rate = service_count_total / float(service_count_total + unresolved_service_total)
        signal_resolution_rate = None
        if signal_count_total + unresolved_signal_total > 0:
            signal_resolution_rate = signal_count_total / float(signal_count_total + unresolved_signal_total)
        static_plan_enriched = any(bool((run.get("corroboration") or {}).get("enriched_domain_metadata_present")) for run in valid_runs)
        static_endpoint_inventory_status = _norm_text((join_row or {}).get("static_endpoint_inventory_status") or "unknown")
        provider_authority_status = _provider_authority_status(join_row)
        baseline_manual_delta_available = bool(baseline_valid_count > 0 and manual_valid_count > 0)
        scripted_phase_available = any(getattr(run.get("phase"), "timeline_available", False) for run in scripted_runs)
        template_label = _template_label(package)
        app_complete = baseline_valid_count >= 3 and manual_valid_count >= 2

        baseline_domain_reproducibility = _pairwise_jaccard([_run_domain_roots(run) for run in baseline_runs])
        baseline_service_reproducibility = _pairwise_jaccard([_run_service_keys(run) for run in baseline_runs])
        baseline_signal_reproducibility = _pairwise_jaccard([_run_signal_keys(run) for run in baseline_runs])
        manual_domain_reproducibility = _pairwise_jaccard([_run_domain_roots(run) for run in manual_runs])
        manual_service_reproducibility = _pairwise_jaccard([_run_service_keys(run) for run in manual_runs])
        manual_signal_reproducibility = _pairwise_jaccard([_run_signal_keys(run) for run in manual_runs])

        baseline_domain_union = set().union(*[_run_domain_roots(run) for run in baseline_runs]) if baseline_runs else set()
        manual_domain_union = set().union(*[_run_domain_roots(run) for run in manual_runs]) if manual_runs else set()
        baseline_service_union = set().union(*[_run_service_keys(run) for run in baseline_runs]) if baseline_runs else set()
        manual_service_union = set().union(*[_run_service_keys(run) for run in manual_runs]) if manual_runs else set()
        baseline_signal_union = set().union(*[_run_signal_keys(run) for run in baseline_runs]) if baseline_runs else set()
        manual_signal_union = set().union(*[_run_signal_keys(run) for run in manual_runs]) if manual_runs else set()

        manual_novel_domain_count = len(manual_domain_union - baseline_domain_union)
        manual_novel_service_count = len(manual_service_union - baseline_service_union)
        manual_novel_signal_count = len(manual_signal_union - baseline_signal_union)
        baseline_manual_domain_overlap = (
            _set_jaccard(baseline_domain_union, manual_domain_union)
            if baseline_domain_union and manual_domain_union
            else None
        )
        baseline_manual_service_overlap = (
            _set_jaccard(baseline_service_union, manual_service_union)
            if baseline_service_union and manual_service_union
            else None
        )
        baseline_manual_signal_overlap = (
            _set_jaccard(baseline_signal_union, manual_signal_union)
            if baseline_signal_union and manual_signal_union
            else None
        )
        dynamic_activation_delta_score = (
            manual_novel_domain_count
            + manual_novel_service_count * 2
            + manual_novel_signal_count * 2
        )

        first_party_hits = sum(
            _safe_int(service.get("total_hits"))
            for run in valid_runs
            for service in (run.get("service_rows") or [])
            if isinstance(service, Mapping) and _norm_text(service.get("owner_class")) == "first_party"
        )
        third_party_hits = sum(
            _safe_int(service.get("total_hits"))
            for run in valid_runs
            for service in (run.get("service_rows") or [])
            if isinstance(service, Mapping) and _norm_text(service.get("owner_class")) == "third_party"
        )
        third_party_first_party_hit_ratio = (
            round(third_party_hits / float(first_party_hits), 4)
            if first_party_hits > 0
            else (999.0 if third_party_hits > 0 else "")
        )
        visibility_loss_run_count = sum(1 for run in valid_runs if bool(run.get("visibility_loss_flag")))

        notes: list[str] = []
        if baseline_domain_reproducibility is not None and baseline_domain_reproducibility < 0.5:
            notes.append("baseline_domains_unstable")
        if baseline_service_reproducibility is not None and baseline_service_reproducibility < 0.5:
            notes.append("baseline_services_unstable")
        if manual_novel_service_count > 0 or manual_novel_signal_count > 0:
            notes.append("manual_activation_expands_runtime_surface")
        if visibility_loss_run_count > 0:
            notes.append("visibility_loss_present")
        reproducibility_note = "; ".join(notes)
        evidence_base_score = min(
            READINESS_WEIGHTS["evidence_base"],
            round(
                (
                    min(len(valid_runs), 5) / 5.0 * 15.0
                    + min(avg_quality, 100.0) / 100.0 * 15.0
                    + (5.0 if len(invalid_runs) == 0 else max(0.0, 5.0 - float(len(invalid_runs))))
                )
            ),
        )
        coverage_completeness_score = min(
            READINESS_WEIGHTS["coverage_completeness"],
            round(
                min(baseline_valid_count, 3) / 3.0 * 15.0
                + min(manual_valid_count, 2) / 2.0 * 10.0
            ),
        )
        static_bridge_completeness_score = min(
            READINESS_WEIGHTS["static_bridge_completeness"],
            round(
                (10.0 if static_endpoint_inventory_status == "present" else 0.0)
                + (5.0 if static_plan_enriched else 0.0)
                + (5.0 if provider_authority_status == "present" else 0.0)
            ),
        )
        resolution_robustness_score = min(
            READINESS_WEIGHTS["resolution_robustness"],
            round(
                ((service_resolution_rate if service_resolution_rate is not None else 0.0) * 6.0)
                + ((signal_resolution_rate if signal_resolution_rate is not None else 0.0) * 4.0)
            ),
        )
        capture_reliability_score = min(
            READINESS_WEIGHTS["capture_reliability"],
            round(
                10.0
                if pcap_failure_count == 0
                else max(0.0, 10.0 - float(pcap_failure_count * 3))
            ),
        )
        readiness_score = float(
            evidence_base_score
            + coverage_completeness_score
            + static_bridge_completeness_score
            + resolution_robustness_score
            + capture_reliability_score
        )
        readiness_tier = _readiness_tier(
            avg_quality=avg_quality,
            baseline_valid_count=baseline_valid_count,
            manual_valid_count=manual_valid_count,
            static_plan_enriched=static_plan_enriched,
            static_endpoint_inventory_status=static_endpoint_inventory_status,
            unresolved_service_total=unresolved_service_total,
            pcap_failure_count=pcap_failure_count,
            valid_run_count=len(valid_runs),
            scripted_phase_available=scripted_phase_available,
            template_label=template_label,
        )
        top_gap = _top_gap_for_app(
            baseline_valid_count=baseline_valid_count,
            manual_valid_count=manual_valid_count,
            pcap_failure_count=pcap_failure_count,
            static_endpoint_inventory_status=static_endpoint_inventory_status,
            static_plan_enriched=static_plan_enriched,
            unresolved_service_total=unresolved_service_total,
            provider_authority_status=provider_authority_status,
            scripted_phase_available=scripted_phase_available,
            template_label=template_label,
        )
        recommendation = _recommend_for_app(
            package=package,
            app_label=app_label,
            join_row=join_row,
            metrics={
                "valid_run_count": len(valid_runs),
                "baseline_valid_count": baseline_valid_count,
                "manual_valid_count": manual_valid_count,
                "scripted_valid_count": scripted_valid_count,
                "pcap_failure_count": pcap_failure_count,
                "unresolved_service_total": unresolved_service_total,
                "static_endpoint_inventory_status": static_endpoint_inventory_status,
                "static_plan_enriched": static_plan_enriched,
                "scripted_phase_available": scripted_phase_available,
            },
        )
        readiness_rows.append(
            {
                "package": package,
                "app_label": app_label,
                "app_profile": _norm_text(runs[0].get("app_profile")) or "unknown",
                "valid_run_count": len(valid_runs),
                "invalid_run_count": len(invalid_runs),
                "baseline_valid_count": baseline_valid_count,
                "manual_valid_count": manual_valid_count,
                "scripted_valid_count": scripted_valid_count,
                "quota_progress": f"{min(baseline_valid_count + manual_valid_count, 5)}/5",
                "app_complete": int(app_complete),
                "avg_evidence_quality_score": round(avg_quality, 2),
                "pcap_failure_count": pcap_failure_count,
                "service_resolution_rate": round(service_resolution_rate, 4) if service_resolution_rate is not None else "",
                "signal_resolution_rate": round(signal_resolution_rate, 4) if signal_resolution_rate is not None else "",
                "baseline_manual_delta_available": int(baseline_manual_delta_available),
                "scripted_phase_available": int(scripted_phase_available),
                "baseline_domain_reproducibility": round(baseline_domain_reproducibility, 4) if baseline_domain_reproducibility is not None else "",
                "baseline_service_reproducibility": round(baseline_service_reproducibility, 4) if baseline_service_reproducibility is not None else "",
                "baseline_signal_reproducibility": round(baseline_signal_reproducibility, 4) if baseline_signal_reproducibility is not None else "",
                "manual_domain_reproducibility": round(manual_domain_reproducibility, 4) if manual_domain_reproducibility is not None else "",
                "manual_service_reproducibility": round(manual_service_reproducibility, 4) if manual_service_reproducibility is not None else "",
                "manual_signal_reproducibility": round(manual_signal_reproducibility, 4) if manual_signal_reproducibility is not None else "",
                "manual_novel_domain_count": manual_novel_domain_count,
                "manual_novel_service_count": manual_novel_service_count,
                "manual_novel_signal_count": manual_novel_signal_count,
                "baseline_manual_domain_overlap": round(baseline_manual_domain_overlap, 4) if baseline_manual_domain_overlap is not None else "",
                "baseline_manual_service_overlap": round(baseline_manual_service_overlap, 4) if baseline_manual_service_overlap is not None else "",
                "baseline_manual_signal_overlap": round(baseline_manual_signal_overlap, 4) if baseline_manual_signal_overlap is not None else "",
                "dynamic_activation_delta_score": dynamic_activation_delta_score,
                "third_party_first_party_hit_ratio": third_party_first_party_hit_ratio,
                "visibility_loss_run_count": visibility_loss_run_count,
                "reproducibility_note": reproducibility_note,
                "static_plan_enriched": int(static_plan_enriched),
                "static_endpoint_inventory_status": static_endpoint_inventory_status,
                "provider_authority_status": provider_authority_status,
                "research_readiness_score": round(readiness_score, 2),
                "research_readiness_tier": readiness_tier,
                "top_gap": top_gap,
                "next_recommended_action": recommendation["recommended_run_intent"],
            }
        )
        bridge_gap_rows.extend(
            _bridge_gaps_for_package(
                package=package,
                app_label=app_label,
                join_row=join_row,
                runs=runs,
            )
        )
        recommendation_rows.append(recommendation)
        stability_rows.append(
            {
                "package": package,
                "app_label": app_label,
                "app_profile": _norm_text(runs[0].get("app_profile")) or "unknown",
                "baseline_valid_count": baseline_valid_count,
                "manual_valid_count": manual_valid_count,
                "scripted_valid_count": scripted_valid_count,
                "baseline_domain_reproducibility": round(baseline_domain_reproducibility, 4) if baseline_domain_reproducibility is not None else "",
                "baseline_service_reproducibility": round(baseline_service_reproducibility, 4) if baseline_service_reproducibility is not None else "",
                "baseline_signal_reproducibility": round(baseline_signal_reproducibility, 4) if baseline_signal_reproducibility is not None else "",
                "manual_domain_reproducibility": round(manual_domain_reproducibility, 4) if manual_domain_reproducibility is not None else "",
                "manual_service_reproducibility": round(manual_service_reproducibility, 4) if manual_service_reproducibility is not None else "",
                "manual_signal_reproducibility": round(manual_signal_reproducibility, 4) if manual_signal_reproducibility is not None else "",
                "baseline_manual_domain_overlap": round(baseline_manual_domain_overlap, 4) if baseline_manual_domain_overlap is not None else "",
                "baseline_manual_service_overlap": round(baseline_manual_service_overlap, 4) if baseline_manual_service_overlap is not None else "",
                "baseline_manual_signal_overlap": round(baseline_manual_signal_overlap, 4) if baseline_manual_signal_overlap is not None else "",
                "manual_novel_domain_count": manual_novel_domain_count,
                "manual_novel_service_count": manual_novel_service_count,
                "manual_novel_signal_count": manual_novel_signal_count,
                "dynamic_activation_delta_score": dynamic_activation_delta_score,
                "third_party_first_party_hit_ratio": third_party_first_party_hit_ratio,
                "visibility_loss_run_count": visibility_loss_run_count,
                "reproducibility_note": reproducibility_note,
            }
        )
    return readiness_rows, bridge_gap_rows, recommendation_rows, stability_rows


def _capture_failure_rows(runs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for run in runs:
        pcap_info = run.get("pcap_info") if isinstance(run.get("pcap_info"), Mapping) else {}
        detail = _norm_text(pcap_info.get("pcap_failure_detail"))
        if not detail:
            continue
        rows.append(
            {
                "run_id": run["run_id"],
                "package": run["package"],
                "app_label": run["app_label"],
                "pcap_failure_detail": detail,
                "netstats_observed_bytes": _safe_int((run.get("telemetry") or {}).get("netstats_observed_bytes")),
                "pcap_size_bytes": _safe_int(pcap_info.get("pcap_size_bytes")),
                "timeline_available": int(bool(getattr(run.get("phase"), "timeline_available", False))),
                "valid_pack": int(bool(run.get("valid_pack"))),
                "recommended_action": "recollect_capture"
                if _safe_int((run.get("telemetry") or {}).get("netstats_observed_bytes")) > 0
                else "review_capture_environment",
            }
        )
    return rows


def _paper_pattern_rows(
    *,
    readiness_rows: Sequence[Mapping[str, Any]],
    stability_rows: Sequence[Mapping[str, Any]],
    recommendation_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    stability_by_package = {str(row["package"]): row for row in stability_rows}
    recommendation_by_package = {str(row["package"]): row for row in recommendation_rows}
    rows: list[dict[str, Any]] = []
    for readiness in readiness_rows:
        package = str(readiness["package"])
        stability = stability_by_package.get(package, {})
        recommendation = recommendation_by_package.get(package, {})
        baseline_domain_repro = _safe_float(stability.get("baseline_domain_reproducibility"), default=-1.0)
        baseline_service_repro = _safe_float(stability.get("baseline_service_reproducibility"), default=-1.0)
        dynamic_activation_delta = _safe_int(stability.get("dynamic_activation_delta_score"))
        ratio = stability.get("third_party_first_party_hit_ratio")
        third_party_ratio = _safe_float(ratio, default=-1.0) if ratio not in ("", None) else None
        service_resolution_rate = _safe_float(readiness.get("service_resolution_rate"), default=-1.0)
        signal_resolution_rate = _safe_float(readiness.get("signal_resolution_rate"), default=-1.0)

        baseline_instability_flag = (
            (baseline_domain_repro >= 0.0 and baseline_domain_repro < 0.5)
            or (baseline_service_repro >= 0.0 and baseline_service_repro < 0.5)
        )
        manual_activation_expansion_flag = bool(
            _safe_int(readiness.get("manual_valid_count")) > 0 and dynamic_activation_delta >= 3
        )
        third_party_heavy_flag = bool(third_party_ratio is not None and third_party_ratio >= 1.0)
        static_dynamic_coverage_gap_flag = bool(
            _norm_text(readiness.get("static_endpoint_inventory_status")) != "present"
            or _safe_int(readiness.get("static_plan_enriched")) == 0
        )
        service_resolution_gap_flag = bool(
            (service_resolution_rate >= 0.0 and service_resolution_rate < 1.0)
            or (signal_resolution_rate >= 0.0 and signal_resolution_rate < 1.0)
        )
        capture_reliability_gap_flag = _safe_int(readiness.get("pcap_failure_count")) > 0
        scripted_gap_flag = _norm_text(readiness.get("research_readiness_tier")) == "needs_scripted_validation"

        pattern_count = sum(
            1
            for value in (
                baseline_instability_flag,
                manual_activation_expansion_flag,
                third_party_heavy_flag,
                static_dynamic_coverage_gap_flag,
                service_resolution_gap_flag,
                capture_reliability_gap_flag,
                scripted_gap_flag,
            )
            if value
        )
        if capture_reliability_gap_flag or baseline_instability_flag:
            research_priority = "high"
        elif manual_activation_expansion_flag or scripted_gap_flag or service_resolution_gap_flag:
            research_priority = "medium"
        elif static_dynamic_coverage_gap_flag or third_party_heavy_flag:
            research_priority = "medium"
        else:
            research_priority = "low"

        notes = [
            label
            for label, value in (
                ("baseline_instability", baseline_instability_flag),
                ("manual_activation_expansion", manual_activation_expansion_flag),
                ("third_party_heavy", third_party_heavy_flag),
                ("static_dynamic_coverage_gap", static_dynamic_coverage_gap_flag),
                ("service_resolution_gap", service_resolution_gap_flag),
                ("capture_reliability_gap", capture_reliability_gap_flag),
                ("scripted_gap", scripted_gap_flag),
            )
            if value
        ]
        rows.append(
            {
                "package": package,
                "app_label": readiness.get("app_label"),
                "app_profile": _norm_text(readiness.get("app_profile")) or "unknown",
                "avg_evidence_quality_score": readiness.get("avg_evidence_quality_score"),
                "research_readiness_tier": readiness.get("research_readiness_tier"),
                "next_recommended_action": recommendation.get("recommended_run_intent") or readiness.get("next_recommended_action"),
                "baseline_instability_flag": int(baseline_instability_flag),
                "manual_activation_expansion_flag": int(manual_activation_expansion_flag),
                "third_party_heavy_flag": int(third_party_heavy_flag),
                "static_dynamic_coverage_gap_flag": int(static_dynamic_coverage_gap_flag),
                "service_resolution_gap_flag": int(service_resolution_gap_flag),
                "capture_reliability_gap_flag": int(capture_reliability_gap_flag),
                "scripted_gap_flag": int(scripted_gap_flag),
                "dynamic_activation_delta_score": dynamic_activation_delta,
                "third_party_first_party_hit_ratio": ratio if ratio not in (None,) else "",
                "baseline_domain_reproducibility": stability.get("baseline_domain_reproducibility", ""),
                "baseline_service_reproducibility": stability.get("baseline_service_reproducibility", ""),
                "manual_novel_domain_count": stability.get("manual_novel_domain_count", 0),
                "manual_novel_service_count": stability.get("manual_novel_service_count", 0),
                "pattern_flag_count": pattern_count,
                "research_priority": research_priority,
                "pattern_notes": "; ".join(notes),
            }
        )
    return rows


def _paper_pattern_summary_rows(
    *,
    pattern_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in pattern_rows:
        group_key = _norm_text(row.get("app_profile")) or "unknown"
        grouped[group_key].append(row)
    rows: list[dict[str, Any]] = []
    for group_key in sorted(grouped):
        items = grouped[group_key]
        app_count = len(items)
        avg_quality = (
            sum(_safe_float(item.get("avg_evidence_quality_score")) for item in items) / float(app_count)
            if app_count
            else 0.0
        )
        avg_pattern_flags = (
            sum(_safe_int(item.get("pattern_flag_count")) for item in items) / float(app_count)
            if app_count
            else 0.0
        )
        top_action = ""
        action_counter = Counter(_norm_text(item.get("next_recommended_action")) for item in items if _norm_text(item.get("next_recommended_action")))
        if action_counter:
            top_action = sorted(action_counter.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        rows.append(
            {
                "app_profile": group_key,
                "app_count": app_count,
                "avg_evidence_quality_score": round(avg_quality, 2),
                "avg_pattern_flag_count": round(avg_pattern_flags, 2),
                "high_priority_count": sum(1 for item in items if _norm_text(item.get("research_priority")) == "high"),
                "needs_manual_runs_count": sum(1 for item in items if _norm_text(item.get("research_readiness_tier")) == "needs_manual_runs"),
                "needs_scripted_validation_count": sum(1 for item in items if _norm_text(item.get("research_readiness_tier")) == "needs_scripted_validation"),
                "capture_gap_count": sum(_safe_int(item.get("capture_reliability_gap_flag")) for item in items),
                "baseline_instability_count": sum(_safe_int(item.get("baseline_instability_flag")) for item in items),
                "manual_activation_expansion_count": sum(_safe_int(item.get("manual_activation_expansion_flag")) for item in items),
                "service_resolution_gap_count": sum(_safe_int(item.get("service_resolution_gap_flag")) for item in items),
                "scripted_gap_count": sum(_safe_int(item.get("scripted_gap_flag")) for item in items),
                "static_dynamic_coverage_gap_count": sum(_safe_int(item.get("static_dynamic_coverage_gap_flag")) for item in items),
                "third_party_heavy_count": sum(_safe_int(item.get("third_party_heavy_flag")) for item in items),
                "top_recommended_action": top_action,
            }
        )
    return rows


def generate_report(*, output_dir: Path | None = None, overlay_latest_static: bool = False) -> dict[str, Any]:
    root = _dynamic_root()
    run_rows = _collect_run_records(root, overlay_latest_static=overlay_latest_static)
    app_profiles = _load_app_profiles(str(row["package"]) for row in run_rows)
    for row in run_rows:
        package = str(row["package"])
        profile_info = app_profiles.get(package, {})
        display_name = _norm_text(profile_info.get("display_name"))
        if display_name:
            row["app_label"] = display_name
        row["app_profile"] = _norm_text(profile_info.get("profile_key")) or "unknown"
    package_runs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in run_rows:
        package_runs[str(row["package"])].append(row)
    join_rows, _candidate_rows = _build_static_join_and_candidates(package_runs)
    scored_runs = [_score_run(run, join_rows.get(str(run["package"]))) for run in run_rows]
    readiness_rows, bridge_gap_rows, recommendation_rows, stability_rows = _app_readiness_rows(
        package_runs=package_runs,
        scored_runs=scored_runs,
        join_rows=join_rows,
    )
    paper_pattern_rows = _paper_pattern_rows(
        readiness_rows=readiness_rows,
        stability_rows=stability_rows,
        recommendation_rows=recommendation_rows,
    )
    paper_pattern_summary_rows = _paper_pattern_summary_rows(pattern_rows=paper_pattern_rows)
    capture_failure_rows = _capture_failure_rows(run_rows)
    service_gap_rows = _service_mapping_gap_rows(run_rows)
    static_enrichment_rows = _static_enrichment_gap_rows(package_runs, join_rows)
    phase_rows = _phase_coverage_rows(run_rows)

    if output_dir is None:
        output_dir = _REPO_ROOT / "output" / "audit" / "dynamic_deep_audit" / datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
    output_dir.mkdir(parents=True, exist_ok=True)

    run_rows_sorted = sorted(scored_runs, key=lambda row: (str(row["package"]), str(row["run_id"])))
    readiness_rows_sorted = sorted(readiness_rows, key=lambda row: str(row["package"]))
    bridge_gap_rows_sorted = sorted(bridge_gap_rows, key=lambda row: (str(row["package"]), str(row["gap_key"])))
    recommendation_rows_sorted = sorted(recommendation_rows, key=lambda row: str(row["package"]))
    stability_rows_sorted = sorted(stability_rows, key=lambda row: str(row["package"]))
    paper_pattern_rows_sorted = sorted(paper_pattern_rows, key=lambda row: str(row["package"]))
    paper_pattern_summary_rows_sorted = sorted(paper_pattern_summary_rows, key=lambda row: str(row["app_profile"]))
    capture_failure_rows_sorted = sorted(capture_failure_rows, key=lambda row: (str(row["package"]), str(row["run_id"])))
    service_gap_rows_sorted = sorted(service_gap_rows, key=lambda row: (str(row["package"]), -int(row["observed_count"]), str(row["domain"])))
    static_enrichment_rows_sorted = sorted(static_enrichment_rows, key=lambda row: str(row["package"]))
    phase_rows_sorted = sorted(phase_rows, key=lambda row: (str(row["package"]), str(row["run_id"])))

    _write_csv(output_dir / "run_evidence_quality.csv", run_rows_sorted)
    _write_csv(output_dir / "app_dynamic_readiness.csv", readiness_rows_sorted)
    _write_csv(output_dir / "static_dynamic_bridge_gaps.csv", bridge_gap_rows_sorted)
    _write_csv(output_dir / "static_guided_dynamic_recommendations.csv", recommendation_rows_sorted)
    _write_csv(output_dir / "behavioral_stability_audit.csv", stability_rows_sorted)
    _write_csv(output_dir / "paper_pattern_matrix.csv", paper_pattern_rows_sorted)
    _write_csv(output_dir / "paper_pattern_summary.csv", paper_pattern_summary_rows_sorted)
    _write_csv(output_dir / "capture_failure_audit.csv", capture_failure_rows_sorted)
    _write_csv(output_dir / "service_mapping_gap_audit.csv", service_gap_rows_sorted)
    _write_csv(output_dir / "static_enrichment_gap_audit.csv", static_enrichment_rows_sorted)
    _write_csv(output_dir / "phase_coverage_audit.csv", phase_rows_sorted)

    summary = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "dynamic_root": str(root.resolve()),
        "plan_analysis_mode": "overlay_latest_static" if overlay_latest_static else "embedded_plan",
        "runs_scanned": len(run_rows_sorted),
        "valid_runs": sum(1 for row in run_rows_sorted if int(row["valid_pack"]) == 1),
        "invalid_or_skipped_runs": sum(1 for row in run_rows_sorted if int(row["valid_pack"]) != 1),
        "apps_scanned": len(readiness_rows_sorted),
        "quality_tier_counts": dict(sorted(Counter(str(row["dynamic_evidence_quality_tier"]) for row in run_rows_sorted).items())),
        "readiness_tier_counts": dict(sorted(Counter(str(row["research_readiness_tier"]) for row in readiness_rows_sorted).items())),
        "top_gap_counts": dict(sorted(Counter(str(row["top_gap"]) for row in readiness_rows_sorted).items())),
        "capture_failure_counts": dict(sorted(Counter(str(row["pcap_failure_detail"]) for row in capture_failure_rows_sorted).items())),
        "service_mapping_gap_counts": dict(sorted(Counter(str(row["gap_type"]) for row in service_gap_rows_sorted).items())),
        "static_enrichment_gap_counts": dict(sorted(Counter(str(row["gap_type"]) for row in static_enrichment_rows_sorted).items())),
        "phase_coverage_counts": dict(sorted(Counter(str(row["phase_attribution_status"]) for row in phase_rows_sorted).items())),
        "reproducibility_band_counts": {
            "baseline_domains_lt_0_5": sum(
                1
                for row in stability_rows_sorted
                if row.get("baseline_domain_reproducibility") not in ("", None)
                and float(row["baseline_domain_reproducibility"]) < 0.5
            ),
            "baseline_services_lt_0_5": sum(
                1
                for row in stability_rows_sorted
                if row.get("baseline_service_reproducibility") not in ("", None)
                and float(row["baseline_service_reproducibility"]) < 0.5
            ),
            "manual_activation_delta_gt_0": sum(
                1 for row in stability_rows_sorted if _safe_int(row.get("dynamic_activation_delta_score")) > 0
            ),
        },
        "pattern_flag_counts": {
            "baseline_instability": sum(_safe_int(row.get("baseline_instability_flag")) for row in paper_pattern_rows_sorted),
            "manual_activation_expansion": sum(_safe_int(row.get("manual_activation_expansion_flag")) for row in paper_pattern_rows_sorted),
            "third_party_heavy": sum(_safe_int(row.get("third_party_heavy_flag")) for row in paper_pattern_rows_sorted),
            "static_dynamic_coverage_gap": sum(_safe_int(row.get("static_dynamic_coverage_gap_flag")) for row in paper_pattern_rows_sorted),
            "service_resolution_gap": sum(_safe_int(row.get("service_resolution_gap_flag")) for row in paper_pattern_rows_sorted),
            "capture_reliability_gap": sum(_safe_int(row.get("capture_reliability_gap_flag")) for row in paper_pattern_rows_sorted),
            "scripted_gap": sum(_safe_int(row.get("scripted_gap_flag")) for row in paper_pattern_rows_sorted),
        },
        "profile_group_counts": {
            str(row["app_profile"]): _safe_int(row["app_count"])
            for row in paper_pattern_summary_rows_sorted
        },
        "score_weights": {
            "dynamic_evidence_quality": QUALITY_WEIGHTS,
            "dynamic_readiness": READINESS_WEIGHTS,
        },
        "tier_definitions": {
            "dynamic_evidence_quality": QUALITY_TIER_DEFINITIONS,
        },
        "known_limitations": KNOWN_LIMITATIONS,
        "output_files": {
            "run_evidence_quality_csv": str((output_dir / "run_evidence_quality.csv").resolve()),
            "app_dynamic_readiness_csv": str((output_dir / "app_dynamic_readiness.csv").resolve()),
            "static_dynamic_bridge_gaps_csv": str((output_dir / "static_dynamic_bridge_gaps.csv").resolve()),
            "static_guided_dynamic_recommendations_csv": str((output_dir / "static_guided_dynamic_recommendations.csv").resolve()),
            "behavioral_stability_audit_csv": str((output_dir / "behavioral_stability_audit.csv").resolve()),
            "paper_pattern_matrix_csv": str((output_dir / "paper_pattern_matrix.csv").resolve()),
            "paper_pattern_summary_csv": str((output_dir / "paper_pattern_summary.csv").resolve()),
            "capture_failure_audit_csv": str((output_dir / "capture_failure_audit.csv").resolve()),
            "service_mapping_gap_audit_csv": str((output_dir / "service_mapping_gap_audit.csv").resolve()),
            "static_enrichment_gap_audit_csv": str((output_dir / "static_enrichment_gap_audit.csv").resolve()),
            "phase_coverage_audit_csv": str((output_dir / "phase_coverage_audit.csv").resolve()),
            "summary_json": str((output_dir / "summary.json").resolve()),
        },
        "row_counts": {
            "run_evidence_quality": len(run_rows_sorted),
            "app_dynamic_readiness": len(readiness_rows_sorted),
            "static_dynamic_bridge_gaps": len(bridge_gap_rows_sorted),
            "static_guided_dynamic_recommendations": len(recommendation_rows_sorted),
            "behavioral_stability_audit": len(stability_rows_sorted),
            "paper_pattern_matrix": len(paper_pattern_rows_sorted),
            "paper_pattern_summary": len(paper_pattern_summary_rows_sorted),
            "capture_failure_audit": len(capture_failure_rows_sorted),
            "service_mapping_gap_audit": len(service_gap_rows_sorted),
            "static_enrichment_gap_audit": len(static_enrichment_rows_sorted),
            "phase_coverage_audit": len(phase_rows_sorted),
        },
        "top_recommended_actions": dict(
            sorted(Counter(str(row["recommended_run_intent"]) for row in recommendation_rows_sorted).items())
        ),
    }
    if overlay_latest_static:
        embedded_enriched = sum(
            1
            for run in run_rows
            if bool(((run.get("embedded_corroboration") or {}).get("enriched_domain_metadata_present")))
        )
        overlay_enriched = sum(
            1
            for run in run_rows
            if bool(((run.get("overlay_corroboration") or {}).get("enriched_domain_metadata_present")))
        )
        embedded_actionable = sum(
            1
            for run in run_rows
            if _safe_int((run.get("embedded_corroboration") or {}).get("corroborated_actionable_domains")) > 0
        )
        overlay_actionable = sum(
            1
            for run in run_rows
            if _safe_int((run.get("overlay_corroboration") or {}).get("corroborated_actionable_domains")) > 0
        )
        overlay_actionable_static = sum(
            1
            for run in run_rows
            if _safe_int((run.get("overlay_corroboration") or {}).get("actionable_static_domain_rows")) > 0
        )
        summary.update(
            {
                "runs_using_overlay_latest_static": sum(
                    1 for run in run_rows if _norm_text(run.get("plan_source")) == "overlay_latest_static"
                ),
                "embedded_stale_plan_runs": sum(1 for run in run_rows if bool(run.get("embedded_plan_stale"))),
                "runs_with_enriched_domain_metadata_embedded": embedded_enriched,
                "runs_with_enriched_domain_metadata_overlay": overlay_enriched,
                "runs_with_actionable_corroboration_embedded": embedded_actionable,
                "runs_with_actionable_corroboration_overlay": overlay_actionable,
                "actionable_corroboration_rate_overlay": (
                    overlay_actionable / float(overlay_actionable_static)
                    if overlay_actionable_static
                    else None
                ),
            }
        )
        summary["known_limitations"] = list(summary.get("known_limitations") or []) + [
            "overlay_latest_static is a read-only reanalysis mode and does not mutate historical embedded plans inside dynamic evidence packs.",
        ]
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    summary = generate_report(output_dir=output_dir, overlay_latest_static=bool(args.overlay_latest_static))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
