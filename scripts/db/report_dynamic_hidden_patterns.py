#!/usr/bin/env python3
"""Read-only hidden-pattern exports joining static Android surface with dynamic evidence packs."""

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
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    return parser


def _dynamic_root() -> Path:
    from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root

    return dynamic_evidence_root()


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


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _norm_text(value: object) -> str:
    return str(value or "").strip()


def _norm_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    text = _norm_text(value).lower()
    return text in {"1", "true", "yes", "on"}


def _root_domain(host: str) -> str:
    from scytaledroid.DynamicAnalysis.domain_context import root_domain

    return root_domain(host)


def _normalize_domain(value: object) -> str:
    from scytaledroid.DynamicAnalysis.domain_context import normalize_domain

    return normalize_domain(value)


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


def _evidence_validity(
    run_dir: Path,
    manifest: dict[str, Any],
    report: dict[str, Any],
    *,
    verify_by_run: dict[str, dict[str, Any]],
) -> tuple[bool, str]:
    from scripts.db.report_dynamic_paper_exports import (
        _evidence_status,
        _summarize_missing_artifacts,
    )
    run_id = str(manifest.get("dynamic_run_id") or run_dir.name)
    verify_row = verify_by_run.get(run_id, {})
    pcap_present, missing_artifacts = _summarize_missing_artifacts(run_dir, manifest, verify_row.get("issues") or [])
    evidence_status = _evidence_status(
        verify_row=verify_row,
        report_status=str(report.get("report_status") or "missing"),
        missing_artifacts=missing_artifacts,
    )
    valid_pack = bool(
        verify_row.get("valid_dataset_run") is True
        and str(report.get("report_status") or "") == "ok"
        and pcap_present
    )
    return valid_pack, evidence_status


def _static_endpoint_features(plan: dict[str, Any]) -> dict[str, Any]:
    network_targets = plan.get("network_targets") if isinstance(plan.get("network_targets"), dict) else {}
    domain_sources = network_targets.get("domain_sources") if isinstance(network_targets.get("domain_sources"), list) else []
    domains = network_targets.get("domains") if isinstance(network_targets.get("domains"), list) else []
    cleartext_domains = network_targets.get("cleartext_domains") if isinstance(network_targets.get("cleartext_domains"), list) else []

    endpoint_domains: set[str] = set()
    http_domains: set[str] = set()
    endpoint_roots: set[str] = set()
    http_roots: set[str] = set()
    for row in domain_sources:
        if not isinstance(row, dict):
            continue
        domain = _normalize_domain(row.get("domain"))
        if not domain:
            continue
        endpoint_domains.add(domain)
        root = _root_domain(domain)
        if root:
            endpoint_roots.add(root)
        scheme = _norm_text(row.get("scheme")).lower()
        if scheme == "http":
            http_domains.add(domain)
            if root:
                http_roots.add(root)
    for value in domains:
        domain = _normalize_domain(value)
        if domain:
            endpoint_domains.add(domain)
            endpoint_roots.add(_root_domain(domain))
    for value in cleartext_domains:
        domain = _normalize_domain(value)
        if domain:
            http_domains.add(domain)
            endpoint_domains.add(domain)
            http_roots.add(_root_domain(domain))
            endpoint_roots.add(_root_domain(domain))

    return {
        "static_endpoint_domain_count": len({item for item in endpoint_domains if item}),
        "static_http_endpoint_domain_count": len({item for item in http_domains if item}),
        "static_endpoint_root_count": len({item for item in endpoint_roots if item}),
        "static_http_endpoint_root_count": len({item for item in http_roots if item}),
        "static_endpoint_roots": sorted({item for item in endpoint_roots if item}),
        "static_http_endpoint_roots": sorted({item for item in http_roots if item}),
        "cleartext_domain_count": len({item for item in cleartext_domains if _normalize_domain(item)}),
    }


def _protocol_http_observed(report: dict[str, Any]) -> bool:
    from scytaledroid.DynamicAnalysis.pcap.security_surface import http_observed_from_report

    return http_observed_from_report(report)


def _visibility_loss_flag(report: dict[str, Any], *, domain_count: int) -> bool:
    vis = report.get("tls_quic_visibility") if isinstance(report.get("tls_quic_visibility"), dict) else {}
    quic_candidates = int(vis.get("quic_candidate_packets") or 0)
    tls_visible = bool(vis.get("tls_visible"))
    if quic_candidates > 0 and (not tls_visible or domain_count == 0):
        return True
    if int(report.get("pcap_size_bytes") or 0) > 0 and domain_count == 0:
        return True
    return False


def _load_static_finding_features(run_ids: set[int]) -> dict[int, dict[str, int]]:
    from scytaledroid.Database.db_core import db_queries as core_q

    if not run_ids:
        return {}
    placeholders = ", ".join(["%s"] * len(run_ids))
    rows = core_q.run_sql(
        f"""
        SELECT run_id, detector, finding_id, title
        FROM static_analysis_findings
        WHERE run_id IN ({placeholders})
          AND detector IN ('ipc_components', 'sdk_inventory', 'webview_hygiene', 'crypto_hygiene')
        """,
        tuple(sorted(run_ids)),
        fetch="all",
        dictionary=True,
    ) or []
    out: dict[int, dict[str, int]] = defaultdict(lambda: {
        "exported_without_permission_count": 0,
        "sdk_tracker_overlap_count": 0,
        "webview_indicator_count": 0,
        "pinning_indicator_present": 0,
    })
    for row in rows:
        if not isinstance(row, dict):
            continue
        run_id = int(row.get("run_id") or 0)
        detector = _norm_text(row.get("detector"))
        title = _norm_text(row.get("title")).lower()
        finding_id = _norm_text(row.get("finding_id")).lower()
        slot = out[run_id]
        if detector == "ipc_components" and "without permission" in title:
            slot["exported_without_permission_count"] += 1
        if detector == "sdk_inventory":
            slot["sdk_tracker_overlap_count"] += 1
        if detector == "webview_hygiene":
            slot["webview_indicator_count"] += 1
        if detector == "crypto_hygiene" and ("pin" in finding_id or "pin" in title):
            slot["pinning_indicator_present"] = 1
    return dict(out)


def _load_permission_features(run_ids: set[int]) -> dict[int, dict[str, int]]:
    from scytaledroid.Database.db_core import db_queries as core_q

    if not run_ids:
        return {}
    placeholders = ", ".join(["%s"] * len(run_ids))
    rows = core_q.run_sql(
        f"""
        SELECT run_id, protection, is_custom
        FROM static_permission_matrix
        WHERE run_id IN ({placeholders})
          AND is_custom = 1
        """,
        tuple(sorted(run_ids)),
        fetch="all",
        dictionary=True,
    ) or []
    out: dict[int, dict[str, int]] = defaultdict(lambda: {
        "custom_permission_count": 0,
        "dangerous_or_weak_custom_permission_count": 0,
    })
    for row in rows:
        if not isinstance(row, dict):
            continue
        run_id = int(row.get("run_id") or 0)
        slot = out[run_id]
        slot["custom_permission_count"] += 1
        protection = _norm_text(row.get("protection")).lower()
        if protection not in {"signature", "signatureorsystem"}:
            slot["dangerous_or_weak_custom_permission_count"] += 1
    return dict(out)


def _load_provider_features(packages: set[str]) -> dict[str, dict[str, int]]:
    from scytaledroid.Database.db_core import db_queries as core_q

    if not packages:
        return {}
    placeholders = ", ".join(["%s"] * len(packages))
    acl_rows = core_q.run_sql(
        f"""
        SELECT package_name, authority, metadata
        FROM static_provider_acl
        WHERE package_name IN ({placeholders})
        """,
        tuple(sorted(packages)),
        fetch="all",
        dictionary=True,
    ) or []
    fileprovider_rows = core_q.run_sql(
        f"""
        SELECT package_name, authority, grant_uri_permissions
        FROM static_fileproviders
        WHERE package_name IN ({placeholders})
        """,
        tuple(sorted(packages)),
        fetch="all",
        dictionary=True,
    ) or []
    authority_counts: dict[str, set[str]] = defaultdict(set)
    grant_uri_counts: Counter[str] = Counter()
    for row in fileprovider_rows:
        if not isinstance(row, dict):
            continue
        package = _norm_text(row.get("package_name")).lower()
        authority = _norm_text(row.get("authority"))
        if authority:
            authority_counts[package].add(authority)
        if _norm_bool(row.get("grant_uri_permissions")):
            grant_uri_counts[package] += 1
    for row in acl_rows:
        if not isinstance(row, dict):
            continue
        package = _norm_text(row.get("package_name")).lower()
        authority = _norm_text(row.get("authority"))
        if authority:
            authority_counts[package].add(authority)
        metadata = row.get("metadata")
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except json.JSONDecodeError:
                metadata = None
        if isinstance(metadata, dict) and metadata.get("grant_uri_permissions") is True:
            grant_uri_counts[package] += 1
    return {
        package: {
            "provider_authority_count": len(authority_counts.get(package, set())),
            "grant_uri_permissions_count": int(grant_uri_counts.get(package, 0)),
        }
        for package in packages
    }


def _load_string_endpoint_features(run_ids: set[int]) -> dict[int, dict[str, Any]]:
    from scytaledroid.Database.db_core import db_queries as core_q

    if not run_ids:
        return {}
    placeholders = ", ".join(["%s"] * len(run_ids))
    summary_rows = core_q.run_sql(
        f"""
        SELECT static_run_id, endpoints, http_cleartext
        FROM static_string_summary
        WHERE static_run_id IN ({placeholders})
        """,
        tuple(sorted(run_ids)),
        fetch="all",
        dictionary=True,
    ) or []
    sample_rows = core_q.run_sql(
        f"""
        SELECT static_run_id, bucket, root_domain, scheme
        FROM static_string_samples
        WHERE static_run_id IN ({placeholders})
          AND bucket IN ('endpoints', 'http_cleartext')
          AND root_domain IS NOT NULL
          AND root_domain <> ''
        """,
        tuple(sorted(run_ids)),
        fetch="all",
        dictionary=True,
    ) or []

    out: dict[int, dict[str, Any]] = defaultdict(
        lambda: {
            "summary_endpoint_count": 0,
            "summary_http_count": 0,
            "sample_endpoint_roots": set(),
            "sample_http_roots": set(),
        }
    )
    for row in summary_rows:
        if not isinstance(row, dict):
            continue
        run_id = int(row.get("static_run_id") or 0)
        slot = out[run_id]
        slot["summary_endpoint_count"] = int(row.get("endpoints") or 0)
        slot["summary_http_count"] = int(row.get("http_cleartext") or 0)
    for row in sample_rows:
        if not isinstance(row, dict):
            continue
        run_id = int(row.get("static_run_id") or 0)
        slot = out[run_id]
        root_domain = _normalize_domain(row.get("root_domain"))
        if not root_domain:
            continue
        slot["sample_endpoint_roots"].add(root_domain)
        bucket = _norm_text(row.get("bucket")).lower()
        scheme = _norm_text(row.get("scheme")).lower()
        if bucket == "http_cleartext" or scheme == "http":
            slot["sample_http_roots"].add(root_domain)

    finalized: dict[int, dict[str, Any]] = {}
    for run_id, slot in out.items():
        finalized[run_id] = {
            "summary_endpoint_count": int(slot["summary_endpoint_count"]),
            "summary_http_count": int(slot["summary_http_count"]),
            "sample_endpoint_roots": sorted(slot["sample_endpoint_roots"]),
            "sample_http_roots": sorted(slot["sample_http_roots"]),
        }
    return finalized


def _service_owner_breakdown(service_rows: list[dict[str, Any]]) -> dict[str, Any]:
    first_party_hits = 0
    third_party_hits = 0
    first_party_services: set[str] = set()
    third_party_services: set[str] = set()
    all_services: set[str] = set()
    for row in service_rows:
        service_key = _norm_text(row.get("service_key"))
        if not service_key:
            continue
        all_services.add(service_key)
        hits = int(row.get("total_hits") or 0)
        owner_class = _norm_text(row.get("owner_class"))
        if owner_class == "first_party":
            first_party_hits += hits
            first_party_services.add(service_key)
        elif owner_class == "third_party":
            third_party_hits += hits
            third_party_services.add(service_key)
    return {
        "first_party_service_hits": first_party_hits,
        "third_party_service_hits": third_party_hits,
        "first_party_service_count": len(first_party_services),
        "third_party_service_count": len(third_party_services),
        "dynamic_service_count": len(all_services),
    }


def _static_run_id_from_plan(plan: Mapping[str, Any] | None) -> int | None:
    if not isinstance(plan, Mapping):
        return None
    candidates: list[Any] = [plan.get("static_run_id")]
    run_identity = plan.get("run_identity")
    if isinstance(run_identity, Mapping):
        candidates.append(run_identity.get("static_run_id"))
    for candidate in candidates:
        try:
            value = int(candidate or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
    return None


def _load_latest_static_run_ids(packages: set[str]) -> dict[str, int]:
    normalized = sorted({_norm_text(package).lower() for package in packages if _norm_text(package)})
    if not normalized:
        return {}
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception:
        return {}
    placeholders = ", ".join(["%s"] * len(normalized))
    try:
        rows = core_q.run_sql(
            f"""
            SELECT
              LOWER(TRIM(a.package_name)) AS package_name,
              MAX(sar.id) AS static_run_id
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE LOWER(TRIM(a.package_name)) IN ({placeholders})
              AND UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
              AND UPPER(COALESCE(sar.run_class, '')) = 'CANONICAL'
            GROUP BY LOWER(TRIM(a.package_name))
            """,
            tuple(normalized),
            fetch="all",
            dictionary=True,
            query_name="dynamic.hidden_patterns.latest_static_run_ids",
        ) or []
    except Exception:
        return {}
    out: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        package = _norm_text(row.get("package_name")).lower()
        try:
            static_run_id = int(row.get("static_run_id") or 0)
        except (TypeError, ValueError):
            static_run_id = 0
        if package and static_run_id > 0:
            out[package] = static_run_id
    return out


def _iter_dynamic_runs() -> list[dict[str, Any]]:
    from scytaledroid.DynamicAnalysis.pcap.context_summary import summarize_pcap_service_context
    from scytaledroid.DynamicAnalysis.tools.evidence.verify_core import (
        verify_dynamic_evidence_packs,
    )

    verify_report = verify_dynamic_evidence_packs(_dynamic_root())
    verify_by_run = {
        str(row.get("run_id") or ""): row
        for row in (verify_report.get("runs") or [])
        if isinstance(row, dict)
    }
    rows: list[dict[str, Any]] = []
    for manifest_path in sorted(_dynamic_root().glob("*/run_manifest.json")):
        run_dir = manifest_path.parent
        manifest = _read_json(manifest_path) or {}
        target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
        operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
        package = _norm_text(target.get("package_name")).lower()
        if not package:
            continue
        plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json") or {}
        report = _read_json(run_dir / "analysis" / "pcap_report.json") or {}
        valid_pack, evidence_status = _evidence_validity(run_dir, manifest, report, verify_by_run=verify_by_run)
        context_bundle = summarize_pcap_service_context(report, package_name=package)
        service_context = context_bundle.get("service_context") if isinstance(context_bundle.get("service_context"), dict) else {}
        service_signals = context_bundle.get("service_signals") if isinstance(context_bundle.get("service_signals"), dict) else {}
        dynamic_domains: set[str] = set()
        for key in ("top_dns", "top_sni"):
            items = report.get(key) if isinstance(report.get(key), list) else []
            for item in items:
                if not isinstance(item, dict):
                    continue
                value = _normalize_domain(item.get("value"))
                if value:
                    dynamic_domains.add(_root_domain(value))
        rows.append(
            {
                "package": package,
                "app_label": _norm_text(target.get("display_name") or target.get("app_label") or package),
                "run_id": _norm_text(manifest.get("dynamic_run_id") or run_dir.name),
                "interaction_mode": _interaction_mode(
                    _norm_text(operator.get("run_profile") or (manifest.get("dataset") or {}).get("run_profile")),
                    _norm_text(operator.get("interaction_level")),
                ),
                "valid_pack": valid_pack,
                "evidence_status": evidence_status,
                "static_plan": plan,
                "pcap_report": report,
                "service_context": service_context,
                "service_signals": service_signals,
                "dynamic_domains": dynamic_domains,
                "service_rows": [row for row in (service_context.get("services") or []) if isinstance(row, dict)],
                "signal_rows": [row for row in (service_signals.get("signals") or []) if isinstance(row, dict)],
                "visibility_loss_flag": _visibility_loss_flag(report, domain_count=int(service_context.get("observed_domain_count") or 0)),
                "http_observed": _protocol_http_observed(report),
            }
        )
    return rows


def _build_static_rows(package_runs: dict[str, list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    authoritative_runs: dict[str, dict[str, Any]] = {}
    run_ids: set[int] = set()
    packages: set[str] = set()
    packages_missing_plan_static_id: set[str] = set()
    for package, runs in package_runs.items():
        valid_runs = [row for row in runs if row["valid_pack"]]
        if not valid_runs:
            continue
        latest = max(valid_runs, key=lambda row: (_norm_text(row["run_id"]),))
        authoritative_runs[package] = latest
        static_run_id = _static_run_id_from_plan(latest.get("static_plan"))
        if static_run_id is not None:
            run_ids.add(int(static_run_id))
        else:
            packages_missing_plan_static_id.add(package)
        packages.add(package)

    fallback_static_run_ids = _load_latest_static_run_ids(packages_missing_plan_static_id)
    run_ids.update(int(value) for value in fallback_static_run_ids.values())

    finding_features = _load_static_finding_features(run_ids)
    permission_features = _load_permission_features(run_ids)
    provider_features = _load_provider_features(packages)
    string_endpoint_features = _load_string_endpoint_features(run_ids)

    join_rows: list[dict[str, Any]] = []
    component_rows: list[dict[str, Any]] = []
    network_rows: list[dict[str, Any]] = []

    for package in sorted(authoritative_runs):
        ref = authoritative_runs[package]
        app_label = ref["app_label"]
        plan = ref["static_plan"]
        static_run_id = _static_run_id_from_plan(plan) or fallback_static_run_ids.get(package)
        static_features = plan.get("static_features") if isinstance(plan.get("static_features"), dict) else {}
        risk_flags = plan.get("risk_flags") if isinstance(plan.get("risk_flags"), dict) else {}
        exported = plan.get("exported_components") if isinstance(plan.get("exported_components"), dict) else {}
        endpoint_features = _static_endpoint_features(plan)
        ff = finding_features.get(static_run_id or -1, {})
        pf = permission_features.get(static_run_id or -1, {})
        prov = provider_features.get(package, {})
        sf = string_endpoint_features.get(static_run_id or -1, {})
        plan_endpoint_roots = set(endpoint_features["static_endpoint_roots"])
        plan_http_roots = set(endpoint_features["static_http_endpoint_roots"])
        sample_endpoint_roots = {
            _normalize_domain(item)
            for item in (sf.get("sample_endpoint_roots") or [])
            if _normalize_domain(item)
        }
        sample_http_roots = {
            _normalize_domain(item)
            for item in (sf.get("sample_http_roots") or [])
            if _normalize_domain(item)
        }
        merged_endpoint_roots = sorted(plan_endpoint_roots or sample_endpoint_roots)
        merged_http_roots = sorted(plan_http_roots or sample_http_roots)
        endpoint_compare_ready = bool(merged_endpoint_roots)
        endpoint_source = "plan"
        if plan_endpoint_roots and sample_endpoint_roots:
            endpoint_source = "plan"
        elif sample_endpoint_roots:
            endpoint_source = "string_samples_fallback"
        elif int(sf.get("summary_endpoint_count") or 0) > 0:
            endpoint_source = "string_summary_only"
        elif plan_endpoint_roots:
            endpoint_source = "plan"
        else:
            endpoint_source = "none"
        inventory_status = "present" if (endpoint_compare_ready or int(sf.get("summary_endpoint_count") or 0) > 0) else "missing"

        component_rows.append(
            {
                "package": package,
                "app_label": app_label,
                "activities_exported": len(exported.get("activities") or []),
                "services_exported": len(exported.get("services") or []),
                "receivers_exported": len(exported.get("receivers") or []),
                "providers_exported": len(exported.get("providers") or []),
                "exported_without_permission_count": int(ff.get("exported_without_permission_count") or 0),
                "grant_uri_permissions_count": int(prov.get("grant_uri_permissions_count") or 0),
                "provider_authority_count": int(prov.get("provider_authority_count") or 0),
                "custom_permission_count": int(pf.get("custom_permission_count") or 0),
                "dangerous_or_weak_custom_permission_count": int(pf.get("dangerous_or_weak_custom_permission_count") or 0),
            }
        )

        network_rows.append(
            {
                "package": package,
                "app_label": app_label,
                "uses_cleartext_traffic": bool(static_features.get("uses_cleartext_traffic") if "uses_cleartext_traffic" in static_features else risk_flags.get("uses_cleartext_traffic")),
                "cleartext_domain_count": int(endpoint_features["cleartext_domain_count"]),
                "network_security_config_present": bool(risk_flags.get("network_security_config")),
                "static_endpoint_inventory_status": inventory_status,
                "static_endpoint_source": endpoint_source,
                "allow_backup": bool(risk_flags.get("allow_backup")),
                "debuggable": bool(risk_flags.get("debuggable")),
                "test_only": False,
                "pinning_indicator_present": bool(ff.get("pinning_indicator_present") or False),
                "http_like_static_endpoint_count": len(merged_http_roots),
                "static_endpoint_root_count": len(merged_endpoint_roots),
            }
        )

        join_rows.append(
            {
                "package": package,
                "app_label": app_label,
                "static_run_id": static_run_id or "",
                "exported_component_total": int(exported.get("total") or static_features.get("exported_components_total") or 0),
                "exported_unprotected_total": int(ff.get("exported_without_permission_count") or 0),
                "provider_authority_count": int(prov.get("provider_authority_count") or 0),
                "webview_indicator_count": int(ff.get("webview_indicator_count") or (1 if static_features.get("uses_webview") else 0)),
                "sdk_tracker_overlap_count": int(ff.get("sdk_tracker_overlap_count") or 0),
                "static_endpoint_root_count": len(merged_endpoint_roots),
                "static_http_endpoint_root_count": len(merged_http_roots),
                "static_endpoint_inventory_status": inventory_status,
                "static_endpoint_source": endpoint_source,
                "_static_endpoint_domain_count": int(endpoint_features["static_endpoint_domain_count"]),
                "uses_cleartext_traffic": bool(static_features.get("uses_cleartext_traffic") if "uses_cleartext_traffic" in static_features else risk_flags.get("uses_cleartext_traffic")),
                "network_security_config_present": bool(risk_flags.get("network_security_config")),
                "pinning_indicator_present": bool(ff.get("pinning_indicator_present") or False),
                "_static_endpoint_roots": merged_endpoint_roots,
                "_static_endpoint_compare_ready": endpoint_compare_ready,
                "_static_endpoint_inventory_status": inventory_status,
                "_static_endpoint_source": endpoint_source,
                "_static_string_endpoint_count": int(sf.get("summary_endpoint_count") or 0),
                "_high_value_permission_count": int(static_features.get("high_value_permission_count") or 0),
                "_permissions_total": int(static_features.get("permissions_total") or 0),
                "_uses_webview": bool(static_features.get("uses_webview") or False),
                "_allow_backup": bool(risk_flags.get("allow_backup")),
                "_debuggable": bool(risk_flags.get("debuggable")),
            }
        )
    return join_rows, component_rows, network_rows


def _merge_dynamic_into_join(join_rows: list[dict[str, Any]], package_runs: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in join_rows:
        package = row["package"]
        valid_runs = [run for run in package_runs.get(package, []) if run["valid_pack"]]
        baseline_runs = [run for run in valid_runs if run["interaction_mode"] == "baseline"]
        manual_runs = [run for run in valid_runs if run["interaction_mode"] == "manual"]
        baseline_domains = set().union(*(run["dynamic_domains"] for run in baseline_runs)) if baseline_runs else set()
        manual_domains = set().union(*(run["dynamic_domains"] for run in manual_runs)) if manual_runs else set()
        observed_domains = set().union(*(run["dynamic_domains"] for run in valid_runs)) if valid_runs else set()
        service_keys: set[str] = set()
        signal_keys: set[str] = set()
        service_breakdown = {
            "first_party_service_hits": 0,
            "third_party_service_hits": 0,
            "first_party_service_count": 0,
            "third_party_service_count": 0,
            "dynamic_service_count": 0,
        }
        for run in valid_runs:
            service_breakdown_run = _service_owner_breakdown(run["service_rows"])
            for key in ("first_party_service_hits", "third_party_service_hits"):
                service_breakdown[key] += int(service_breakdown_run[key])
            service_breakdown["first_party_service_count"] += int(service_breakdown_run["first_party_service_count"])
            service_breakdown["third_party_service_count"] += int(service_breakdown_run["third_party_service_count"])
            for service in run["service_rows"]:
                key = _norm_text(service.get("service_key"))
                if key:
                    service_keys.add(key)
            for signal in run["signal_rows"]:
                key = _norm_text(signal.get("signal_key"))
                if key:
                    signal_keys.add(key)
        service_breakdown["dynamic_service_count"] = len(service_keys)
        dynamic_signal_count = len(signal_keys)
        visibility_loss = any(bool(run["visibility_loss_flag"]) for run in valid_runs)
        http_observed = any(bool(run["http_observed"]) for run in valid_runs)
        merged = dict(row)
        merged.update(
            {
                "dynamic_valid_run_count": len(valid_runs),
                "baseline_domain_count": len(baseline_domains),
                "manual_domain_count": len(manual_domains),
                "baseline_only_domain_count": len(baseline_domains - manual_domains),
                "manual_only_domain_count": len(manual_domains - baseline_domains),
                "dynamic_service_count": int(service_breakdown["dynamic_service_count"]),
                "dynamic_signal_count": dynamic_signal_count,
                "first_party_service_hits": int(service_breakdown["first_party_service_hits"]),
                "third_party_service_hits": int(service_breakdown["third_party_service_hits"]),
                "visibility_loss_flag": bool(visibility_loss),
                "_observed_domain_count": len(observed_domains),
                "_dynamic_only_domains": sorted(observed_domains - set(merged["_static_endpoint_roots"])),
                "_manual_run_count": len(manual_runs),
                "_baseline_run_count": len(baseline_runs),
                "_third_party_service_count": len(
                    {
                        _norm_text(service.get("service_key"))
                        for run in valid_runs
                        for service in run["service_rows"]
                        if _norm_text(service.get("owner_class")) == "third_party"
                    }
                ),
                "_first_party_service_count": len(
                    {
                        _norm_text(service.get("service_key"))
                        for run in valid_runs
                        for service in run["service_rows"]
                        if _norm_text(service.get("owner_class")) == "first_party"
                    }
                ),
                "_http_observed": bool(http_observed),
            }
        )
        out.append(merged)
    return out


def _candidate_row(
    package: str,
    app_label: str,
    pattern_key: str,
    pattern_family: str,
    evidence_strength: str,
    explanation: str,
    *,
    static_features: dict[str, Any],
    dynamic_features: dict[str, Any],
) -> dict[str, Any]:
    return {
        "package": package,
        "app_label": app_label,
        "pattern_key": pattern_key,
        "pattern_family": pattern_family,
        "evidence_strength": evidence_strength,
        "explanation": explanation,
        "static_features_json": json.dumps(static_features, sort_keys=True),
        "dynamic_features_json": json.dumps(dynamic_features, sort_keys=True),
    }


def _build_hidden_pattern_candidates(join_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in sorted(join_rows, key=lambda item: (item["package"], str(item.get("static_run_id") or ""))):
        package = row["package"]
        app_label = row["app_label"]
        static_features = {
            "static_run_id": row["static_run_id"],
            "exported_component_total": row["exported_component_total"],
            "exported_unprotected_total": row["exported_unprotected_total"],
            "static_endpoint_root_count": row["static_endpoint_root_count"],
            "static_http_endpoint_root_count": row["static_http_endpoint_root_count"],
            "static_endpoint_inventory_status": row["_static_endpoint_inventory_status"],
            "static_endpoint_source": row["_static_endpoint_source"],
            "uses_cleartext_traffic": row["uses_cleartext_traffic"],
            "network_security_config_present": row["network_security_config_present"],
            "provider_authority_count": row["provider_authority_count"],
            "webview_indicator_count": row["webview_indicator_count"],
            "sdk_tracker_overlap_count": row["sdk_tracker_overlap_count"],
            "high_value_permission_count": row["_high_value_permission_count"],
            "permissions_total": row["_permissions_total"],
        }
        dynamic_features = {
            "dynamic_valid_run_count": row["dynamic_valid_run_count"],
            "baseline_domain_count": row["baseline_domain_count"],
            "manual_domain_count": row["manual_domain_count"],
            "baseline_only_domain_count": row["baseline_only_domain_count"],
            "manual_only_domain_count": row["manual_only_domain_count"],
            "dynamic_service_count": row["dynamic_service_count"],
            "dynamic_signal_count": row["dynamic_signal_count"],
            "first_party_service_hits": row["first_party_service_hits"],
            "third_party_service_hits": row["third_party_service_hits"],
            "visibility_loss_flag": row["visibility_loss_flag"],
            "observed_domain_count": row["_observed_domain_count"],
            "http_observed": row["_http_observed"],
        }
        if row["_permissions_total"] <= 12 and row["_third_party_service_count"] >= 3:
            out.append(
                _candidate_row(
                    package,
                    app_label,
                    "few_permissions_many_third_party_services",
                    "static_dynamic_mismatch",
                    "medium",
                    "Few declared permissions but multiple third-party dynamic services were observed; review whether runtime dependencies exceed the apparent static permission posture.",
                    static_features=static_features,
                    dynamic_features=dynamic_features,
                )
            )
        if (
            row["_high_value_permission_count"] >= 2
            and row["third_party_service_hits"] >= 5
            and row["_third_party_service_count"] >= 2
            and row["dynamic_valid_run_count"] >= 2
        ):
            privacy_strength = "high" if row["dynamic_valid_run_count"] >= 3 else "medium"
            out.append(
                _candidate_row(
                    package,
                    app_label,
                    "privacy_sensitive_static_tags_with_third_party_activation",
                    "privacy_context",
                    privacy_strength,
                    "Privacy-relevant static capabilities coexist with active third-party dynamic services; treat this as a review candidate rather than a direct vulnerability claim.",
                    static_features=static_features,
                    dynamic_features=dynamic_features,
                )
            )
        if row["_baseline_run_count"] > 0 and row["_manual_run_count"] > 0 and row["manual_only_domain_count"] >= 1:
            dynamic_plus = dict(dynamic_features)
            dynamic_plus["dynamic_only_domains_top5"] = row["_dynamic_only_domains"][:5]
            out.append(
                _candidate_row(
                    package,
                    app_label,
                    "manual_only_provider_expansion",
                    "behavioral_delta",
                    "medium",
                    "Manual interaction introduced additional runtime providers/domains beyond the baseline union; review the activated surface and whether it matches expected user flows.",
                    static_features=static_features,
                    dynamic_features=dynamic_plus,
                )
            )
        if (
            max(int(row.get("_static_endpoint_domain_count") or 0), row["static_endpoint_root_count"]) >= 8
            and row["_observed_domain_count"] <= max(3, max(int(row.get("_static_endpoint_domain_count") or 0), row["static_endpoint_root_count"]) // 3)
        ):
            out.append(
                _candidate_row(
                    package,
                    app_label,
                    "many_static_endpoints_few_observed_endpoints",
                    "coverage_gap",
                    "medium",
                    "Static string inventory is much broader than the currently observed runtime destination set; this may indicate dormant code paths, environment gating, or incomplete interaction coverage.",
                    static_features=static_features,
                    dynamic_features=dynamic_features,
                )
            )
        if (
            row["_static_endpoint_compare_ready"]
            and row["dynamic_valid_run_count"] >= 2
            and len(row["_dynamic_only_domains"]) >= 3
            and len(row["_dynamic_only_domains"]) >= max(3, row["_observed_domain_count"] // 2)
        ):
            dynamic_plus = dict(dynamic_features)
            dynamic_plus["dynamic_only_domains_top5"] = row["_dynamic_only_domains"][:5]
            out.append(
                _candidate_row(
                    package,
                    app_label,
                    "observed_endpoints_absent_from_static_strings",
                    "static_dynamic_mismatch",
                    "medium",
                    "Observed runtime destinations were not present in the static endpoint-root set; review CDN/platform indirection, configuration fetch, or string-extraction blind spots.",
                    static_features=static_features,
                    dynamic_features=dynamic_plus,
                )
            )
        if (
            row["uses_cleartext_traffic"]
            and not row["_http_observed"]
            and row["dynamic_valid_run_count"] >= 3
            and row["static_http_endpoint_root_count"] >= 2
            and not row["network_security_config_present"]
        ):
            out.append(
                _candidate_row(
                    package,
                    app_label,
                    "cleartext_allowed_not_observed",
                    "network_policy_mismatch",
                    "low",
                    "Cleartext is statically permitted, but no cleartext-like protocol evidence was observed in the current runtime captures.",
                    static_features=static_features,
                    dynamic_features=dynamic_features,
                )
            )
        if row["static_http_endpoint_root_count"] >= 2 and not row["uses_cleartext_traffic"]:
            out.append(
                _candidate_row(
                    package,
                    app_label,
                    "http_static_endpoints_cleartext_denied",
                    "network_policy_mismatch",
                    "medium",
                    "Static HTTP-like endpoints exist while the manifest/network posture denies cleartext traffic; review whether these are dead paths, documentation references, or policy mismatches.",
                    static_features=static_features,
                    dynamic_features=dynamic_features,
                )
            )
        if (
            not row["uses_cleartext_traffic"]
            and row["_http_observed"]
            and row["dynamic_valid_run_count"] >= 2
            and not row["visibility_loss_flag"]
        ):
            out.append(
                _candidate_row(
                    package,
                    app_label,
                    "cleartext_observed_when_denied",
                    "network_policy_mismatch",
                    "high",
                    "Static posture denies cleartext traffic, but HTTP/cleartext metadata was observed in dynamic captures; treat as a policy mismatch for manual review.",
                    static_features=static_features,
                    dynamic_features=dynamic_features,
                )
            )
        if (
            row["exported_unprotected_total"] >= 12
            and row["dynamic_valid_run_count"] >= 2
            and row["_third_party_service_count"] >= 2
            and (row["dynamic_service_count"] >= 6 or row["_observed_domain_count"] >= 10)
        ):
            out.append(
                _candidate_row(
                    package,
                    app_label,
                    "exported_surface_with_broad_network_activation",
                    "surface_activation",
                    "medium",
                    "Large exported surface coincides with broad runtime network activation; review whether the externally reachable surface aligns with the observed service footprint.",
                    static_features=static_features,
                    dynamic_features=dynamic_features,
                )
            )
        if (
            row["dynamic_valid_run_count"] >= 4
            and row["_third_party_service_count"] >= 4
            and row["third_party_service_hits"] >= max(25, row["first_party_service_hits"] * 2)
        ):
            out.append(
                _candidate_row(
                    package,
                    app_label,
                    "first_party_to_third_party_expansion",
                    "ownership_shift",
                    "medium",
                    "Third-party service activity exceeds first-party service activity in the observed runtime corpus; review whether that balance is expected for this app class and run mode.",
                    static_features=static_features,
                    dynamic_features=dynamic_features,
                )
            )
        if row["visibility_loss_flag"]:
            out.append(
                _candidate_row(
                    package,
                    app_label,
                    "visibility_loss_present",
                    "measurement_limit",
                    "medium",
                    "Traffic visibility appears partially degraded, for example by QUIC-heavy or domain-sparse flows; interpret destination counts conservatively.",
                    static_features=static_features,
                    dynamic_features=dynamic_features,
                )
            )
    return sorted(out, key=lambda item: (item["package"], item["pattern_key"]))


def generate_report(*, output_dir: Path | None = None) -> dict[str, Any]:
    run_rows = _iter_dynamic_runs()
    package_runs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in run_rows:
        package_runs[row["package"]].append(row)

    static_join_seed, component_rows, network_rows = _build_static_rows(package_runs)
    join_rows = _merge_dynamic_into_join(static_join_seed, package_runs)
    candidate_rows = _build_hidden_pattern_candidates(join_rows)

    export_join_rows = [
        {
            key: value
            for key, value in row.items()
            if not str(key).startswith("_")
        }
        for row in sorted(join_rows, key=lambda item: item["package"])
    ]
    component_rows = sorted(component_rows, key=lambda item: item["package"])
    network_rows = sorted(network_rows, key=lambda item: item["package"])

    output_root = output_dir or (_REPO_ROOT / "output" / "audit" / "dynamic_hidden_patterns" / datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S"))
    output_root.mkdir(parents=True, exist_ok=True)
    _write_csv(output_root / "static_dynamic_join_summary.csv", export_join_rows)
    _write_csv(output_root / "component_exposure_summary.csv", component_rows)
    _write_csv(output_root / "network_security_policy_summary.csv", network_rows)
    _write_csv(output_root / "hidden_pattern_candidates.csv", candidate_rows)

    family_counts = Counter(row["pattern_family"] for row in candidate_rows)
    summary = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "repo_root": str(_REPO_ROOT),
        "dynamic_evidence_root": str(_dynamic_root().resolve()),
        "apps_exported": len(export_join_rows),
        "runs_scanned": len(run_rows),
        "valid_dynamic_runs": sum(1 for row in run_rows if row["valid_pack"]),
        "static_dynamic_join_rows": len(export_join_rows),
        "component_exposure_rows": len(component_rows),
        "network_security_policy_rows": len(network_rows),
        "hidden_pattern_candidate_rows": len(candidate_rows),
        "top_candidate_pattern_families": dict(sorted(family_counts.items())),
        "output_files": {
            "static_dynamic_join_summary_csv": str((output_root / "static_dynamic_join_summary.csv").resolve()),
            "component_exposure_summary_csv": str((output_root / "component_exposure_summary.csv").resolve()),
            "network_security_policy_summary_csv": str((output_root / "network_security_policy_summary.csv").resolve()),
            "hidden_pattern_candidates_csv": str((output_root / "hidden_pattern_candidates.csv").resolve()),
            "summary_json": str((output_root / "summary.json").resolve()),
        },
        "assumptions": [
            "filesystem_first_dynamic_evidence",
            "current_dynamic_validity_rules_match_report_dynamic_paper_exports",
            "embedded_static_dynamic_plan_is_primary_with_static_string_fallback_for_endpoint_context",
            "hidden_pattern_candidates_are_review_indicators_not_vulnerability_claims",
        ],
        "limitations": [
            "no secret-like raw values are exported; only counts and booleans are used",
            "grant_uri_permissions_count is conservative and only uses persisted provider metadata when available",
            "pinning_indicator_present is conservative and only reflects explicit static findings currently visible in canonical tables",
            "cleartext observation is based on PCAP protocol hierarchy and may miss encrypted or protocol-obscured flows",
            "invalid_or_skipped dynamic packs are excluded from valid-run summaries",
        ],
        "no_db_writes": True,
        "experimental_audit": True,
    }
    (output_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    summary = generate_report(output_dir=output_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
