"""Aggregate PCAP features into a single CSV dataset."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.core.static_context import compute_static_context


def export_pcap_features_csv() -> Path | None:
    output_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not output_root.exists():
        return None
    rows: list[dict[str, Any]] = []
    for run_dir in output_root.iterdir():
        if not run_dir.is_dir():
            continue
        features_path = run_dir / "analysis" / "pcap_features.json"
        manifest_path = run_dir / "run_manifest.json"
        plan_path = run_dir / "inputs" / "static_dynamic_plan.json"
        if not features_path.exists() or not manifest_path.exists():
            continue
        try:
            features = json.loads(features_path.read_text(encoding="utf-8"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            plan = json.loads(plan_path.read_text(encoding="utf-8")) if plan_path.exists() else {}
        except (OSError, json.JSONDecodeError):
            continue
        static_cols = _extract_static_export_columns(plan if isinstance(plan, dict) else {}, manifest)
        dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
        row = _flatten_features(features)
        row.update(
            {
                "dynamic_run_id": manifest.get("dynamic_run_id"),
                "package_name": (manifest.get("target") or {}).get("package_name"),
                "static_run_id": (manifest.get("target") or {}).get("static_run_id"),
                "scenario": (manifest.get("scenario") or {}).get("id"),
                "started_at": manifest.get("started_at"),
                "ended_at": manifest.get("ended_at"),
                "tier": dataset.get("tier") or (manifest.get("operator") or {}).get("tier"),
                "countable": dataset.get("countable"),
                "valid_dataset_run": dataset.get("valid_dataset_run"),
                "invalid_reason_code": dataset.get("invalid_reason_code"),
                "min_pcap_bytes": dataset.get("min_pcap_bytes"),
                "pcap_size_bytes": dataset.get("pcap_size_bytes"),
                "run_profile": (manifest.get("operator") or {}).get("run_profile"),
                "run_sequence": (manifest.get("operator") or {}).get("run_sequence"),
                "interaction_level": (manifest.get("operator") or {}).get("interaction_level"),
                "messaging_activity": (manifest.get("operator") or {}).get("messaging_activity"),
            }
        )
        row.update(static_cols)
        rows.append(row)
    if not rows:
        return None
    dest = Path(app_config.DATA_DIR) / "archive" / "pcap_features.csv"
    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_csv(dest, rows)
    return dest


def export_dynamic_run_summary_csv() -> Path | None:
    output_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not output_root.exists():
        return None
    rows: list[dict[str, Any]] = []
    for run_dir in output_root.iterdir():
        if not run_dir.is_dir():
            continue
        manifest = _load_json(run_dir / "run_manifest.json")
        summary = _load_json(run_dir / "analysis" / "summary.json")
        overlap = _load_json(run_dir / "analysis" / "static_dynamic_overlap.json")
        report = _load_json(run_dir / "analysis" / "pcap_report.json")
        features = _load_json(run_dir / "analysis" / "pcap_features.json")
        if not manifest or not summary or not report or not features:
            continue
        row = _build_run_summary_row(run_dir, manifest, summary, report, overlap, features)
        if row:
            rows.append(row)
    if not rows:
        return None
    dest = Path(app_config.DATA_DIR) / "archive" / "dynamic_run_summary.csv"
    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_csv(dest, rows)
    return dest


def _flatten_features(features: dict[str, Any]) -> dict[str, Any]:
    row = {}
    for group in ("metrics", "proxies", "quality"):
        values = features.get(group) or {}
        if not isinstance(values, dict):
            continue
        for key, value in values.items():
            if isinstance(value, (list, dict)):
                row[f"{group}_{key}"] = json.dumps(value, sort_keys=True)
            else:
                row[f"{group}_{key}"] = value
    return row


def _build_run_summary_row(
    run_dir: Path,
    manifest: dict[str, Any],
    summary: dict[str, Any],
    report: dict[str, Any],
    overlap: dict[str, Any] | None,
    features: dict[str, Any],
) -> dict[str, Any] | None:
    target = manifest.get("target") or {}
    plan = _load_json(run_dir / "inputs" / "static_dynamic_plan.json")
    static_cols = _extract_static_export_columns(plan if isinstance(plan, dict) else {}, manifest)
    dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
    static_tags = target.get("static_context_tags")
    static_context = target.get("static_context") if isinstance(target.get("static_context"), dict) else None
    # Back-compat: older runs won't have static tags in the manifest. Derive them
    # from the embedded static plan, without modifying the evidence pack.
    if not isinstance(static_tags, list):
        plan = _load_json(run_dir / "inputs" / "static_dynamic_plan.json")
        if isinstance(plan, dict):
            derived = compute_static_context(plan)
            static_tags = derived.get("tags") if isinstance(derived.get("tags"), list) else None
            static_context = derived if isinstance(derived, dict) else static_context
    if isinstance(static_tags, list):
        static_tags_str = json.dumps(static_tags, sort_keys=True)
    else:
        static_tags_str = None
    telemetry = summary.get("telemetry") or {}
    stats = telemetry.get("stats") or {}
    capture = summary.get("capture") or {}
    metrics = (features.get("metrics") or {}) if isinstance(features.get("metrics"), dict) else {}
    proxies = (features.get("proxies") or {}) if isinstance(features.get("proxies"), dict) else {}
    overlap_sources = (overlap or {}).get("overlap_by_source") or {}
    overlap_nsc = _overlap_ratio_for_source(overlap_sources, "nsc")
    overlap_strings = _overlap_ratio_for_source(overlap_sources, "strings")
    unique_domains = _unique_domains(report)
    row = {
        "app": target.get("package_name"),
        "run_id": manifest.get("dynamic_run_id"),
        # Alias for downstream consumers that expect an explicit dynamic_run_id field.
        "dynamic_run_id": manifest.get("dynamic_run_id"),
        "tier": dataset.get("tier") or (manifest.get("operator") or {}).get("tier"),
        "countable": dataset.get("countable"),
        "valid_dataset_run": dataset.get("valid_dataset_run"),
        "invalid_reason_code": dataset.get("invalid_reason_code"),
        "min_pcap_bytes": dataset.get("min_pcap_bytes"),
        "pcap_size_bytes": dataset.get("pcap_size_bytes"),
        "run_profile": (manifest.get("operator") or {}).get("run_profile"),
        "run_sequence": (manifest.get("operator") or {}).get("run_sequence"),
        "interaction_level": (manifest.get("operator") or {}).get("interaction_level"),
        "static_tags": static_tags_str,
        "static_run_id": target.get("static_run_id"),
        "exported_components_total": ((static_context or {}).get("exported_components") or {}).get("total")
        if isinstance(static_context, dict)
        else None,
        "sampling_duration_seconds": stats.get("sampling_duration_seconds"),
        "pcap_valid": capture.get("pcap_valid"),
        "overlap_ratio": (overlap or {}).get("overlap_ratio"),
        "overlap_ratio_nsc": overlap_nsc,
        "overlap_ratio_strings": overlap_strings,
        "dynamic_only_ratio": (overlap or {}).get("dynamic_only_ratio"),
        "bytes_per_sec": metrics.get("data_byte_rate_bps"),
        "packets_per_sec": metrics.get("avg_packet_rate_pps"),
        # Use the post-processed ratios from pcap_features.json (quic/udp, tls/tcp).
        # This avoids double-counting when protocol_hierarchy contains multiple rows.
        "quic_ratio": proxies.get("quic_ratio"),
        "tls_ratio": proxies.get("tls_ratio"),
        # Explicit-denominator aliases to avoid misinterpretation.
        "quic_over_udp_ratio": proxies.get("quic_ratio"),
        "tls_over_tcp_ratio": proxies.get("tls_ratio"),
        "tcp_ratio": proxies.get("tcp_ratio"),
        "udp_ratio": proxies.get("udp_ratio"),
        "unique_domains": unique_domains,
    }
    row.update(static_cols)
    return row


def _protocol_ratio(rows: list[dict[str, Any]], protocol: str) -> float | None:
    if not rows:
        return None
    total = 0
    matched = 0
    for row in rows:
        try:
            bytes_count = int(row.get("bytes") or 0)
        except (TypeError, ValueError):
            bytes_count = 0
        total += bytes_count
        if str(row.get("protocol") or "").lower() == protocol:
            matched += bytes_count
    if total <= 0:
        return None
    return matched / float(total)


def _unique_domains(report: dict[str, Any]) -> int | None:
    domains = set()
    for item in report.get("top_sni") or []:
        value = item.get("value")
        if value:
            domains.add(str(value).strip())
    for item in report.get("top_dns") or []:
        value = item.get("value")
        if value:
            domains.add(str(value).strip())
    return len(domains) if domains else None


def _overlap_ratio_for_source(sources: dict[str, Any], source: str) -> float | None:
    payload = sources.get(source)
    if not isinstance(payload, dict):
        return None
    ratio = payload.get("overlap_ratio")
    if isinstance(ratio, (int, float)):
        return float(ratio)
    return None


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    preferred = [
        "dynamic_run_id",
        "run_id",
        "app",
        "package_name_lc",
        "version_code",
        "version_name",
        "base_apk_sha256",
        "static_handoff_hash",
        "signer_digest",
        "static_risk_score",
        "static_risk_band",
        "masvs_total_score",
        "perm_dangerous_n",
        "nsc_cleartext_permitted",
    ]
    discovered = {key for row in rows for key in row.keys()}
    fieldnames = [key for key in preferred if key in discovered]
    fieldnames.extend(sorted(discovered.difference(fieldnames)))
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _extract_static_export_columns(plan: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    identity = plan.get("run_identity") if isinstance(plan.get("run_identity"), dict) else {}
    static_features = plan.get("static_features") if isinstance(plan.get("static_features"), dict) else {}
    target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    package_name_lc = str(identity.get("package_name_lc") or plan.get("package_name") or target.get("package_name") or "").strip().lower()
    signer_digest = str(identity.get("signer_digest") or "").strip() or "UNKNOWN"
    version_code_raw = identity.get("version_code")
    if version_code_raw in (None, ""):
        version_code_raw = plan.get("version_code")
    try:
        version_code = int(version_code_raw) if version_code_raw not in (None, "") else None
    except Exception:
        version_code = None
    out: dict[str, Any] = {
        "package_name_lc": package_name_lc or None,
        "version_code": version_code,
        "version_name": identity.get("version_name") or plan.get("version_name"),
        "base_apk_sha256": identity.get("base_apk_sha256"),
        "static_handoff_hash": identity.get("static_handoff_hash"),
        "signer_digest": signer_digest,
        "static_risk_score": static_features.get("static_risk_score"),
        "static_risk_band": static_features.get("static_risk_band"),
        "masvs_total_score": static_features.get("masvs_total_score"),
        "perm_dangerous_n": static_features.get("perm_dangerous_n", static_features.get("dangerous_permission_count")),
        "nsc_cleartext_permitted": static_features.get(
            "nsc_cleartext_permitted",
            static_features.get("uses_cleartext_traffic"),
        ),
    }
    return out


__all__ = ["export_pcap_features_csv", "export_dynamic_run_summary_csv"]
