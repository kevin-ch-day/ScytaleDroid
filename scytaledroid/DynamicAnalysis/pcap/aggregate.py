"""Aggregate PCAP features into a single CSV dataset."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.core.static_context import compute_static_context
from scytaledroid.DynamicAnalysis.plans.loader import enrich_dynamic_plan


def export_pcap_features_csv(
    *,
    freeze_path: Path | None = None,
    require_freeze: bool = False,
) -> Path | None:
    output_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not output_root.exists():
        return None
    if require_freeze and freeze_path is None:
        raise RuntimeError("EXPORT_BLOCKED_MISSING_FREEZE: provide freeze_path in paper mode")
    if require_freeze and freeze_path is not None and not freeze_path.exists():
        raise RuntimeError(f"EXPORT_BLOCKED_MISSING_FREEZE:{freeze_path}")
    selected_run_ids = _load_freeze_included_run_ids(freeze_path) if freeze_path else None
    if selected_run_ids is not None:
        _ensure_freeze_ids_present(
            selected_run_ids=selected_run_ids,
            evidence_root=output_root,
            freeze_path=freeze_path,
        )
    rows: list[dict[str, Any]] = []
    for run_dir in sorted([p for p in output_root.iterdir() if p.is_dir()], key=lambda p: p.name):
        if selected_run_ids is not None and run_dir.name not in selected_run_ids:
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
            if isinstance(plan, dict):
                plan = enrich_dynamic_plan(plan)
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


def export_dynamic_run_summary_csv(
    *,
    freeze_path: Path | None = None,
    require_freeze: bool = False,
) -> Path | None:
    output_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not output_root.exists():
        return None
    if require_freeze and freeze_path is None:
        raise RuntimeError("EXPORT_BLOCKED_MISSING_FREEZE: provide freeze_path in paper mode")
    if require_freeze and freeze_path is not None and not freeze_path.exists():
        raise RuntimeError(f"EXPORT_BLOCKED_MISSING_FREEZE:{freeze_path}")
    selected_run_ids = _load_freeze_included_run_ids(freeze_path) if freeze_path else None
    if selected_run_ids is not None:
        _ensure_freeze_ids_present(
            selected_run_ids=selected_run_ids,
            evidence_root=output_root,
            freeze_path=freeze_path,
        )
    rows: list[dict[str, Any]] = []
    for run_dir in sorted([p for p in output_root.iterdir() if p.is_dir()], key=lambda p: p.name):
        if selected_run_ids is not None and run_dir.name not in selected_run_ids:
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


def export_protocol_ledger_csv(
    *,
    freeze_path: Path | None = None,
    require_freeze: bool = False,
) -> Path | None:
    output_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not output_root.exists():
        return None
    if require_freeze and freeze_path is None:
        raise RuntimeError("EXPORT_BLOCKED_MISSING_FREEZE: provide freeze_path in paper mode")
    if require_freeze and freeze_path is not None and not freeze_path.exists():
        raise RuntimeError(f"EXPORT_BLOCKED_MISSING_FREEZE:{freeze_path}")
    selected_run_ids = _load_freeze_included_run_ids(freeze_path) if freeze_path else None
    if selected_run_ids is not None:
        _ensure_freeze_ids_present(
            selected_run_ids=selected_run_ids,
            evidence_root=output_root,
            freeze_path=freeze_path,
        )
    freeze_contract_hash = _freeze_contract_hash(freeze_path) if freeze_path else None
    rows: list[dict[str, Any]] = []
    for run_dir in sorted([p for p in output_root.iterdir() if p.is_dir()], key=lambda p: p.name):
        if selected_run_ids is not None and run_dir.name not in selected_run_ids:
            continue
        manifest = _load_json(run_dir / "run_manifest.json")
        if not isinstance(manifest, dict):
            continue
        target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
        operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
        dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
        run_profile = str(operator.get("run_profile") or dataset.get("run_profile") or "")
        all_reasons = dataset.get("paper_exclusion_all_reason_codes")
        reason_list = [str(x) for x in all_reasons] if isinstance(all_reasons, list) else []
        protocol_reasons = [r for r in reason_list if r.startswith("EXCLUDED_SCRIPT_") or r.startswith("EXCLUDED_PROTOCOL_")]
        common = {
            "dynamic_run_id": manifest.get("dynamic_run_id") or run_dir.name,
            "package_name": target.get("package_name"),
            "run_profile": run_profile,
            "template_id": operator.get("template_id") or operator.get("scenario_template"),
            "template_hash": operator.get("template_hash") or operator.get("script_hash"),
            "interaction_protocol_version": operator.get("interaction_protocol_version"),
            "protocol_fit": operator.get("protocol_fit"),
            "protocol_violations": json.dumps(protocol_reasons, sort_keys=True),
            "technical_validity": dataset.get("technical_validity") or operator.get("technical_validity"),
            "protocol_compliance": dataset.get("protocol_compliance") or operator.get("protocol_compliance"),
            "cohort_eligibility": dataset.get("cohort_eligibility") or operator.get("cohort_eligibility"),
            "paper_eligible": dataset.get("paper_eligible"),
            "paper_exclusion_primary_reason_code": dataset.get("paper_exclusion_primary_reason_code"),
            "freeze_paper_contract_hash": freeze_contract_hash,
        }
        step_rows = _protocol_step_rows(run_dir / "notes" / "run_events.jsonl")
        if step_rows:
            for srow in step_rows:
                row = dict(common)
                row.update(srow)
                rows.append(row)
        else:
            rows.append(
                {
                    **common,
                    "step_index": None,
                    "step_id": None,
                    "step_variant": None,
                    "step_start_utc": None,
                    "step_end_utc": None,
                    "step_elapsed_s": None,
                }
            )
    if not rows:
        return None
    dest = Path(app_config.DATA_DIR) / "archive" / "protocol_ledger.csv"
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
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and path.name == "static_dynamic_plan.json":
            try:
                return enrich_dynamic_plan(payload)
            except Exception:
                # Keep exports resilient for partial/legacy plans.
                return payload
        return payload if isinstance(payload, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            text = line.strip()
            if not text:
                continue
            payload = json.loads(text)
            if isinstance(payload, dict):
                out.append(payload)
    except Exception:
        return []
    return out


def _protocol_step_rows(events_path: Path) -> list[dict[str, Any]]:
    events = _load_jsonl(events_path)
    if not events:
        return []
    step_index: dict[int, dict[str, Any]] = {}
    for e in events:
        event_type = str(e.get("event_type") or "").strip().upper()
        ts = e.get("timestamp")
        details = e.get("details") if isinstance(e.get("details"), dict) else {}
        if event_type == "STEP_START":
            idx = details.get("step_index")
            try:
                i = int(idx)
            except Exception:
                continue
            step_index.setdefault(i, {})
            step_index[i].update(
                {
                    "step_index": i,
                    "step_id": details.get("step_id"),
                    "step_variant": details.get("step_variant"),
                    "step_start_utc": ts,
                }
            )
        elif event_type == "STEP_END":
            idx = details.get("step_index")
            try:
                i = int(idx)
            except Exception:
                continue
            step_index.setdefault(i, {})
            step_index[i].update(
                {
                    "step_index": i,
                    "step_id": details.get("step_id"),
                    "step_variant": details.get("step_variant"),
                    "step_end_utc": ts,
                    "step_elapsed_s": details.get("elapsed_s"),
                }
            )
    out = []
    for i in sorted(step_index.keys()):
        row = step_index[i]
        out.append(
            {
                "step_index": row.get("step_index"),
                "step_id": row.get("step_id"),
                "step_variant": row.get("step_variant"),
                "step_start_utc": row.get("step_start_utc"),
                "step_end_utc": row.get("step_end_utc"),
                "step_elapsed_s": row.get("step_elapsed_s"),
            }
        )
    return out


def _freeze_contract_hash(freeze_path: Path | None) -> str | None:
    if freeze_path is None or not freeze_path.exists():
        return None
    payload = _load_json(freeze_path)
    if not isinstance(payload, dict):
        return None
    value = str(payload.get("paper_contract_hash") or "").strip().lower()
    return value or None


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


def _load_freeze_included_run_ids(freeze_path: Path) -> set[str]:
    payload = _load_json(freeze_path)
    if not isinstance(payload, dict):
        raise RuntimeError(f"Invalid freeze manifest JSON: {freeze_path}")
    ids = payload.get("included_run_ids")
    if not isinstance(ids, list):
        raise RuntimeError(f"Freeze manifest missing included_run_ids: {freeze_path}")
    out = {str(v).strip() for v in ids if str(v).strip()}
    if not out:
        raise RuntimeError(f"Freeze manifest has empty included_run_ids: {freeze_path}")
    return out


def _ensure_freeze_ids_present(
    *,
    selected_run_ids: set[str],
    evidence_root: Path,
    freeze_path: Path | None,
) -> None:
    available = {p.name for p in evidence_root.iterdir() if p.is_dir()}
    found = selected_run_ids.intersection(available)
    if found:
        return
    raise RuntimeError(
        "EXPORT_BLOCKED_STALE_FREEZE:"
        f"{freeze_path}:none_of_{len(selected_run_ids)}_included_run_ids_present_locally"
    )


__all__ = ["export_pcap_features_csv", "export_dynamic_run_summary_csv", "export_protocol_ledger_csv"]
