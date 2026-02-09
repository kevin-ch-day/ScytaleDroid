"""DB indexing from dynamic evidence packs (derived, optional).

Paper #2 contract:
- Evidence packs are authoritative and ML is DB-free.
- The DB is a derived index/cache to help query and compare patterns across apps.

This module builds minimal `dynamic_sessions` rows from `run_manifest.json` and
`inputs/static_dynamic_plan.json`, then (optionally) indexes network indicators.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils import diagnostics as db_diagnostics
from scytaledroid.DynamicAnalysis.pcap.timeseries import scan_pcap_timeseries_and_destinations
from scytaledroid.DynamicAnalysis.storage.network_indicators import index_network_indicators_for_run


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _to_mysql_dt(value: object) -> str | None:
    """Convert common ISO-ish timestamps to MySQL DATETIME string."""
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        if not isinstance(value, str):
            return None
        s = value.strip()
        if not s:
            return None
        # Common forms: 2026-02-07T17:06:31Z, 2026-02-07T17:06:31.123Z
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
        except Exception:
            # Fallback: already a DB string
            if len(s) >= 19 and s[4] == "-" and s[10] in (" ", "T"):
                return s[:19].replace("T", " ")
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _ensure_dynamic_network_features_columns() -> None:
    """Best-effort migration for derived/index-only columns.

    This runs only as part of the explicit "rebuild DB index from evidence packs"
    workflow (not during capture). It keeps DB optional and rebuildable.
    """

    try:
        cols = core_q.run_sql("SHOW COLUMNS FROM dynamic_network_features", fetch="all")
        existing = {str(c[0]) for c in (cols or []) if c and len(c) >= 1}
    except Exception:
        return

    alters: list[str] = []

    # Dataset/ML tags (non-authoritative; derived from run_manifest.json).
    if "low_signal" not in existing:
        alters.append("ADD COLUMN low_signal TINYINT(1) DEFAULT NULL")
    if "low_signal_reasons_json" not in existing:
        # JSON type is supported on MariaDB/MySQL; if not, it will fail and we fall back.
        alters.append("ADD COLUMN low_signal_reasons_json JSON DEFAULT NULL")

    # Window-ready per-run summaries (from pcap_features.json metrics/proxies).
    add_float = [
        "bytes_per_second_p50",
        "bytes_per_second_p95",
        "bytes_per_second_max",
        "packets_per_second_p50",
        "packets_per_second_p95",
        "packets_per_second_max",
        "burstiness_bytes_p95_over_p50",
        "burstiness_packets_p95_over_p50",
        "top1_sni_share",
        "top1_dns_share",
        "domains_per_min",
        "new_domain_rate_per_min",
        "new_sni_rate_per_min",
        "new_dns_rate_per_min",
    ]
    add_int = [
        "unique_dst_ip_count",
        "unique_dst_port_count",
        "sni_observation_count",
        "dns_observation_count",
        "unique_sni_count",
        "unique_dns_qname_count",
    ]
    for col in add_float:
        if col not in existing:
            alters.append(f"ADD COLUMN {col} DOUBLE DEFAULT NULL")
    for col in add_int:
        if col not in existing:
            alters.append(f"ADD COLUMN {col} INT DEFAULT NULL")

    if not alters:
        return

    for clause in alters:
        try:
            core_q.run_sql_write(f"ALTER TABLE dynamic_network_features {clause}")
        except Exception:
            # Fallback for older MariaDB configurations without JSON type.
            if "JSON" in clause:
                try:
                    core_q.run_sql_write(
                        "ALTER TABLE dynamic_network_features ADD COLUMN low_signal_reasons_json LONGTEXT DEFAULT NULL"
                    )
                except Exception:
                    pass


def build_dynamic_session_row_from_evidence_pack(run_dir: Path) -> dict[str, Any] | None:
    mf = _read_json(run_dir / "run_manifest.json") or {}
    if not mf:
        return None
    rid = str(mf.get("dynamic_run_id") or run_dir.name).strip()
    target = mf.get("target") if isinstance(mf.get("target"), dict) else {}
    pkg = str((target or {}).get("package_name") or "").strip()
    if not rid or not pkg:
        return None

    ds = mf.get("dataset") if isinstance(mf.get("dataset"), dict) else {}
    env = mf.get("environment") if isinstance(mf.get("environment"), dict) else {}

    scenario = mf.get("scenario") if isinstance(mf.get("scenario"), dict) else {}
    scenario_id = None
    if isinstance(scenario, dict):
        scenario_id = str(scenario.get("id") or "").strip() or None

    plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json") or {}
    ident = plan.get("run_identity") if isinstance(plan.get("run_identity"), dict) else {}

    pcap_report = _read_json(run_dir / "analysis" / "pcap_report.json") or {}
    summary = _read_json(run_dir / "analysis" / "summary.json") or {}
    telemetry = summary.get("telemetry") if isinstance(summary.get("telemetry"), dict) else {}
    telemetry_stats = telemetry.get("stats") if isinstance(telemetry.get("stats"), dict) else {}
    telemetry_quality = telemetry.get("quality") if isinstance(telemetry.get("quality"), dict) else {}

    # PCAP artifact metadata (best-effort).
    pcap_rel = None
    for a in mf.get("artifacts") or []:
        if not isinstance(a, dict):
            continue
        if a.get("type") != "pcapdroid_capture":
            continue
        rel = a.get("relative_path")
        if isinstance(rel, str) and rel:
            pcap_rel = rel
            break

    schema_version = db_diagnostics.get_schema_version() or "<unknown>"

    # Sampling rate is defined by the operator config; some older manifests do not
    # duplicate it into `dataset`. Fall back to telemetry-derived average delta.
    sampling_rate_s = ds.get("sampling_rate_s")
    if sampling_rate_s is None:
        sampling_rate_s = (mf.get("operator") or {}).get("sampling_rate_s") if isinstance(mf.get("operator"), dict) else None
    if sampling_rate_s is None:
        sampling_rate_s = telemetry_stats.get("sample_avg_delta_s")
    if sampling_rate_s is None:
        sampling_rate_s = telemetry_quality.get("avg_delta_s")
    try:
        sampling_rate_s_int = int(float(sampling_rate_s)) if sampling_rate_s is not None else None
    except Exception:
        sampling_rate_s_int = None

    def _as_int(v: object) -> int | None:
        try:
            if v is None:
                return None
            return int(v)
        except Exception:
            return None

    def _as_float(v: object) -> float | None:
        try:
            if v is None:
                return None
            return float(v)
        except Exception:
            return None

    return {
        "dynamic_run_id": rid,
        "package_name": pkg,
        "device_serial": str((target or {}).get("device_serial") or "").strip() or None,
        "scenario_id": scenario_id,
        "tier": str(ds.get("tier") or "") or None,
        "duration_seconds": int(ds.get("duration_seconds") or 0) or None,
        "sampling_rate_s": sampling_rate_s_int,
        "started_at_utc": _to_mysql_dt(mf.get("started_at")),
        "ended_at_utc": _to_mysql_dt(mf.get("ended_at")),
        "status": str(mf.get("status") or "") or None,
        "evidence_path": str(run_dir),
        "static_run_id": int(plan.get("static_run_id") or 0) or None,
        "run_signature": ident.get("run_signature"),
        "run_signature_version": ident.get("run_signature_version"),
        "base_apk_sha256": ident.get("base_apk_sha256"),
        "artifact_set_hash": ident.get("artifact_set_hash"),
        "version_name": plan.get("version_name"),
        "version_code": int(plan.get("version_code") or 0) or None,
        "netstats_available": 1 if ((mf.get("qa") or {}).get("network_quality") == "netstats_ok") else None,
        "expected_samples": _as_int(telemetry_stats.get("expected_samples")),
        "captured_samples": _as_int(telemetry_stats.get("captured_samples")),
        "sample_max_gap_s": _as_float(telemetry_stats.get("sample_max_gap_s") or telemetry_quality.get("max_gap_s")),
        "netstats_missing_rows": _as_int(telemetry_stats.get("netstats_missing_rows")),
        "netstats_rows": _as_int(telemetry_stats.get("netstats_rows")),
        "network_signal_quality": str(telemetry_stats.get("network_signal_quality") or telemetry.get("network_signal_quality") or "") or None,
        "pcap_relpath": pcap_rel,
        "pcap_bytes": int(pcap_report.get("pcap_size_bytes") or ds.get("pcap_size_bytes") or 0) or None,
        "pcap_sha256": str(pcap_report.get("pcap_sha256") or ds.get("pcap_sha256") or "") or None,
        "pcap_valid": 1
        if (pcap_report.get("report_status") == "ok" and pcap_report.get("pcap_size_bytes"))
        else (0 if ds.get("pcap_valid") is False else None),
        "pcap_validated_at_utc": _to_mysql_dt(pcap_report.get("generated_at")),
        "sampling_duration_seconds": float(ds.get("sampling_duration_seconds")) if ds.get("sampling_duration_seconds") is not None else None,
        "clock_alignment_delta_s": float(ds.get("clock_delta_seconds")) if ds.get("clock_delta_seconds") is not None else None,
        "tool_semver": app_config.APP_VERSION,
        "tool_git_commit": None,
        "schema_version": schema_version,
    }


def upsert_dynamic_session_row(row: dict[str, Any]) -> None:
    cols = list(row.keys())
    placeholders = ", ".join(["%s"] * len(cols))
    updates = ", ".join([f"{c}=VALUES({c})" for c in cols if c != "dynamic_run_id"])
    sql = f"""
        INSERT INTO dynamic_sessions ({', '.join(cols)})
        VALUES ({placeholders})
        ON DUPLICATE KEY UPDATE {updates}
    """
    core_q.run_sql_write(sql, tuple(row[c] for c in cols), query_name="dynamic.sessions.index_from_evidence")


def build_dynamic_network_features_row_from_evidence_pack(run_dir: Path) -> dict[str, Any] | None:
    """Build a derived per-run feature row from evidence-pack artifacts.

    This is intentionally conservative: it mirrors fields we already compute and
    export today (pcap_features.json + manifest dataset metadata) so the schema
    does not churn weekly.
    """
    mf = _read_json(run_dir / "run_manifest.json") or {}
    if not mf:
        return None
    rid = str(mf.get("dynamic_run_id") or run_dir.name).strip()
    target = mf.get("target") if isinstance(mf.get("target"), dict) else {}
    pkg = str((target or {}).get("package_name") or "").strip()
    if not rid or not pkg:
        return None

    ds = mf.get("dataset") if isinstance(mf.get("dataset"), dict) else {}
    op = mf.get("operator") if isinstance(mf.get("operator"), dict) else {}
    env = mf.get("environment") if isinstance(mf.get("environment"), dict) else {}

    pf = _read_json(run_dir / "analysis" / "pcap_features.json") or {}
    metrics = pf.get("metrics") if isinstance(pf.get("metrics"), dict) else {}
    proxies = pf.get("proxies") if isinstance(pf.get("proxies"), dict) else {}
    qual = pf.get("quality") if isinstance(pf.get("quality"), dict) else {}

    pr = _read_json(run_dir / "analysis" / "pcap_report.json") or {}

    # Optional accelerator: for older runs, pcap_features.json may not include the
    # window-ready enrichment metrics yet. We can derive them from the PCAP at
    # *index time* (derived DB only) without mutating evidence packs.
    need_ts = any(
        metrics.get(k) is None
        for k in (
            "bytes_per_second_p50",
            "bytes_per_second_p95",
            "bytes_per_second_max",
            "packets_per_second_p50",
            "packets_per_second_p95",
            "packets_per_second_max",
        )
    ) or any(proxies.get(k) is None for k in ("unique_dst_ip_count", "unique_dst_port_count"))

    if need_ts:
        rel = pr.get("pcap_path") if isinstance(pr.get("pcap_path"), str) else None
        pcap_path = (run_dir / rel) if rel else None
        if pcap_path and pcap_path.exists():
            try:
                ts = scan_pcap_timeseries_and_destinations(pcap_path)
            except Exception:
                ts = None
            if isinstance(ts, dict):
                for k in (
                    "bytes_per_second_p50",
                    "bytes_per_second_p95",
                    "bytes_per_second_max",
                    "packets_per_second_p50",
                    "packets_per_second_p95",
                    "packets_per_second_max",
                    "burstiness_bytes_p95_over_p50",
                    "burstiness_packets_p95_over_p50",
                ):
                    if metrics.get(k) is None and ts.get(k) is not None:
                        metrics[k] = ts.get(k)
                for k in ("unique_dst_ip_count", "unique_dst_port_count"):
                    if proxies.get(k) is None and ts.get(k) is not None:
                        proxies[k] = ts.get(k)

    # Fill missing diversity proxies from pcap_report.json (no tshark scan needed).
    def _safe_int(value: object) -> int | None:
        try:
            return int(value)  # type: ignore[arg-type]
        except Exception:
            return None

    def _top1_share(items: object) -> float | None:
        if not isinstance(items, list) or not items:
            return None
        total = 0
        top1 = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                c = int(item.get("count") or 0)
            except Exception:
                c = 0
            total += c
            if c > top1:
                top1 = c
        return (float(top1) / float(total)) if total > 0 else None

    if proxies.get("sni_observation_count") is None:
        v = _safe_int(pr.get("sni_observation_count"))
        if v is not None:
            proxies["sni_observation_count"] = v
    if proxies.get("dns_observation_count") is None:
        v = _safe_int(pr.get("dns_observation_count"))
        if v is not None:
            proxies["dns_observation_count"] = v
    if proxies.get("unique_sni_count") is None:
        v = _safe_int(pr.get("sni_unique_count"))
        if v is not None:
            proxies["unique_sni_count"] = v
    if proxies.get("unique_dns_qname_count") is None:
        v = _safe_int(pr.get("dns_unique_count"))
        if v is not None:
            proxies["unique_dns_qname_count"] = v
    if proxies.get("top1_sni_share") is None:
        v = pr.get("top1_sni_share")
        if isinstance(v, (int, float)):
            proxies["top1_sni_share"] = float(v)
        else:
            share = _top1_share(pr.get("top_sni"))
            if share is not None:
                proxies["top1_sni_share"] = share
    if proxies.get("top1_dns_share") is None:
        v = pr.get("top1_dns_share")
        if isinstance(v, (int, float)):
            proxies["top1_dns_share"] = float(v)
        else:
            share = _top1_share(pr.get("top_dns"))
            if share is not None:
                proxies["top1_dns_share"] = share

    # Derive unique-per-minute proxies if missing but duration+unique counts exist.
    dur = metrics.get("capture_duration_s")
    try:
        denom_min = float(dur) / 60.0 if dur else None
    except Exception:
        denom_min = None
    if denom_min and denom_min > 0:
        sni_u = proxies.get("unique_sni_count")
        dns_u = proxies.get("unique_dns_qname_count")
        try:
            sni_ui = int(sni_u) if sni_u is not None else 0
        except Exception:
            sni_ui = 0
        try:
            dns_ui = int(dns_u) if dns_u is not None else 0
        except Exception:
            dns_ui = 0
        if proxies.get("domains_per_min") is None and (sni_u is not None or dns_u is not None):
            proxies["domains_per_min"] = float(sni_ui + dns_ui) / float(denom_min)
        # Fallback: when report-level unique counts are missing, approximate from the
        # top-N-limited unique_domains_topn proxy (still useful as a diversity rate).
        if proxies.get("domains_per_min") is None and proxies.get("unique_domains_topn") is not None:
            try:
                ud = int(proxies.get("unique_domains_topn") or 0)
            except Exception:
                ud = 0
            proxies["domains_per_min"] = float(ud) / float(denom_min) if denom_min else None
        if proxies.get("new_domain_rate_per_min") is None and proxies.get("domains_per_min") is not None:
            proxies["new_domain_rate_per_min"] = proxies.get("domains_per_min")
        if proxies.get("new_sni_rate_per_min") is None and sni_u is not None:
            proxies["new_sni_rate_per_min"] = float(sni_ui) / float(denom_min)
        if proxies.get("new_dns_rate_per_min") is None and dns_u is not None:
            proxies["new_dns_rate_per_min"] = float(dns_ui) / float(denom_min)

    # In pcap_features.json we store protocol tags under quality.protocol
    proto = qual.get("protocol") if isinstance(qual.get("protocol"), dict) else {}
    run_profile = str(proto.get("run_profile") or op.get("run_profile") or "").strip() or None
    interaction_level = str(proto.get("interaction_level") or op.get("interaction_level") or "").strip() or None

    host_tools = env.get("host_tools") if isinstance(env.get("host_tools"), dict) else None
    # Stored as JSON (string) for audit/repro; do not denormalize tool versions yet.
    host_tools_json = json.dumps(host_tools, sort_keys=True) if isinstance(host_tools, dict) else None

    schema_ver = None
    if isinstance(pf.get("feature_schema_version"), str) and pf.get("feature_schema_version").strip():
        schema_ver = pf.get("feature_schema_version").strip()
    elif isinstance(qual.get("feature_schema_version"), str) and qual.get("feature_schema_version").strip():
        schema_ver = qual.get("feature_schema_version").strip()

    return {
        "dynamic_run_id": rid,
        "package_name": pkg,
        "run_profile": run_profile,
        "interaction_level": interaction_level,
        "tier": str(ds.get("tier") or "") or None,
        "valid_dataset_run": 1 if ds.get("valid_dataset_run") is True else (0 if ds.get("valid_dataset_run") is False else None),
        "invalid_reason_code": str(ds.get("invalid_reason_code") or "") or None,
        "countable": 1 if ds.get("countable") is True else (0 if ds.get("countable") is False else None),
        "low_signal": 1 if ds.get("low_signal") is True else (0 if ds.get("low_signal") is False else None),
        "low_signal_reasons_json": (
            json.dumps(ds.get("low_signal_reasons"), sort_keys=True)
            if isinstance(ds.get("low_signal_reasons"), list)
            else None
        ),
        "min_pcap_bytes": int(ds.get("min_pcap_bytes") or 0) or None,
        "min_duration_s": int(getattr(app_config, "DYNAMIC_MIN_DURATION_S", 120)),
        "feature_schema_version": schema_ver or "v1",
        "host_tools_json": host_tools_json,

        # Metrics
        "capture_duration_s": float(metrics.get("capture_duration_s")) if metrics.get("capture_duration_s") is not None else None,
        "packet_count": int(metrics.get("packet_count")) if metrics.get("packet_count") is not None else None,
        "data_size_bytes": int(metrics.get("data_size_bytes")) if metrics.get("data_size_bytes") is not None else None,
        "bytes_per_sec": float(metrics.get("bytes_per_sec")) if metrics.get("bytes_per_sec") is not None else None,
        "packets_per_sec": float(metrics.get("packets_per_sec")) if metrics.get("packets_per_sec") is not None else None,
        "avg_packet_size_bytes": float(metrics.get("avg_packet_size_bytes")) if metrics.get("avg_packet_size_bytes") is not None else None,
        "avg_packet_rate_pps": float(metrics.get("avg_packet_rate_pps")) if metrics.get("avg_packet_rate_pps") is not None else None,
        "bytes_per_second_p50": float(metrics.get("bytes_per_second_p50")) if metrics.get("bytes_per_second_p50") is not None else None,
        "bytes_per_second_p95": float(metrics.get("bytes_per_second_p95")) if metrics.get("bytes_per_second_p95") is not None else None,
        "bytes_per_second_max": float(metrics.get("bytes_per_second_max")) if metrics.get("bytes_per_second_max") is not None else None,
        "packets_per_second_p50": float(metrics.get("packets_per_second_p50")) if metrics.get("packets_per_second_p50") is not None else None,
        "packets_per_second_p95": float(metrics.get("packets_per_second_p95")) if metrics.get("packets_per_second_p95") is not None else None,
        "packets_per_second_max": float(metrics.get("packets_per_second_max")) if metrics.get("packets_per_second_max") is not None else None,
        "burstiness_bytes_p95_over_p50": float(metrics.get("burstiness_bytes_p95_over_p50")) if metrics.get("burstiness_bytes_p95_over_p50") is not None else None,
        "burstiness_packets_p95_over_p50": float(metrics.get("burstiness_packets_p95_over_p50")) if metrics.get("burstiness_packets_p95_over_p50") is not None else None,

        # Proxies
        "tls_ratio": float(proxies.get("tls_ratio")) if proxies.get("tls_ratio") is not None else None,
        "quic_ratio": float(proxies.get("quic_ratio")) if proxies.get("quic_ratio") is not None else None,
        "tcp_ratio": float(proxies.get("tcp_ratio")) if proxies.get("tcp_ratio") is not None else None,
        "udp_ratio": float(proxies.get("udp_ratio")) if proxies.get("udp_ratio") is not None else None,
        "unique_dns_topn": int(proxies.get("unique_dns_topn")) if proxies.get("unique_dns_topn") is not None else None,
        "unique_sni_topn": int(proxies.get("unique_sni_topn")) if proxies.get("unique_sni_topn") is not None else None,
        "unique_domains_topn": int(proxies.get("unique_domains_topn")) if proxies.get("unique_domains_topn") is not None else None,
        "unique_dst_ip_count": int(proxies.get("unique_dst_ip_count")) if proxies.get("unique_dst_ip_count") is not None else None,
        "unique_dst_port_count": int(proxies.get("unique_dst_port_count")) if proxies.get("unique_dst_port_count") is not None else None,
        "sni_observation_count": int(proxies.get("sni_observation_count")) if proxies.get("sni_observation_count") is not None else None,
        "dns_observation_count": int(proxies.get("dns_observation_count")) if proxies.get("dns_observation_count") is not None else None,
        "unique_sni_count": int(proxies.get("unique_sni_count")) if proxies.get("unique_sni_count") is not None else None,
        "unique_dns_qname_count": int(proxies.get("unique_dns_qname_count")) if proxies.get("unique_dns_qname_count") is not None else None,
        "top1_sni_share": float(proxies.get("top1_sni_share")) if proxies.get("top1_sni_share") is not None else None,
        "top1_dns_share": float(proxies.get("top1_dns_share")) if proxies.get("top1_dns_share") is not None else None,
        "domains_per_min": float(proxies.get("domains_per_min")) if proxies.get("domains_per_min") is not None else None,
        "new_domain_rate_per_min": float(proxies.get("new_domain_rate_per_min")) if proxies.get("new_domain_rate_per_min") is not None else None,
        "new_sni_rate_per_min": float(proxies.get("new_sni_rate_per_min")) if proxies.get("new_sni_rate_per_min") is not None else None,
        "new_dns_rate_per_min": float(proxies.get("new_dns_rate_per_min")) if proxies.get("new_dns_rate_per_min") is not None else None,
        "top_dns_total": int(proxies.get("top_dns_total")) if proxies.get("top_dns_total") is not None else None,
        "top_sni_total": int(proxies.get("top_sni_total")) if proxies.get("top_sni_total") is not None else None,
        "dns_concentration": float(proxies.get("dns_concentration")) if proxies.get("dns_concentration") is not None else None,
        "sni_concentration": float(proxies.get("sni_concentration")) if proxies.get("sni_concentration") is not None else None,
    }


def upsert_dynamic_network_features_row(row: dict[str, Any]) -> None:
    cols = list(row.keys())
    placeholders = ", ".join(["%s"] * len(cols))
    updates = ", ".join([f"{c}=VALUES({c})" for c in cols if c != "dynamic_run_id"])
    sql = f"""
        INSERT INTO dynamic_network_features ({', '.join(cols)})
        VALUES ({placeholders})
        ON DUPLICATE KEY UPDATE {updates}
    """
    core_q.run_sql_write(sql, tuple(row[c] for c in cols), query_name="dynamic.network_features.index_from_evidence")


def index_dynamic_evidence_pack_to_db(run_dir: Path) -> dict[str, Any]:
    row = build_dynamic_session_row_from_evidence_pack(run_dir)
    if not row:
        return {"ok": False, "reason": "missing_manifest_or_package"}
    rid = str(row.get("dynamic_run_id") or "")
    try:
        upsert_dynamic_session_row(row)
    except Exception as exc:
        return {"ok": False, "reason": f"dynamic_sessions_upsert_failed:{exc}", "dynamic_run_id": rid}

    features_upserted = 0
    feat_row = build_dynamic_network_features_row_from_evidence_pack(run_dir)
    if feat_row:
        try:
            upsert_dynamic_network_features_row(feat_row)
            features_upserted = 1
        except Exception:
            features_upserted = 0

    indicators = 0
    try:
        indicators = index_network_indicators_for_run(rid, run_dir)
    except Exception:
        indicators = 0
    return {
        "ok": True,
        "dynamic_run_id": rid,
        "network_features_upserted": features_upserted,
        "indicators_indexed": indicators,
    }


def index_dynamic_evidence_packs_to_db(root: Path) -> dict[str, Any]:
    _ensure_dynamic_network_features_columns()
    run_dirs = sorted([p for p in root.iterdir()] if root.exists() else [], key=lambda p: p.name)
    scanned = 0
    ok = 0
    features = 0
    indicators = 0
    errors: list[str] = []
    for rd in run_dirs:
        if not rd.is_dir():
            continue
        # Skip ghost dirs early (no manifest) to keep rebuild noise-free.
        if not (rd / "run_manifest.json").exists():
            continue
        scanned += 1
        res = index_dynamic_evidence_pack_to_db(rd)
        if res.get("ok") is True:
            ok += 1
            indicators += int(res.get("indicators_indexed") or 0)
            features += int(res.get("network_features_upserted") or 0)
        else:
            errors.append(str(res.get("reason") or "error"))
    return {
        "scanned": scanned,
        "ok": ok,
        "network_features_upserted": features,
        "indicators_indexed": indicators,
        "errors": errors[:20],
    }


__all__ = [
    "build_dynamic_session_row_from_evidence_pack",
    "build_dynamic_network_features_row_from_evidence_pack",
    "index_dynamic_evidence_pack_to_db",
    "index_dynamic_evidence_packs_to_db",
]
