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

    return {
        "dynamic_run_id": rid,
        "package_name": pkg,
        "device_serial": str((target or {}).get("device_serial") or "").strip() or None,
        "scenario_id": scenario_id,
        "tier": str(ds.get("tier") or "") or None,
        "duration_seconds": int(ds.get("duration_seconds") or 0) or None,
        "sampling_rate_s": int(ds.get("sampling_rate_s") or 0) or None,
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

    # In pcap_features.json we store protocol tags under quality.protocol
    proto = qual.get("protocol") if isinstance(qual.get("protocol"), dict) else {}
    run_profile = str(proto.get("run_profile") or op.get("run_profile") or "").strip() or None
    interaction_level = str(proto.get("interaction_level") or op.get("interaction_level") or "").strip() or None

    host_tools = env.get("host_tools") if isinstance(env.get("host_tools"), dict) else None
    # Stored as JSON (string) for audit/repro; do not denormalize tool versions yet.
    host_tools_json = json.dumps(host_tools, sort_keys=True) if isinstance(host_tools, dict) else None

    return {
        "dynamic_run_id": rid,
        "package_name": pkg,
        "run_profile": run_profile,
        "interaction_level": interaction_level,
        "tier": str(ds.get("tier") or "") or None,
        "valid_dataset_run": 1 if ds.get("valid_dataset_run") is True else (0 if ds.get("valid_dataset_run") is False else None),
        "invalid_reason_code": str(ds.get("invalid_reason_code") or "") or None,
        "countable": 1 if ds.get("countable") is True else (0 if ds.get("countable") is False else None),
        "min_pcap_bytes": int(ds.get("min_pcap_bytes") or 0) or None,
        "min_duration_s": int(getattr(app_config, "DYNAMIC_MIN_DURATION_S", 120)),
        "feature_schema_version": "v1",
        "host_tools_json": host_tools_json,

        # Metrics
        "capture_duration_s": float(metrics.get("capture_duration_s")) if metrics.get("capture_duration_s") is not None else None,
        "packet_count": int(metrics.get("packet_count")) if metrics.get("packet_count") is not None else None,
        "data_size_bytes": int(metrics.get("data_size_bytes")) if metrics.get("data_size_bytes") is not None else None,
        "bytes_per_sec": float(metrics.get("bytes_per_sec")) if metrics.get("bytes_per_sec") is not None else None,
        "packets_per_sec": float(metrics.get("packets_per_sec")) if metrics.get("packets_per_sec") is not None else None,
        "avg_packet_size_bytes": float(metrics.get("avg_packet_size_bytes")) if metrics.get("avg_packet_size_bytes") is not None else None,
        "avg_packet_rate_pps": float(metrics.get("avg_packet_rate_pps")) if metrics.get("avg_packet_rate_pps") is not None else None,

        # Proxies
        "tls_ratio": float(proxies.get("tls_ratio")) if proxies.get("tls_ratio") is not None else None,
        "quic_ratio": float(proxies.get("quic_ratio")) if proxies.get("quic_ratio") is not None else None,
        "tcp_ratio": float(proxies.get("tcp_ratio")) if proxies.get("tcp_ratio") is not None else None,
        "udp_ratio": float(proxies.get("udp_ratio")) if proxies.get("udp_ratio") is not None else None,
        "unique_dns_topn": int(proxies.get("unique_dns_topn")) if proxies.get("unique_dns_topn") is not None else None,
        "unique_sni_topn": int(proxies.get("unique_sni_topn")) if proxies.get("unique_sni_topn") is not None else None,
        "unique_domains_topn": int(proxies.get("unique_domains_topn")) if proxies.get("unique_domains_topn") is not None else None,
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
