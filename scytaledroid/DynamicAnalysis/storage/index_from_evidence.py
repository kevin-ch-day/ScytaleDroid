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


def index_dynamic_evidence_pack_to_db(run_dir: Path) -> dict[str, Any]:
    row = build_dynamic_session_row_from_evidence_pack(run_dir)
    if not row:
        return {"ok": False, "reason": "missing_manifest_or_package"}
    rid = str(row.get("dynamic_run_id") or "")
    try:
        upsert_dynamic_session_row(row)
    except Exception as exc:
        return {"ok": False, "reason": f"dynamic_sessions_upsert_failed:{exc}", "dynamic_run_id": rid}

    indicators = 0
    try:
        indicators = index_network_indicators_for_run(rid, run_dir)
    except Exception:
        indicators = 0
    return {"ok": True, "dynamic_run_id": rid, "indicators_indexed": indicators}


def index_dynamic_evidence_packs_to_db(root: Path) -> dict[str, Any]:
    run_dirs = sorted([p for p in root.iterdir()] if root.exists() else [], key=lambda p: p.name)
    scanned = 0
    ok = 0
    indicators = 0
    errors: list[str] = []
    for rd in run_dirs:
        if not rd.is_dir():
            continue
        scanned += 1
        res = index_dynamic_evidence_pack_to_db(rd)
        if res.get("ok") is True:
            ok += 1
            indicators += int(res.get("indicators_indexed") or 0)
        else:
            errors.append(str(res.get("reason") or "error"))
    return {"scanned": scanned, "ok": ok, "indicators_indexed": indicators, "errors": errors[:20]}


__all__ = [
    "build_dynamic_session_row_from_evidence_pack",
    "index_dynamic_evidence_pack_to_db",
    "index_dynamic_evidence_packs_to_db",
]
