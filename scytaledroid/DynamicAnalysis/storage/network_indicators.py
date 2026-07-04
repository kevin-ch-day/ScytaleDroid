"""Derived indexing of dynamic network indicators into the DB.

This is intentionally derived/optional: evidence packs remain authoritative.
The DB is a cache/index to support querying patterns across runs/apps.

We only store metadata-derived indicators (DNS names, SNI names, etc).
No payload inspection and no secrets are stored here.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_core import db_queries as core_q


def extract_network_indicators_from_pcap_report(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def _append(
        kind: str,
        value: str,
        *,
        source: str,
        count: int | None = None,
        meta_json: dict[str, Any] | None = None,
    ) -> None:
        v = str(value or "").strip()
        if not v:
            return
        key = (kind, v.lower(), source)
        if key in seen:
            return
        seen.add(key)
        rows.append(
            {
                "indicator_type": kind,
                "indicator_value": v,
                "indicator_count": count,
                "indicator_source": source,
                "meta_json": meta_json,
            }
        )

    def _append_top(kind: str, items: object, *, source: str) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            value = item.get("value")
            if not isinstance(value, str):
                continue
            count = item.get("count")
            try:
                count_i = int(count) if count is not None else None
            except Exception:
                count_i = None
            _append(kind, value, source=source, count=count_i)

    _append_top("dns", report.get("top_dns"), source="top_dns")
    _append_top("sni", report.get("top_sni"), source="top_sni")

    surface = report.get("security_surface")
    if isinstance(surface, dict) and surface.get("status") == "ok":
        inventory = surface.get("domain_inventory")
        if isinstance(inventory, dict):
            for name in inventory.get("dns_names") or []:
                _append("dns", str(name), source="security_surface.dns_inventory")
            for name in inventory.get("sni_names") or []:
                _append("sni", str(name), source="security_surface.sni_inventory")
            for name in inventory.get("dns_only_samples") or []:
                _append("dns_only", str(name), source="security_surface.dns_only")
            for name in inventory.get("sni_only_samples") or []:
                _append("sni_only", str(name), source="security_surface.sni_only")

        cleartext = surface.get("cleartext")
        if isinstance(cleartext, dict):
            for item in cleartext.get("top_http_hosts") or []:
                if not isinstance(item, dict):
                    continue
                host = str(item.get("value") or "").strip()
                if not host:
                    continue
                count = item.get("count")
                try:
                    count_i = int(count) if count is not None else None
                except Exception:
                    count_i = None
                _append("http_host", host, source="security_surface.http_host", count=count_i)
            for sample in cleartext.get("sanitized_http_samples") or []:
                if not isinstance(sample, dict):
                    continue
                host = str(sample.get("host") or "").strip()
                path = str(sample.get("sanitized_path") or "").strip()
                if not host:
                    continue
                meta = {
                    "method": sample.get("method"),
                    "sanitized_path": path or None,
                    "path_class": sample.get("path_class"),
                }
                _append(
                    "http_host",
                    host,
                    source="security_surface.http_sample",
                    count=_safe_int(sample.get("rows"), default=None) if sample.get("rows") is not None else None,
                    meta_json=meta,
                )

        for flag in surface.get("risk_flags") or []:
            text = str(flag or "").strip()
            if text:
                _append("risk_flag", text, source="security_surface.risk_flag")

    return rows


def _safe_int(value: Any, *, default: int | None = None) -> int | None:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def index_network_indicators_for_run(dynamic_run_id: str, run_dir: Path) -> int:
    """Upsert indicators for a single evidence pack into dynamic_network_indicators.

    Returns: number of inserted rows (best-effort).
    """
    report_path = run_dir / "analysis" / "pcap_report.json"
    if not report_path.exists():
        return 0
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    if not isinstance(report, dict):
        return 0

    indicators = extract_network_indicators_from_pcap_report(report)
    if not indicators:
        return 0

    # Idempotent refresh: delete previous derived rows for this run and repopulate.
    core_q.run_sql_write(
        "DELETE FROM dynamic_network_indicators WHERE dynamic_run_id = %s",
        (dynamic_run_id,),
        query_name="dynamic.net_indicators.delete_run",
    )

    sql = """
        INSERT INTO dynamic_network_indicators (
          dynamic_run_id,
          indicator_type,
          indicator_value,
          indicator_count,
          indicator_source,
          meta_json
        ) VALUES (%s, %s, %s, %s, %s, %s)
    """
    data: list[tuple[object, ...]] = []
    for row in indicators:
        meta = row.get("meta_json")
        if isinstance(meta, (dict, list)):
            meta = json.dumps(meta, sort_keys=True)
        data.append(
            (
                dynamic_run_id,
                row.get("indicator_type"),
                row.get("indicator_value"),
                row.get("indicator_count"),
                row.get("indicator_source"),
                meta,
            )
        )
    core_q.run_sql_many(sql, data, query_name="dynamic.net_indicators.insert")
    return len(data)


def index_network_indicators_from_evidence_packs(root: Path) -> dict[str, Any]:
    """Index indicators for all evidence packs found under root.

    This does not create dynamic_sessions rows; it assumes sessions already exist in DB.
    If your environment is evidence-pack-only, keep using the audit report and skip this.
    """
    manifests = sorted(root.glob("*/run_manifest.json"))
    scanned = 0
    indexed = 0
    errors = 0
    for mf in manifests:
        scanned += 1
        try:
            payload = json.loads(mf.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                continue
            rid = str(payload.get("dynamic_run_id") or mf.parent.name)
            if not rid:
                continue
            # Only index if the session exists; otherwise we'd violate FK constraints.
            row = core_q.run_sql(
                "SELECT dynamic_run_id FROM dynamic_sessions WHERE dynamic_run_id=%s",
                (rid,),
                fetch="one",
                query_name="dynamic.net_indicators.session_exists",
            )
            if not row:
                continue
            indexed += index_network_indicators_for_run(rid, mf.parent)
        except Exception:
            errors += 1
            continue
    return {"scanned": scanned, "indexed_rows": indexed, "errors": errors}


__all__ = [
    "extract_network_indicators_from_pcap_report",
    "index_network_indicators_for_run",
    "index_network_indicators_from_evidence_packs",
]
