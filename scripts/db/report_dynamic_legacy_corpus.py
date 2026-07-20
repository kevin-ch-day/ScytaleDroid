#!/usr/bin/env python3
"""Read-only inventory of modern and legacy dynamic evidence for governance/reporting."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

MESSAGING_FOCUS_APPS: dict[str, str] = {
    "com.facebook.orca": "Messenger",
    "com.whatsapp": "WhatsApp",
    "org.telegram.messenger": "Telegram",
    "org.thoughtcrime.securesms": "Signal",
    "com.snapchat.android": "Snapchat",
}

COMPARISON_APPS: dict[str, str] = {
    "com.twitter.android": "X",
    "com.cnn.mobile.android.phone": "CNN",
    "bbc.mobile.news.ww": "BBC",
    "com.facebook.katana": "Facebook",
}

CLASSIFICATIONS: tuple[str, ...] = (
    "CURRENT_COUNTABLE",
    "CURRENT_SUPPLEMENTAL_LOW_SIGNAL",
    "CURRENT_SUPPLEMENTAL_EXTRA",
    "INVALID_EXCLUDED",
    "INCOMPLETE_LOCAL_PACK",
    "LEGACY_DB_ONLY_UNKNOWN",
    "LEGACY_LOCAL_RECONSTRUCTABLE",
    "LOCAL_ONLY_UNKNOWN",
    "RAW_EVIDENCE_DERIVED_MISSING",
    "UNKNOWN",
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    parser.add_argument(
        "--package",
        action="append",
        default=None,
        help="Optional package filter; may be passed more than once.",
    )
    parser.add_argument(
        "--stdout-json",
        action="store_true",
        help="Print summary JSON to stdout after writing report files.",
    )
    return parser


def _dynamic_root() -> Path:
    from scytaledroid.DynamicAnalysis.utils.path_utils import dynamic_evidence_root

    return dynamic_evidence_root()


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_legacy_corpus" / stamp


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


def _is_true(value: Any) -> bool:
    return value in (True, 1, "1", "true", "TRUE", "yes", "YES")


def _is_false(value: Any) -> bool:
    return value in (False, 0, "0", "false", "FALSE", "no", "NO")


def _has_pcap_artifact(artifacts_dir: Path) -> bool:
    if not artifacts_dir.exists():
        return False
    return any(
        path.is_file() and path.suffix.lower() in {".pcap", ".pcapng"}
        for path in artifacts_dir.rglob("*.pcap*")
    )


def _list_sample(values: Iterable[str], *, limit: int = 5) -> str:
    out: list[str] = []
    for value in values:
        text = _norm_text(value)
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return " | ".join(out)


def _first_present(mapping: Mapping[str, Any] | None, keys: Sequence[str]) -> Any:
    if not isinstance(mapping, Mapping):
        return None
    for key in keys:
        if key in mapping and mapping.get(key) not in (None, ""):
            return mapping.get(key)
    return None


def _load_app_labels(packages: Iterable[str]) -> dict[str, str]:
    normalized = sorted({_norm_text(package).lower() for package in packages if _norm_text(package)})
    if not normalized:
        return {}
    try:
        from scytaledroid.Database.db_core import db_queries as core_q

        placeholders = ", ".join(["%s"] * len(normalized))
        rows = core_q.run_sql(
            f"""
            SELECT LOWER(TRIM(package_name)) AS package_name,
                   NULLIF(display_name, '') AS display_name
            FROM apps
            WHERE LOWER(TRIM(package_name)) IN ({placeholders})
            """,
            tuple(normalized),
            fetch="all",
            dictionary=True,
            query_name="dynamic.legacy_corpus.app_labels",
        ) or []
    except Exception:
        return {}
    out: dict[str, str] = {}
    for row in rows:
        package_name = _norm_text(row.get("package_name")).lower()
        if package_name:
            out[package_name] = _norm_text(row.get("display_name"))
    return out


def _load_db_rows(package_filter: Sequence[str] | None = None) -> list[dict[str, Any]]:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception:
        return []

    sessions = core_q.run_sql(
        """
        SELECT dynamic_run_id,
               package_name,
               version_code,
               version_name,
               static_run_id,
               status,
               evidence_path,
               pcap_valid,
               pcap_bytes,
               operator_run_profile,
               operator_interaction_level,
               operator_messaging_activity,
               valid_dataset_run,
               countable,
               invalid_reason_code,
               ended_at_utc
        FROM dynamic_sessions
        """,
        fetch="all",
        dictionary=True,
        query_name="dynamic.legacy_corpus.dynamic_sessions",
    ) or []
    if package_filter:
        wanted = {_norm_text(value).lower() for value in package_filter if _norm_text(value)}
        sessions = [row for row in sessions if _norm_text(row.get("package_name")).lower() in wanted]

    run_ids = [_norm_text(row.get("dynamic_run_id")) for row in sessions if _norm_text(row.get("dynamic_run_id"))]
    if not run_ids:
        return []

    view_rows = {
        _norm_text(row.get("dynamic_run_id")): row
        for row in (
            core_q.run_sql(
                """
                SELECT *
                FROM v_dynamic_run_context_v1
                """,
                fetch="all",
                dictionary=True,
                query_name="dynamic.legacy_corpus.run_context",
            )
            or []
        )
        if _norm_text(row.get("dynamic_run_id"))
    }
    feature_rows = {
        _norm_text(row.get("dynamic_run_id")): row
        for row in (
            core_q.run_sql(
                """
                SELECT dynamic_run_id,
                       low_signal,
                       low_signal_reasons_json,
                       capture_duration_s,
                       packet_count,
                       data_size_bytes,
                       unique_dns_topn,
                       unique_sni_topn,
                       unique_domains_topn
                FROM dynamic_network_features
                """,
                fetch="all",
                dictionary=True,
                query_name="dynamic.legacy_corpus.network_features",
            )
            or []
        )
        if _norm_text(row.get("dynamic_run_id"))
    }
    indicator_counts = defaultdict(int)
    for row in (
        core_q.run_sql(
            """
            SELECT dynamic_run_id, COUNT(*) AS indicator_rows
            FROM dynamic_network_indicators
            GROUP BY dynamic_run_id
            """,
            fetch="all",
            dictionary=True,
            query_name="dynamic.legacy_corpus.network_indicators",
        )
        or []
    ):
        indicator_counts[_norm_text(row.get("dynamic_run_id"))] = _safe_int(row.get("indicator_rows"))
    domain_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in (
        core_q.run_sql(
            """
            SELECT dynamic_run_id,
                   observed_domain,
                   root_domain,
                   indicator_count
            FROM dynamic_domain_observations
            """,
            fetch="all",
            dictionary=True,
            query_name="dynamic.legacy_corpus.domain_observations",
        )
        or []
    ):
        run_id = _norm_text(row.get("dynamic_run_id"))
        if run_id:
            domain_groups[run_id].append(dict(row))

    labels = _load_app_labels(_norm_text(row.get("package_name")) for row in sessions)

    merged: list[dict[str, Any]] = []
    for row in sessions:
        run_id = _norm_text(row.get("dynamic_run_id"))
        package_name = _norm_text(row.get("package_name"))
        view = view_rows.get(run_id, {})
        feat = feature_rows.get(run_id, {})
        domains = sorted(
            domain_groups.get(run_id, []),
            key=lambda item: (-_safe_int(item.get("indicator_count")), _norm_text(item.get("observed_domain"))),
        )
        merged.append(
            {
                "dynamic_run_id": run_id,
                "package_name": package_name,
                "app_label": _norm_text(view.get("app_label")) or labels.get(package_name.lower(), ""),
                "version_code": _norm_text(view.get("version_code") or row.get("version_code")),
                "version_name": _norm_text(view.get("version_name") or row.get("version_name")),
                "static_run_id": _norm_text(view.get("static_run_id") or row.get("static_run_id")),
                "status": _norm_text(row.get("status")),
                "evidence_path": _norm_text(row.get("evidence_path")),
                "profile": _norm_text(view.get("effective_run_profile") or row.get("operator_run_profile")),
                "interaction_mode": _norm_text(view.get("effective_interaction_level") or row.get("operator_interaction_level")),
                "operator_messaging_activity": _norm_text(view.get("operator_messaging_activity") or row.get("operator_messaging_activity")),
                "valid_dataset_run": view.get("valid_dataset_run", row.get("valid_dataset_run")),
                "countable": view.get("countable", row.get("countable")),
                "quota_state": _norm_text(view.get("quota_state")),
                "technical_validity_state": _norm_text(view.get("technical_validity_state")),
                "cohort_eligibility_state": _norm_text(view.get("cohort_eligibility_state")),
                "low_signal": view.get("low_signal", feat.get("low_signal")),
                "low_signal_reasons_json": _norm_text(view.get("low_signal_reasons_json") or feat.get("low_signal_reasons_json")),
                "invalid_reason_code": _norm_text(view.get("invalid_reason_code") or row.get("invalid_reason_code")),
                "pcap_valid": view.get("pcap_valid", row.get("pcap_valid")),
                "pcap_bytes": view.get("pcap_bytes", row.get("pcap_bytes")),
                "duration_s": view.get("capture_duration_s", feat.get("capture_duration_s")),
                "packet_count": view.get("packet_count", feat.get("packet_count")),
                "dns_count": feat.get("unique_dns_topn"),
                "sni_count": feat.get("unique_sni_topn"),
                "domain_count": view.get("distinct_observed_domains", feat.get("unique_domains_topn")),
                "domain_observation_rows": view.get("domain_observation_rows"),
                "network_indicator_rows": indicator_counts.get(run_id, 0),
                "network_feature_present": run_id in feature_rows,
                "top_domains_sample": _list_sample(_norm_text(item.get("observed_domain")) for item in domains[:5]),
                "service_context_service_count": _safe_int(view.get("matched_service_count")),
                "signal_count": _safe_int(view.get("matched_signal_count")),
                "ended_at_utc": row.get("ended_at_utc"),
                "db_row_present": True,
            }
        )
    return merged


def _scan_local_evidence_packs(package_filter: Sequence[str] | None = None) -> list[dict[str, Any]]:
    root = _dynamic_root()
    wanted = {_norm_text(value).lower() for value in (package_filter or []) if _norm_text(value)}
    rows: list[dict[str, Any]] = []
    for run_dir in sorted(root.iterdir()) if root.exists() else []:
        if not run_dir.is_dir():
            continue
        manifest = _read_json(run_dir / "run_manifest.json")
        summary = _read_json(run_dir / "analysis" / "summary.json")
        pcap_report = _read_json(run_dir / "analysis" / "pcap_report.json")
        pcap_features = _read_json(run_dir / "analysis" / "pcap_features.json")
        package_name = _norm_text(
            _first_present(
                (manifest.get("target") if isinstance(manifest, Mapping) else {}) or {},
                ["package_name"],
            )
            or _first_present(
                (summary.get("target") if isinstance(summary, Mapping) else {}) or {},
                ["package_name", "package"],
            )
        )
        if wanted and package_name.lower() not in wanted:
            continue
        target = manifest.get("target") if isinstance(manifest, Mapping) else {}
        operator = manifest.get("operator") if isinstance(manifest, Mapping) else {}
        dataset = manifest.get("dataset") if isinstance(manifest, Mapping) else {}
        run_id = _norm_text(
            _first_present(manifest or {}, ["dynamic_run_id"])
            or _first_present(summary or {}, ["dynamic_run_id"])
            or run_dir.name
        )
        pcap_exists = _has_pcap_artifact(run_dir / "artifacts")
        top_domains: list[str] = []
        if isinstance(pcap_report, Mapping):
            for key in ("top_dns_qnames", "top_sni_server_names", "service_domains"):
                value = pcap_report.get(key)
                if isinstance(value, list):
                    for item in value[:5]:
                        if isinstance(item, Mapping):
                            top_domains.append(_norm_text(item.get("name") or item.get("domain") or item.get("value")))
                        else:
                            top_domains.append(_norm_text(item))
                if top_domains:
                    break
        if not top_domains and isinstance(pcap_features, Mapping):
            proxies = pcap_features.get("proxies") if isinstance(pcap_features.get("proxies"), Mapping) else {}
            for key in ("top_dns_qnames", "top_sni_names", "top_domains"):
                value = proxies.get(key) if isinstance(proxies, Mapping) else None
                if isinstance(value, list):
                    for item in value[:5]:
                        if isinstance(item, Mapping):
                            top_domains.append(_norm_text(item.get("name") or item.get("domain") or item.get("value")))
                        else:
                            top_domains.append(_norm_text(item))
                if top_domains:
                    break
        service_count = 0
        if isinstance(pcap_features, Mapping):
            service_context = pcap_features.get("service_context") if isinstance(pcap_features.get("service_context"), Mapping) else {}
            services = service_context.get("matched_services") if isinstance(service_context.get("matched_services"), list) else service_context.get("services")
            if isinstance(services, list):
                service_count = len(services)
        rows.append(
            {
                "dynamic_run_id": run_id,
                "package_name": package_name,
                "app_label": _norm_text(_first_present(target if isinstance(target, Mapping) else {}, ["display_name", "app_label"])),
                "version_code": _norm_text(_first_present(target if isinstance(target, Mapping) else {}, ["version_code", "observed_version_code"])),
                "version_name": _norm_text(_first_present(target if isinstance(target, Mapping) else {}, ["version_name"])),
                "static_run_id": _norm_text(_first_present(target if isinstance(target, Mapping) else {}, ["static_run_id"])),
                "status": _norm_text(_first_present(manifest or {}, ["status"])),
                "evidence_path": str(run_dir),
                "profile": _norm_text(_first_present(operator if isinstance(operator, Mapping) else {}, ["run_profile"])),
                "interaction_mode": _norm_text(_first_present(operator if isinstance(operator, Mapping) else {}, ["interaction_level"])),
                "operator_messaging_activity": _norm_text(_first_present(operator if isinstance(operator, Mapping) else {}, ["messaging_activity"])),
                "valid_dataset_run": dataset.get("valid_dataset_run") if isinstance(dataset, Mapping) else None,
                "countable": dataset.get("countable") if isinstance(dataset, Mapping) else None,
                "quota_state": "",
                "technical_validity_state": "",
                "cohort_eligibility_state": "",
                "low_signal": dataset.get("low_signal") if isinstance(dataset, Mapping) else None,
                "low_signal_reasons_json": json.dumps(dataset.get("low_signal_reasons"), sort_keys=True)
                if isinstance(dataset, Mapping) and isinstance(dataset.get("low_signal_reasons"), list)
                else "",
                "invalid_reason_code": _norm_text(_first_present(dataset if isinstance(dataset, Mapping) else {}, ["invalid_reason_code"])),
                "pcap_valid": _first_present(
                    (summary.get("capture") if isinstance(summary, Mapping) else {}) or {},
                    ["pcap_valid"],
                ),
                "pcap_bytes": _first_present(
                    (summary.get("capture") if isinstance(summary, Mapping) else {}) or {},
                    ["pcap_size_bytes", "total_bytes"],
                )
                or _first_present(pcap_report or {}, ["pcap_size_bytes", "bytes_total"]),
                "duration_s": _first_present(pcap_report or {}, ["capture_duration_s"])
                or _first_present((pcap_features.get("metrics") if isinstance(pcap_features, Mapping) else {}) or {}, ["capture_duration_s"]),
                "packet_count": _first_present(pcap_report or {}, ["packet_count"])
                or _first_present((pcap_features.get("metrics") if isinstance(pcap_features, Mapping) else {}) or {}, ["packet_count"]),
                "dns_count": _first_present(pcap_report or {}, ["dns_observation_count", "dns_unique_count"])
                or _first_present((pcap_features.get("visibility") if isinstance(pcap_features, Mapping) else {}) or {}, ["dns_observation_count", "unique_dns_count"]),
                "sni_count": _first_present(pcap_report or {}, ["sni_observation_count", "sni_unique_count"])
                or _first_present((pcap_features.get("visibility") if isinstance(pcap_features, Mapping) else {}) or {}, ["sni_observation_count", "unique_sni_count"]),
                "domain_count": _first_present(pcap_report or {}, ["service_domain_unique_count", "service_domain_count"])
                or _first_present((pcap_features.get("proxies") if isinstance(pcap_features, Mapping) else {}) or {}, ["unique_domains_topn"]),
                "domain_observation_rows": None,
                "network_indicator_rows": None,
                "network_feature_present": pcap_features is not None,
                "top_domains_sample": _list_sample(top_domains),
                "service_context_service_count": service_count,
                "signal_count": 0,
                "ended_at_utc": None,
                "db_row_present": False,
                "local_pack_present": True,
                "run_manifest_present": manifest is not None,
                "summary_present": summary is not None,
                "pcap_report_present": pcap_report is not None,
                "pcap_features_present": pcap_features is not None,
                "run_events_present": (run_dir / "notes" / "run_events.jsonl").exists(),
                "finalized_local": bool(_norm_text(_first_present(manifest or {}, ["status"])) == "success" and _first_present(manifest or {}, ["sealed_at"])),
                "raw_pcap_present": pcap_exists,
            }
        )
    return rows


def _merge_records(
    db_rows: Sequence[Mapping[str, Any]],
    local_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for row in db_rows:
        run_id = _norm_text(row.get("dynamic_run_id"))
        if not run_id:
            continue
        merged = dict(row)
        merged.setdefault("local_pack_present", False)
        merged.setdefault("run_manifest_present", False)
        merged.setdefault("summary_present", False)
        merged.setdefault("pcap_report_present", False)
        merged.setdefault("pcap_features_present", False)
        merged.setdefault("run_events_present", False)
        merged.setdefault("finalized_local", False)
        merged.setdefault("raw_pcap_present", False)
        by_id[run_id] = merged
    for row in local_rows:
        run_id = _norm_text(row.get("dynamic_run_id"))
        if not run_id:
            continue
        if run_id not in by_id:
            by_id[run_id] = dict(row)
            continue
        merged = by_id[run_id]
        for key, value in row.items():
            if key not in merged or merged.get(key) in (None, "", False):
                merged[key] = value
        for flag in (
            "local_pack_present",
            "run_manifest_present",
            "summary_present",
            "pcap_report_present",
            "pcap_features_present",
            "run_events_present",
            "finalized_local",
            "raw_pcap_present",
        ):
            merged[flag] = bool(merged.get(flag)) or bool(row.get(flag))
    return sorted(by_id.values(), key=lambda item: (_norm_text(item.get("package_name")), _norm_text(item.get("version_code")), _norm_text(item.get("dynamic_run_id"))))


def classify_record(record: Mapping[str, Any]) -> tuple[str, str]:
    valid = record.get("valid_dataset_run")
    countable = record.get("countable")
    low_signal = _is_true(record.get("low_signal"))
    invalid_reason = _norm_text(record.get("invalid_reason_code"))
    pcap_valid = record.get("pcap_valid")
    local_pack_present = bool(record.get("local_pack_present"))
    manifest_present = bool(record.get("run_manifest_present"))
    pcap_report_present = bool(record.get("pcap_report_present"))
    pcap_features_present = bool(record.get("pcap_features_present"))
    db_row_present = bool(record.get("db_row_present"))
    finalized_local = bool(record.get("finalized_local"))
    raw_pcap_present = bool(record.get("raw_pcap_present"))

    if _is_true(valid) and _is_true(countable):
        return ("CURRENT_COUNTABLE", "valid current-build evidence counts toward quota")
    if _is_true(valid) and _is_false(countable) and low_signal:
        return ("CURRENT_SUPPLEMENTAL_LOW_SIGNAL", "valid supplemental evidence excluded by low-signal policy")
    if _is_true(valid) and _is_false(countable):
        return ("CURRENT_SUPPLEMENTAL_EXTRA", "valid supplemental evidence retained outside quota")
    if _is_false(valid) or _is_false(pcap_valid) or invalid_reason:
        return ("INVALID_EXCLUDED", "invalid or PCAP-excluded evidence")
    if local_pack_present and not finalized_local:
        return ("INCOMPLETE_LOCAL_PACK", "local evidence pack exists but did not finalize cleanly")
    if raw_pcap_present and not (pcap_report_present or pcap_features_present):
        return ("RAW_EVIDENCE_DERIVED_MISSING", "raw PCAP exists but derived report/features are missing")
    if db_row_present and valid is None and not local_pack_present:
        return ("LEGACY_DB_ONLY_UNKNOWN", "historical DB-only row lacks modern validity contract")
    if local_pack_present and valid is None and (manifest_present or pcap_report_present or pcap_features_present):
        return ("LEGACY_LOCAL_RECONSTRUCTABLE", "historical/local evidence can be partially reconstructed from files")
    if local_pack_present and not db_row_present:
        return ("LOCAL_ONLY_UNKNOWN", "local evidence exists without a matching DB row")
    return ("UNKNOWN", "insufficient metadata to classify evidence")


def _evidence_era(record: Mapping[str, Any], classification: str) -> str:
    if classification.startswith("CURRENT_") or record.get("valid_dataset_run") is not None:
        return "MODERN_FINALIZED"
    if classification == "LEGACY_DB_ONLY_UNKNOWN":
        return "LEGACY_DB_ONLY"
    if classification == "LEGACY_LOCAL_RECONSTRUCTABLE":
        return "LEGACY_LOCAL_RECONSTRUCTABLE"
    if classification == "INCOMPLETE_LOCAL_PACK":
        return "INCOMPLETE_LOCAL"
    if classification == "LOCAL_ONLY_UNKNOWN":
        return "LOCAL_ONLY_UNKNOWN"
    return "UNKNOWN"


def _finalize_record(record: Mapping[str, Any]) -> dict[str, Any]:
    classification, reason = classify_record(record)
    out = dict(record)
    out["classification"] = classification
    out["classification_reason"] = reason
    out["evidence_era"] = _evidence_era(record, classification)
    out["db_row_present"] = "yes" if bool(out.get("db_row_present")) else "no"
    out["local_pack_present"] = "yes" if bool(out.get("local_pack_present")) else "no"
    out["run_manifest_present"] = "yes" if bool(out.get("run_manifest_present")) else "no"
    out["summary_present"] = "yes" if bool(out.get("summary_present")) else "no"
    out["pcap_report_present"] = "yes" if bool(out.get("pcap_report_present")) else "no"
    out["pcap_features_present"] = "yes" if bool(out.get("pcap_features_present")) else "no"
    out["run_events_present"] = "yes" if bool(out.get("run_events_present")) else "no"
    out["network_feature_present"] = "yes" if bool(out.get("network_feature_present")) else "no"
    return out


def _build_per_app_rollup(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        package_name = _norm_text(row.get("package_name"))
        if not package_name:
            continue
        grouped[package_name].append(row)
    rollups: list[dict[str, Any]] = []
    for package_name, items in sorted(grouped.items()):
        app_label = next((_norm_text(row.get("app_label")) for row in items if _norm_text(row.get("app_label"))), "")
        counter = Counter(_norm_text(row.get("classification")) for row in items)
        usable = [row for row in items if _safe_int(row.get("pcap_bytes")) > 0]
        domain_indexed_runs = sum(1 for row in items if _safe_int(row.get("domain_observation_rows")) > 0)
        feature_context_runs = sum(
            1
            for row in items
            if (
                row.get("network_feature_present") is True
                or _norm_text(row.get("network_feature_present")).lower() == "yes"
            )
        )
        indicator_context_runs = sum(1 for row in items if _safe_int(row.get("network_indicator_rows")) > 0)
        raw_pcap_runs = sum(
            1
            for row in items
            if (
                row.get("raw_pcap_present") is True
                or _norm_text(row.get("raw_pcap_present")).lower() == "yes"
            )
        )

        if domain_indexed_runs > 0:
            network_context_state = "domain_ready"
            ingest_guidance = "use DB domain observations for historical network context"
        elif feature_context_runs > 0 or indicator_context_runs > 0:
            network_context_state = "feature_only"
            ingest_guidance = "use feature/indicator context only; do not infer domains"
        elif counter["RAW_EVIDENCE_DERIVED_MISSING"] > 0 or raw_pcap_runs > 0:
            network_context_state = "local_rebuild_needed"
            ingest_guidance = "local raw/partial evidence exists; rebuild derived network context from pack"
        elif counter["LEGACY_DB_ONLY_UNKNOWN"] > 0:
            network_context_state = "db_only_legacy"
            ingest_guidance = "DB lineage only; recollect to recover trustworthy network context"
        else:
            network_context_state = "none"
            ingest_guidance = "no reusable network context available"

        def _median(field: str, rows: list[dict[str, Any]] = usable) -> str:
            values = [_safe_int(row.get(field), default=-1) for row in rows if _safe_int(row.get(field), default=-1) >= 0]
            return str(int(median(values))) if values else ""
        rollups.append(
            {
                "package_name": package_name,
                "app_label": app_label,
                "total_rows": len(items),
                "local_packs": sum(1 for row in items if _norm_text(row.get("local_pack_present")) == "yes"),
                "modern_finalized_rows": sum(1 for row in items if _norm_text(row.get("evidence_era")) == "MODERN_FINALIZED"),
                "countable_current": counter["CURRENT_COUNTABLE"],
                "supplemental_low_signal": counter["CURRENT_SUPPLEMENTAL_LOW_SIGNAL"],
                "supplemental_extra": counter["CURRENT_SUPPLEMENTAL_EXTRA"],
                "invalid_excluded": counter["INVALID_EXCLUDED"],
                "incomplete_local": counter["INCOMPLETE_LOCAL_PACK"],
                "legacy_db_only_unknown": counter["LEGACY_DB_ONLY_UNKNOWN"],
                "legacy_local_reconstructable": counter["LEGACY_LOCAL_RECONSTRUCTABLE"],
                "local_only_unknown": counter["LOCAL_ONLY_UNKNOWN"],
                "raw_evidence_derived_missing": counter["RAW_EVIDENCE_DERIVED_MISSING"],
                "domain_indexed_runs": domain_indexed_runs,
                "feature_context_runs": feature_context_runs,
                "indicator_context_runs": indicator_context_runs,
                "raw_pcap_runs": raw_pcap_runs,
                "network_context_state": network_context_state,
                "ingest_guidance": ingest_guidance,
                "median_pcap_bytes": _median("pcap_bytes"),
                "median_packet_count": _median("packet_count"),
                "median_domain_count": _median("domain_count"),
                "profiles_seen": _list_sample(sorted({_norm_text(row.get("profile")) for row in items if _norm_text(row.get("profile"))}), limit=10),
                "notes": _list_sample(sorted({_norm_text(row.get("classification_reason")) for row in items if _norm_text(row.get("classification_reason"))}), limit=3),
            }
        )
    return rollups


def _build_focus_rollup(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    focus = {**MESSAGING_FOCUS_APPS, **COMPARISON_APPS}
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        package_name = _norm_text(row.get("package_name"))
        if package_name in focus:
            grouped[package_name].append(row)
    out: list[dict[str, Any]] = []
    for package_name, display_label in focus.items():
        items = grouped.get(package_name, [])
        if not items:
            continue
        usable = [row for row in items if _safe_int(row.get("pcap_bytes")) > 0]
        def _median(field: str, rows: list[dict[str, Any]] = usable) -> str:
            values = [_safe_int(row.get(field), default=-1) for row in rows if _safe_int(row.get(field), default=-1) >= 0]
            return str(int(median(values))) if values else ""
        out.append(
            {
                "app_label": display_label,
                "package_name": package_name,
                "total_rows": len(items),
                "local_packs": sum(1 for row in items if _norm_text(row.get("local_pack_present")) == "yes"),
                "modern_valid": sum(1 for row in items if _is_true(row.get("valid_dataset_run"))),
                "countable_baseline_connected": sum(1 for row in items if _is_true(row.get("valid_dataset_run")) and _is_true(row.get("countable")) and _norm_text(row.get("profile")) == "baseline_connected"),
                "supplemental_baseline_connected": sum(1 for row in items if _is_true(row.get("valid_dataset_run")) and _is_false(row.get("countable")) and _norm_text(row.get("profile")) == "baseline_connected"),
                "countable_baseline_idle": sum(1 for row in items if _is_true(row.get("valid_dataset_run")) and _is_true(row.get("countable")) and _norm_text(row.get("profile")) == "baseline_idle"),
                "supplemental_low_signal_idle": sum(1 for row in items if _is_true(row.get("valid_dataset_run")) and _is_false(row.get("countable")) and _is_true(row.get("low_signal")) and _norm_text(row.get("profile")) == "baseline_idle"),
                "invalid_excluded": sum(1 for row in items if _norm_text(row.get("classification")) == "INVALID_EXCLUDED"),
                "incomplete_local": sum(1 for row in items if _norm_text(row.get("classification")) == "INCOMPLETE_LOCAL_PACK"),
                "legacy_unknown": sum(1 for row in items if _norm_text(row.get("classification")) in {"LEGACY_DB_ONLY_UNKNOWN", "LEGACY_LOCAL_RECONSTRUCTABLE", "LOCAL_ONLY_UNKNOWN"}),
                "median_pcap_bytes": _median("pcap_bytes"),
                "median_packet_count": _median("packet_count"),
                "median_domain_count": _median("domain_count"),
                "notes": _list_sample(sorted({_norm_text(row.get("classification")) for row in items if _norm_text(row.get("classification"))}), limit=4),
            }
        )
    return out


def _build_markdown_summary(rows: Sequence[Mapping[str, Any]], focus_rows: Sequence[Mapping[str, Any]]) -> str:
    counter = Counter(_norm_text(row.get("classification")) for row in rows)
    lines = [
        "# Dynamic Legacy Corpus Audit",
        "",
        f"Generated: {datetime.now(UTC).isoformat()}",
        "",
        "## Evidence Classes",
        "",
    ]
    for key in CLASSIFICATIONS:
        lines.append(f"- {key}: {counter.get(key, 0)}")
    lines.extend(
        [
            "",
            "## Messaging Baseline Focus",
            "",
            "| App | Countable connected | Supplemental low-signal idle | Invalid | Legacy unknown | Notes |",
            "| --- | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for row in focus_rows:
        lines.append(
            f"| {row.get('app_label')} | {row.get('countable_baseline_connected')} | "
            f"{row.get('supplemental_low_signal_idle')} | {row.get('invalid_excluded')} | "
            f"{row.get('legacy_unknown')} | {row.get('notes')} |"
        )
    lines.extend(
        [
            "",
            "## Governance Note",
            "",
            "This report is read-only. It does not change quota policy, tracker markings, or legacy run validity. "
            "It separates countable current-build evidence from supplemental low-signal evidence, invalid exclusions, "
            "incomplete packs, and legacy/unknown rows for paper/reporting use.",
            "",
        ]
    )
    return "\n".join(lines)


def generate_report(
    *,
    output_dir: Path | None = None,
    package_filter: Sequence[str] | None = None,
    db_rows: Sequence[Mapping[str, Any]] | None = None,
    local_rows: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    target_dir = output_dir or _default_output_dir()
    target_dir.mkdir(parents=True, exist_ok=True)

    db_records = list(db_rows) if db_rows is not None else _load_db_rows(package_filter)
    local_records = list(local_rows) if local_rows is not None else _scan_local_evidence_packs(package_filter)
    per_run_rows = [_finalize_record(row) for row in _merge_records(db_records, local_records)]
    per_app_rows = _build_per_app_rollup(per_run_rows)
    focus_rows = _build_focus_rollup(per_run_rows)

    _write_csv(target_dir / "per_run_classification.csv", per_run_rows)
    _write_csv(target_dir / "per_app_rollup.csv", per_app_rows)
    _write_csv(target_dir / "messaging_baseline_rollup.csv", focus_rows)
    (target_dir / "evidence_governance_summary.md").write_text(
        _build_markdown_summary(per_run_rows, focus_rows),
        encoding="utf-8",
    )

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "output_dir": str(target_dir),
        "total_runs": len(per_run_rows),
        "total_apps": len(per_app_rows),
        "classification_counts": dict(Counter(_norm_text(row.get("classification")) for row in per_run_rows)),
        "messaging_focus_apps": len(focus_rows),
    }
    (target_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    output_dir = Path(args.output_dir).expanduser() if args.output_dir else None
    summary = generate_report(output_dir=output_dir, package_filter=args.package)
    if args.stdout_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"[OK] Dynamic legacy corpus audit written: {summary['output_dir']}")
        print(f"[OK] Runs={summary['total_runs']} apps={summary['total_apps']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
