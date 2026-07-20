#!/usr/bin/env python3
"""Experimental static exposure analytics bundle (read-only, no DML/DDL).

Builds a measurement-oriented bundle over canonical static evidence:

- static exposure vectors
- category baselines
- category-relative outliers
- MASVS/control-family entropy
- permission co-occurrence
- evidence completeness gaps
- optional PCA / Jensen-Shannon outputs

This script does not change canonical scoring, write DB rows, or mutate schema.

Examples:

  PYTHONPATH=. python scripts/db/report_static_exposure_analytics.py
  PYTHONPATH=. python scripts/db/report_static_exposure_analytics.py --session 20260612-all-full
  PYTHONPATH=. python scripts/db/report_static_exposure_analytics.py --latest --verbose
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import combinations
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_MASVS_FAMILIES: tuple[str, ...] = (
    "PRIVACY",
    "PLATFORM",
    "NETWORK",
    "STORAGE",
    "CODE",
    "RESILIENCE",
)
_STRONG_VECTOR_FIELDS: tuple[str, ...] = (
    "permission_total",
    "dangerous_permission_count",
    "permission_signal_count",
    "permission_signal_score_total",
    "provider_findings",
    "fileprovider_count",
    "provider_acl_findings",
    "network_findings",
    "cleartext_findings",
    "cleartext_indicator",
    "secrets_findings",
    "high_entropy_string_count",
    "url_or_endpoint_count",
    "masvs_privacy_count",
    "masvs_platform_count",
    "masvs_network_count",
    "masvs_storage_count",
    "masvs_code_count",
    "masvs_resilience_count",
    "total_static_findings",
    "high_or_critical_findings",
    "split_count",
    "split_complexity",
    "evidence_ref_count",
)
_PARTIAL_VECTOR_FIELDS: tuple[str, ...] = (
    "exported_component_findings",
    "storage_findings",
    "evidence_gap_count",
    "evidence_completeness_ratio",
)


@dataclass(frozen=True)
class RunSelection:
    static_run_id: int
    package_name: str
    display_name: str
    raw_category: str
    category: str
    category_source: str
    category_confidence: str
    category_reason: str
    category_needs_review: bool
    session_stamp: str | None
    session_label: str | None
    scope_label: str | None
    profile_key: str | None
    publisher_key: str | None
    catalog_category_name: str | None
    version_code: int | None
    version_name: str | None
    base_apk_sha256: str | None
    artifact_set_hash: str | None
    apk_set_id: int | None
    run_class: str | None
    identity_valid: bool | None
    detector_metrics: Mapping[str, Any] | None
    repro_bundle: Mapping[str, Any] | None
    analysis_matrices: Mapping[str, Any] | None
    analysis_indicators: Mapping[str, Any] | None
    workload_profile: Mapping[str, Any] | None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", help="Restrict to one static session_stamp.")
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Select latest preferred completed static run per package.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Write outputs to this directory instead of output/audit/static_exposure/<stamp>/.",
    )
    parser.add_argument(
        "--min-category-n",
        type=int,
        default=5,
        help="Minimum category size for comparative baselines and z-scores (default: 5).",
    )
    parser.add_argument(
        "--include-partial",
        action="store_true",
        help="Include clearly marked partial dimensions such as component/storage/evidence proxies.",
    )
    parser.add_argument(
        "--no-pca",
        action="store_true",
        help="Skip exploratory PCA outputs even if dependencies/data support them.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print compact progress to stderr.",
    )
    return parser


def _json_load(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except Exception:
            return None
    return None


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _norm_text_or_none(value: Any) -> str | None:
    text = _norm_text(value)
    return text or None


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _series_mean(values: Sequence[float]) -> float | None:
    if not values:
        return None
    return sum(values) / len(values)


def _series_median(values: Sequence[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _series_std(values: Sequence[float]) -> float | None:
    if len(values) < 2:
        return 0.0 if values else None
    mean_value = _series_mean(values)
    if mean_value is None:
        return None
    variance = sum((value - mean_value) ** 2 for value in values) / (len(values) - 1)
    return math.sqrt(max(variance, 0.0))


def _percentile(values: Sequence[float], p: float) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return float(values[0])
    ordered = sorted(values)
    idx = (len(ordered) - 1) * p
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))
    if lo == hi:
        return float(ordered[lo])
    frac = idx - lo
    return float(ordered[lo] * (1.0 - frac) + ordered[hi] * frac)


def _series_iqr(values: Sequence[float]) -> float | None:
    q1 = _percentile(values, 0.25)
    q3 = _percentile(values, 0.75)
    if q1 is None or q3 is None:
        return None
    return q3 - q1


def _series_mad(values: Sequence[float]) -> float | None:
    median_value = _series_median(values)
    if median_value is None:
        return None
    deviations = [abs(value - median_value) for value in values]
    return _series_median(deviations)


def _family_from_finding(area: Any, control: Any) -> str | None:
    text = _norm_text(area) or _norm_text(control)
    if not text:
        return None
    upper = text.upper().replace("MASVS-", "")
    if upper.startswith("PRIVACY"):
        return "PRIVACY"
    if upper.startswith("PLATFORM"):
        return "PLATFORM"
    if upper.startswith("NETWORK"):
        return "NETWORK"
    if upper.startswith("STORAGE"):
        return "STORAGE"
    if upper.startswith("CRYPTO"):
        return "CODE"
    if upper.startswith("CODE"):
        return "CODE"
    if upper.startswith("RESILIENCE"):
        return "RESILIENCE"
    return None


def _is_high_or_critical(severity: Any) -> bool:
    value = _norm_text(severity).lower()
    return value in {"critical", "high", "p0", "p1", "fail"}


def _heuristic_component_finding(rule_id: Any, detector: Any, module: Any, title: Any) -> bool:
    combined = " ".join(
        token for token in (_norm_text(rule_id), _norm_text(detector), _norm_text(module), _norm_text(title)) if token
    ).lower()
    if not combined:
        return False
    markers = (
        "exported component",
        "exported activity",
        "exported service",
        "exported receiver",
        "content provider",
        "ipc",
        "fileprovider",
        "provider acl",
        "base-ipc",
    )
    return any(marker in combined for marker in markers)


def _heuristic_secret_finding(rule_id: Any, detector: Any, module: Any, title: Any) -> bool:
    combined = " ".join(
        token for token in (_norm_text(rule_id), _norm_text(detector), _norm_text(module), _norm_text(title)) if token
    ).lower()
    if not combined:
        return False
    markers = (
        "secret",
        "credential",
        "token",
        "api key",
        "key material",
        "hardcoded",
        "entropy",
    )
    return any(marker in combined for marker in markers)


def _bool_label(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"


def _table_exists(core_q: Any, name: str) -> bool:
    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS c
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
          AND table_name = %s
        """,
        (name,),
        fetch="one_dict",
        query_name="report.static_exposure.table_exists",
    ) or {}
    return bool(int(row.get("c") or 0))


def _view_exists(core_q: Any, name: str) -> bool:
    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS c
        FROM information_schema.views
        WHERE table_schema = DATABASE()
          AND table_name = %s
        """,
        (name,),
        fetch="one_dict",
        query_name="report.static_exposure.view_exists",
    ) or {}
    return bool(int(row.get("c") or 0))


def _latest_runs_sql() -> str:
    return """
    SELECT
      sar.id AS static_run_id,
      a.package_name,
      COALESCE(NULLIF(a.display_name, ''), a.package_name) AS display_name,
      COALESCE(NULLIF(sar.category, ''), cat.category_name, NULLIF(a.profile_key, ''), 'Uncategorized') AS category,
      sar.category AS run_category,
      cat.category_name AS catalog_category_name,
      a.profile_key,
      a.publisher_key,
      sar.session_stamp,
      sar.session_label,
      sar.scope_label,
      av.version_code,
      av.version_name,
      sar.base_apk_sha256,
      sar.artifact_set_hash,
      sar.apk_set_id,
      sar.run_class,
      sar.identity_valid,
      sar.detector_metrics,
      sar.repro_bundle,
      sar.analysis_matrices,
      sar.analysis_indicators,
      sar.workload_profile
    FROM static_analysis_runs sar
    JOIN app_versions av ON av.id = sar.app_version_id
    JOIN apps a ON a.id = av.app_id
    LEFT JOIN android_app_categories cat ON cat.category_id = a.category_id
    JOIN (
      SELECT
        a2.package_name,
        COALESCE(
          MAX(CASE
            WHEN UPPER(COALESCE(sar2.status, '')) = 'COMPLETED'
             AND UPPER(COALESCE(sar2.run_class, '')) = 'CANONICAL'
            THEN sar2.id
          END),
          MAX(CASE
            WHEN UPPER(COALESCE(sar2.status, '')) = 'COMPLETED'
            THEN sar2.id
          END),
          MAX(sar2.id)
        ) AS preferred_static_run_id
      FROM static_analysis_runs sar2
      JOIN app_versions av2 ON av2.id = sar2.app_version_id
      JOIN apps a2 ON a2.id = av2.app_id
      GROUP BY a2.package_name
    ) preferred
      ON preferred.package_name = a.package_name
     AND preferred.preferred_static_run_id = sar.id
    ORDER BY a.package_name ASC, sar.id ASC
    """


def _session_runs_sql() -> str:
    return """
    SELECT
      sar.id AS static_run_id,
      a.package_name,
      COALESCE(NULLIF(a.display_name, ''), a.package_name) AS display_name,
      COALESCE(NULLIF(sar.category, ''), cat.category_name, NULLIF(a.profile_key, ''), 'Uncategorized') AS category,
      sar.category AS run_category,
      cat.category_name AS catalog_category_name,
      a.profile_key,
      a.publisher_key,
      sar.session_stamp,
      sar.session_label,
      sar.scope_label,
      av.version_code,
      av.version_name,
      sar.base_apk_sha256,
      sar.artifact_set_hash,
      sar.apk_set_id,
      sar.run_class,
      sar.identity_valid,
      sar.detector_metrics,
      sar.repro_bundle,
      sar.analysis_matrices,
      sar.analysis_indicators,
      sar.workload_profile
    FROM static_analysis_runs sar
    JOIN app_versions av ON av.id = sar.app_version_id
    JOIN apps a ON a.id = av.app_id
    LEFT JOIN android_app_categories cat ON cat.category_id = a.category_id
    WHERE sar.session_stamp = %s
      AND UPPER(COALESCE(sar.status, '')) = 'COMPLETED'
    ORDER BY a.package_name ASC, sar.id ASC
    """


def _load_runs(core_q: Any, *, session: str | None) -> list[RunSelection]:
    if session:
        rows = core_q.run_sql(
            _session_runs_sql(),
            (session,),
            fetch="all_dict",
            query_name="report.static_exposure.session_runs",
        ) or []
    else:
        rows = core_q.run_sql(
            _latest_runs_sql(),
            fetch="all_dict",
            query_name="report.static_exposure.latest_runs",
        ) or []

    out: list[RunSelection] = []
    for row in rows:
        out.append(
            RunSelection(
                static_run_id=int(row["static_run_id"]),
                package_name=_norm_text(row.get("package_name")).lower(),
                display_name=_norm_text(row.get("display_name")) or _norm_text(row.get("package_name")).lower(),
                raw_category=_norm_text(row.get("category")) or "Uncategorized",
                category=_norm_text(row.get("category")) or "Uncategorized",
                category_source="initial_selection",
                category_confidence="low",
                category_reason="raw selection category before exposure-specific resolution",
                category_needs_review=False,
                session_stamp=_norm_text_or_none(row.get("session_stamp")),
                session_label=_norm_text_or_none(row.get("session_label")),
                scope_label=_norm_text_or_none(row.get("scope_label")),
                profile_key=_norm_text_or_none(row.get("profile_key")),
                publisher_key=_norm_text_or_none(row.get("publisher_key")),
                catalog_category_name=_norm_text_or_none(row.get("catalog_category_name")),
                version_code=_as_int(row.get("version_code")),
                version_name=_norm_text_or_none(row.get("version_name")),
                base_apk_sha256=_norm_text_or_none(row.get("base_apk_sha256")),
                artifact_set_hash=_norm_text_or_none(row.get("artifact_set_hash")),
                apk_set_id=_as_int(row.get("apk_set_id")),
                run_class=_norm_text_or_none(row.get("run_class")),
                identity_valid=(None if row.get("identity_valid") is None else bool(int(row.get("identity_valid") or 0))),
                detector_metrics=_json_load(row.get("detector_metrics")),
                repro_bundle=_json_load(row.get("repro_bundle")),
                analysis_matrices=_json_load(row.get("analysis_matrices")),
                analysis_indicators=_json_load(row.get("analysis_indicators")),
                workload_profile=_json_load(row.get("workload_profile")),
            )
        )
    return out


def _load_latest_inventory_metadata() -> dict[str, dict[str, Any]]:
    active_path = _REPO_ROOT / "data" / "state" / "active_device.json"
    serial: str | None = None
    try:
        payload = json.loads(active_path.read_text(encoding="utf-8"))
        if isinstance(payload, Mapping):
            serial = _norm_text_or_none(payload.get("active_serial") or payload.get("last_serial"))
    except Exception:
        serial = None
    candidate_paths: list[Path] = []
    if serial:
        candidate_paths.append(_REPO_ROOT / "data" / "state" / serial / "inventory" / "latest.json")
    candidate_paths.extend(sorted((_REPO_ROOT / "data" / "state").glob("*/inventory/latest.json")))
    for path in candidate_paths:
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        packages = payload.get("packages") if isinstance(payload, Mapping) else None
        if not isinstance(packages, list):
            continue
        out: dict[str, dict[str, Any]] = {}
        for row in packages:
            if not isinstance(row, Mapping):
                continue
            package_name = _norm_text(row.get("package_name")).lower()
            if package_name:
                out[package_name] = dict(row)
        if out:
            return out
    return {}


def _apply_category_resolution(
    runs: Sequence[RunSelection],
    *,
    resolve_category_with_provenance: Any,
    inventory_by_package: Mapping[str, Mapping[str, Any]],
) -> list[RunSelection]:
    resolved: list[RunSelection] = []
    for run in runs:
        inventory_row = inventory_by_package.get(run.package_name) or {}
        metadata: dict[str, Any] = {
            "category": run.raw_category,
            "category_name": run.catalog_category_name,
            "profile_key": run.profile_key,
            "publisher_key": run.publisher_key,
            "display_name": run.display_name,
        }
        if isinstance(inventory_row, Mapping):
            metadata.update(dict(inventory_row))
            metadata.setdefault("display_name", run.display_name)
            metadata.setdefault("profile_key", run.profile_key)
            metadata.setdefault("publisher_key", run.publisher_key)
            metadata["manual_category"] = None
        try:
            resolution = resolve_category_with_provenance(run.package_name, metadata)
        except Exception:
            resolution = None
        if resolution is None:
            category = run.raw_category
            category_source = "initial_selection"
            category_confidence = "low"
            category_reason = "resolution failed; preserved raw category"
            category_needs_review = True
        else:
            category = resolution.category
            category_source = resolution.source
            category_confidence = resolution.confidence
            category_reason = resolution.reason
            category_needs_review = bool(resolution.needs_review)
        resolved.append(
            RunSelection(
                static_run_id=run.static_run_id,
                package_name=run.package_name,
                display_name=run.display_name,
                raw_category=run.raw_category,
                category=category,
                category_source=category_source,
                category_confidence=category_confidence,
                category_reason=category_reason,
                category_needs_review=category_needs_review,
                session_stamp=run.session_stamp,
                session_label=run.session_label,
                scope_label=run.scope_label,
                profile_key=run.profile_key,
                publisher_key=run.publisher_key,
                catalog_category_name=run.catalog_category_name,
                version_code=run.version_code,
                version_name=run.version_name,
                base_apk_sha256=run.base_apk_sha256,
                artifact_set_hash=run.artifact_set_hash,
                apk_set_id=run.apk_set_id,
                run_class=run.run_class,
                identity_valid=run.identity_valid,
                detector_metrics=run.detector_metrics,
                repro_bundle=run.repro_bundle,
                analysis_matrices=run.analysis_matrices,
                analysis_indicators=run.analysis_indicators,
                workload_profile=run.workload_profile,
            )
        )
    return resolved


def _ids_sql(run_ids: Sequence[int]) -> tuple[str, tuple[Any, ...]]:
    placeholders = ",".join(["%s"] * len(run_ids))
    return placeholders, tuple(int(run_id) for run_id in run_ids)


def _load_permission_matrix(core_q: Any, run_ids: Sequence[int]) -> tuple[dict[int, dict[str, Any]], dict[int, set[str]]]:
    if not run_ids or not _table_exists(core_q, "static_permission_matrix"):
        return {}, {}
    ids_sql, params = _ids_sql(run_ids)
    rows = core_q.run_sql(
        f"""
        SELECT
          run_id,
          LOWER(TRIM(permission_name)) AS permission_name,
          is_runtime_dangerous,
          is_signature,
          is_privileged,
          is_special_access,
          is_flagged_normal
        FROM static_permission_matrix
        WHERE run_id IN ({ids_sql})
        """,
        params,
        fetch="all_dict",
        query_name="report.static_exposure.permission_matrix",
    ) or []

    agg: dict[int, dict[str, Any]] = defaultdict(
        lambda: {
            "permission_total": 0,
            "dangerous_permission_count": 0,
            "signature_permission_count": 0,
            "privileged_permission_count": 0,
            "special_access_permission_count": 0,
            "flagged_normal_permission_count": 0,
        }
    )
    per_run_perms: dict[int, set[str]] = defaultdict(set)
    for row in rows:
        run_id = int(row["run_id"])
        data = agg[run_id]
        data["permission_total"] += 1
        data["dangerous_permission_count"] += int(row.get("is_runtime_dangerous") or 0)
        data["signature_permission_count"] += int(row.get("is_signature") or 0)
        data["privileged_permission_count"] += int(row.get("is_privileged") or 0)
        data["special_access_permission_count"] += int(row.get("is_special_access") or 0)
        data["flagged_normal_permission_count"] += int(row.get("is_flagged_normal") or 0)
        permission_name = _norm_text(row.get("permission_name")).lower()
        if permission_name:
            per_run_perms[run_id].add(permission_name)
    return dict(agg), dict(per_run_perms)


def _load_permission_signals(core_q: Any, run_ids: Sequence[int]) -> dict[int, dict[str, Any]]:
    if not run_ids or not _table_exists(core_q, "permission_signal_observations"):
        return {}
    ids_sql, params = _ids_sql(run_ids)
    rows = core_q.run_sql(
        f"""
        SELECT static_run_id AS run_id, COUNT(*) AS permission_signal_count, COALESCE(SUM(score), 0) AS permission_signal_score_total
        FROM permission_signal_observations
        WHERE static_run_id IN ({ids_sql})
        GROUP BY static_run_id
        """,
        params,
        fetch="all_dict",
        query_name="report.static_exposure.permission_signals",
    ) or []
    return {
        int(row["run_id"]): {
            "permission_signal_count": int(row.get("permission_signal_count") or 0),
            "permission_signal_score_total": int(row.get("permission_signal_score_total") or 0),
        }
        for row in rows
    }


def _load_fileprovider_stats(core_q: Any, run_ids: Sequence[int]) -> dict[int, dict[str, Any]]:
    if not run_ids or not _table_exists(core_q, "static_fileproviders"):
        return {}
    ids_sql, params = _ids_sql(run_ids)
    rows = core_q.run_sql(
        f"""
        SELECT
          fp.run_id,
          COUNT(fp.id) AS fileprovider_count,
          SUM(CASE WHEN COALESCE(fp.exported, 0) = 1 THEN 1 ELSE 0 END) AS exported_provider_count,
          SUM(
            CASE
              WHEN LOWER(COALESCE(fp.effective_guard, '')) IN ('none', 'weak', 'unknown', 'broad')
              THEN 1 ELSE 0
            END
          ) AS broad_guard_provider_count,
          COUNT(acl.id) AS provider_acl_findings
        FROM static_fileproviders fp
        LEFT JOIN static_provider_acl acl ON acl.provider_id = fp.id
        WHERE fp.run_id IN ({ids_sql})
        GROUP BY fp.run_id
        """,
        params,
        fetch="all_dict",
        query_name="report.static_exposure.fileproviders",
    ) or []
    out: dict[int, dict[str, Any]] = {}
    for row in rows:
        out[int(row["run_id"])] = {
            "fileprovider_count": int(row.get("fileprovider_count") or 0),
            "provider_findings": int(row.get("fileprovider_count") or 0),
            "provider_acl_findings": int(row.get("provider_acl_findings") or 0),
            "exported_provider_count": int(row.get("exported_provider_count") or 0),
            "broad_guard_provider_count": int(row.get("broad_guard_provider_count") or 0),
        }
    return out


def _load_string_summary(core_q: Any, run_ids: Sequence[int]) -> dict[int, dict[str, Any]]:
    if not run_ids or not _table_exists(core_q, "static_string_summary"):
        return {}
    ids_sql, params = _ids_sql(run_ids)
    rows = core_q.run_sql(
        f"""
        SELECT
          static_run_id AS run_id,
          endpoints,
          http_cleartext,
          api_keys,
          analytics_ids,
          cloud_refs,
          ipc,
          uris,
          flags,
          certs,
          high_entropy,
          placeholders_downgraded,
          placeholders_suppressed,
          ws_wss_seen,
          ipv6_seen
        FROM static_string_summary
        WHERE static_run_id IN ({ids_sql})
        """,
        params,
        fetch="all_dict",
        query_name="report.static_exposure.string_summary",
    ) or []
    out: dict[int, dict[str, Any]] = {}
    for row in rows:
        run_id = int(row["run_id"])
        endpoints = int(row.get("endpoints") or 0)
        http_cleartext = int(row.get("http_cleartext") or 0)
        api_keys = int(row.get("api_keys") or 0)
        high_entropy = int(row.get("high_entropy") or 0)
        out[run_id] = {
            "url_or_endpoint_count": endpoints,
            "cleartext_findings": http_cleartext,
            "cleartext_indicator": 1 if http_cleartext > 0 else 0,
            "analytics_id_count": int(row.get("analytics_ids") or 0),
            "cloud_reference_count": int(row.get("cloud_refs") or 0),
            "ipc_string_count": int(row.get("ipc") or 0),
            "uri_string_count": int(row.get("uris") or 0),
            "flag_string_count": int(row.get("flags") or 0),
            "certificate_string_count": int(row.get("certs") or 0),
            "high_entropy_string_count": high_entropy,
            "api_key_string_count": api_keys,
            "secrets_findings": api_keys + high_entropy,
            "ws_wss_seen_count": int(row.get("ws_wss_seen") or 0),
            "ipv6_seen_count": int(row.get("ipv6_seen") or 0),
        }
    return out


def _load_findings(core_q: Any, run_ids: Sequence[int]) -> dict[int, dict[str, Any]]:
    if not run_ids or not _table_exists(core_q, "static_analysis_findings"):
        return {}
    ids_sql, params = _ids_sql(run_ids)
    rows = core_q.run_sql(
        f"""
        SELECT
          run_id,
          severity,
          rule_id,
          detector,
          module,
          title,
          masvs_area,
          masvs_control,
          evidence_refs,
          evidence
        FROM static_analysis_findings
        WHERE run_id IN ({ids_sql})
        """,
        params,
        fetch="all_dict",
        query_name="report.static_exposure.findings",
    ) or []
    out: dict[int, dict[str, Any]] = defaultdict(
        lambda: {
            "total_static_findings": 0,
            "high_or_critical_findings": 0,
            "network_findings": 0,
            "storage_findings": 0,
            "evidence_ref_count": 0,
            "exported_component_findings": 0,
            "secrets_detector_findings": 0,
            "masvs_privacy_count": 0,
            "masvs_platform_count": 0,
            "masvs_network_count": 0,
            "masvs_storage_count": 0,
            "masvs_code_count": 0,
            "masvs_crypto_count": 0,
            "masvs_resilience_count": 0,
        }
    )
    for row in rows:
        run_id = int(row["run_id"])
        data = out[run_id]
        data["total_static_findings"] += 1
        if _is_high_or_critical(row.get("severity")):
            data["high_or_critical_findings"] += 1
        family = _family_from_finding(row.get("masvs_area"), row.get("masvs_control"))
        if family == "PRIVACY":
            data["masvs_privacy_count"] += 1
        elif family == "PLATFORM":
            data["masvs_platform_count"] += 1
        elif family == "NETWORK":
            data["masvs_network_count"] += 1
            data["network_findings"] += 1
        elif family == "STORAGE":
            data["masvs_storage_count"] += 1
            data["storage_findings"] += 1
        elif family == "CODE":
            data["masvs_code_count"] += 1
            data["masvs_crypto_count"] += 1
        elif family == "RESILIENCE":
            data["masvs_resilience_count"] += 1

        evidence_refs = _json_load(row.get("evidence_refs"))
        if isinstance(evidence_refs, list):
            data["evidence_ref_count"] += len(evidence_refs)
        evidence = _json_load(row.get("evidence"))
        if isinstance(evidence, list):
            data["evidence_ref_count"] += len(evidence)

        if _heuristic_component_finding(
            row.get("rule_id"),
            row.get("detector"),
            row.get("module"),
            row.get("title"),
        ):
            data["exported_component_findings"] += 1
        if _heuristic_secret_finding(
            row.get("rule_id"),
            row.get("detector"),
            row.get("module"),
            row.get("title"),
        ):
            data["secrets_detector_findings"] += 1
    return dict(out)


def _load_apk_set_stats(core_q: Any, apk_set_ids: Sequence[int]) -> dict[int, dict[str, Any]]:
    if not apk_set_ids or not _table_exists(core_q, "apk_sets"):
        return {}
    ids_sql, params = _ids_sql(apk_set_ids)
    rows = core_q.run_sql(
        f"""
        SELECT
          apk_set_id,
          member_count,
          split_count,
          completeness_state,
          source_kind
        FROM apk_sets
        WHERE apk_set_id IN ({ids_sql})
        """,
        params,
        fetch="all_dict",
        query_name="report.static_exposure.apk_sets",
    ) or []
    return {
        int(row["apk_set_id"]): {
            "apk_member_count": int(row.get("member_count") or 0),
            "split_count": int(row.get("split_count") or 0),
            "split_complexity": int(row.get("member_count") or row.get("split_count") or 0),
            "apk_set_completeness_state": _norm_text_or_none(row.get("completeness_state")),
            "apk_set_source_kind": _norm_text_or_none(row.get("source_kind")),
        }
        for row in rows
    }


def _load_handoff_presence(core_q: Any, run_ids: Sequence[int]) -> set[int]:
    if not run_ids or not _view_exists(core_q, "v_static_handoff_v1"):
        return set()
    ids_sql, params = _ids_sql(run_ids)
    rows = core_q.run_sql(
        f"""
        SELECT static_run_id
        FROM v_static_handoff_v1
        WHERE static_run_id IN ({ids_sql})
        """,
        params,
        fetch="all_dict",
        query_name="report.static_exposure.handoff",
    ) or []
    return {int(row["static_run_id"]) for row in rows}


def _build_evidence_gap_row(
    run: RunSelection,
    vector: Mapping[str, Any],
    *,
    has_permission_matrix: bool,
    has_findings: bool,
    has_string_summary: bool,
    has_apk_set: bool,
    has_handoff: bool,
) -> dict[str, Any]:
    checks = {
        "has_base_apk_sha256": bool(run.base_apk_sha256),
        "has_artifact_set_hash": bool(run.artifact_set_hash),
        "has_permission_matrix": bool(has_permission_matrix),
        "has_findings": bool(has_findings),
        "has_string_summary": bool(has_string_summary),
        "has_apk_set_link": bool(has_apk_set),
        "has_handoff_ready_surface": bool(has_handoff),
    }
    total_checks = len(checks)
    present = sum(1 for value in checks.values() if value)
    gap_count = total_checks - present
    ratio = round(present / total_checks, 4) if total_checks else None
    warning_bits = [name for name, ok in checks.items() if not ok]
    return {
        "package_name": run.package_name,
        "display_name": run.display_name,
        "category": run.category,
        "static_run_id": run.static_run_id,
        "session_stamp": run.session_stamp,
        "version_code": run.version_code,
        "base_apk_sha256": run.base_apk_sha256,
        "artifact_set_hash": run.artifact_set_hash,
        **checks,
        "evidence_ref_count": int(vector.get("evidence_ref_count") or 0),
        "evidence_gap_count": gap_count,
        "evidence_completeness_ratio": ratio,
        "warning": ",".join(warning_bits) if warning_bits else "",
    }


def _build_vectors(
    runs: Sequence[RunSelection],
    *,
    permission_matrix: Mapping[int, Mapping[str, Any]],
    permission_signals: Mapping[int, Mapping[str, Any]],
    fileproviders: Mapping[int, Mapping[str, Any]],
    strings: Mapping[int, Mapping[str, Any]],
    findings: Mapping[int, Mapping[str, Any]],
    apk_sets: Mapping[int, Mapping[str, Any]],
    handoff_runs: set[int],
    include_partial: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    vectors: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    for run in runs:
        run_id = run.static_run_id
        vector: dict[str, Any] = {
            "package_name": run.package_name,
            "display_name": run.display_name,
            "raw_category": run.raw_category,
            "category": run.category,
            "category_source": run.category_source,
            "category_confidence": run.category_confidence,
            "category_reason": run.category_reason,
            "category_needs_review": int(run.category_needs_review),
            "session_stamp": run.session_stamp,
            "session_label": run.session_label,
            "scope_label": run.scope_label,
            "static_run_id": run.static_run_id,
            "profile_key": run.profile_key,
            "publisher_key": run.publisher_key,
            "version_code": run.version_code,
            "version_name": run.version_name,
            "base_apk_sha256": run.base_apk_sha256,
            "artifact_set_hash": run.artifact_set_hash,
            "apk_set_id": run.apk_set_id,
            "split_count": 0,
            "split_complexity": 0,
        }

        for source in (
            permission_matrix.get(run_id) or {},
            permission_signals.get(run_id) or {},
            fileproviders.get(run_id) or {},
            strings.get(run_id) or {},
            findings.get(run_id) or {},
            apk_sets.get(int(run.apk_set_id or 0)) or {},
        ):
            vector.update(source)

        if "network_findings" not in vector:
            vector["network_findings"] = int(vector.get("masvs_network_count") or 0)
        if "storage_findings" not in vector:
            vector["storage_findings"] = int(vector.get("masvs_storage_count") or 0)
        if "provider_findings" not in vector:
            vector["provider_findings"] = int(vector.get("fileprovider_count") or 0)
        if "cleartext_findings" not in vector:
            vector["cleartext_findings"] = 0
        if "cleartext_indicator" not in vector:
            vector["cleartext_indicator"] = 0
        if "secrets_findings" not in vector:
            vector["secrets_findings"] = int(vector.get("secrets_detector_findings") or 0)

        gap_row = _build_evidence_gap_row(
            run,
            vector,
            has_permission_matrix=run_id in permission_matrix,
            has_findings=run_id in findings,
            has_string_summary=run_id in strings,
            has_apk_set=bool(run.apk_set_id and int(run.apk_set_id) in apk_sets),
            has_handoff=run_id in handoff_runs,
        )
        vector["evidence_ref_count"] = int(vector.get("evidence_ref_count") or 0)
        vector["evidence_gap_count"] = int(gap_row["evidence_gap_count"])
        vector["evidence_completeness_ratio"] = gap_row["evidence_completeness_ratio"]

        if not include_partial:
            vector.pop("exported_component_findings", None)
            vector.pop("storage_findings", None)

        vectors.append(vector)
        gaps.append(gap_row)
    return vectors, gaps


def _build_category_resolution_gaps(
    runs: Sequence[RunSelection],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for run in runs:
        changed = run.category != run.raw_category
        review = bool(run.category_needs_review) or run.category == "Unknown / review"
        if not changed and not review:
            continue
        review_bucket = _review_bucket_for_run(run) if review else None
        rows.append(
            {
                "package_name": run.package_name,
                "display_name": run.display_name,
                "current_category": run.raw_category,
                "proposed_category": run.category,
                "category_source": run.category_source,
                "category_confidence": run.category_confidence,
                "category_reason": run.category_reason,
                "needs_review": int(review),
                "review_bucket": review_bucket or "",
                "profile_key": run.profile_key,
                "publisher_key": run.publisher_key,
            }
        )
    return rows


def _review_bucket_for_run(run: RunSelection) -> str | None:
    review = bool(run.category_needs_review) or run.category == "Unknown / review"
    if not review:
        return None
    if run.category_needs_review and run.category != "Unknown / review":
        return "labeled_review"
    if run.category_source == "taxonomy_gap_review":
        return "taxonomy_gap_review"
    return "ambiguous_review"


def _review_queue_summary(runs: Sequence[RunSelection]) -> dict[str, Any]:
    bucket_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    labeled_category_counts: Counter[str] = Counter()
    for run in runs:
        bucket = _review_bucket_for_run(run)
        if not bucket:
            continue
        bucket_counts[bucket] += 1
        source_counts[run.category_source or "unknown"] += 1
        if run.category != "Unknown / review":
            labeled_category_counts[run.category or "unknown"] += 1
    return {
        "bucket_distribution": dict(sorted(bucket_counts.items())),
        "source_distribution": dict(sorted(source_counts.items())),
        "labeled_category_distribution": dict(sorted(labeled_category_counts.items())),
    }


def _category_coverage_summary(runs: Sequence[RunSelection]) -> dict[str, Any]:
    before_counts: Counter[str] = Counter()
    after_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    confidence_counts: Counter[str] = Counter()
    review_flagged_count = 0
    for run in runs:
        before_counts[run.raw_category or "Uncategorized"] += 1
        after_counts[run.category or "Unknown / review"] += 1
        source_counts[run.category_source or "unknown"] += 1
        confidence_counts[run.category_confidence or "unknown"] += 1
        if run.category_needs_review:
            review_flagged_count += 1
    return {
        "before_distribution": dict(sorted(before_counts.items())),
        "after_distribution": dict(sorted(after_counts.items())),
        "source_distribution": dict(sorted(source_counts.items())),
        "confidence_distribution": dict(sorted(confidence_counts.items())),
        "before_uncategorized_count": int(before_counts.get("Uncategorized", 0) + before_counts.get("User", 0)),
        "after_unknown_review_count": int(after_counts.get("Unknown / review", 0)),
        "review_flagged_count": int(review_flagged_count),
        "heuristic_category_count": int(
            sum(count for source, count in source_counts.items() if source.startswith("heuristic"))
        ),
        "curated_category_count": int(
            sum(count for source, count in source_counts.items() if source.startswith("curated") or source.startswith("local"))
        ),
        "system_oem_platform_category_count": int(
            sum(after_counts.get(label, 0) for label in ("Platform / system", "OEM / system", "Carrier / vendor", "Google app"))
        ),
        "review_queue": _review_queue_summary(runs),
    }


def _numeric_fields(include_partial: bool) -> list[str]:
    fields = list(_STRONG_VECTOR_FIELDS)
    if include_partial:
        fields.extend(_PARTIAL_VECTOR_FIELDS)
    return fields


def _build_category_baselines(
    vectors: Sequence[Mapping[str, Any]],
    *,
    numeric_fields: Sequence[str],
    min_category_n: int,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, dict[str, Any]]], list[str]]:
    by_category: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in vectors:
        by_category[_norm_text(row.get("category")) or "Uncategorized"].append(row)

    baseline_rows: list[dict[str, Any]] = []
    baseline_map: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    warnings: list[str] = []

    for category, rows in sorted(by_category.items()):
        category_n = len(rows)
        descriptive_only = category_n < min_category_n
        if descriptive_only:
            warnings.append(f"category:{category}:n<{min_category_n}")
        for field in numeric_fields:
            values: list[float] = []
            missing_count = 0
            for row in rows:
                value = _as_float(row.get(field))
                if value is None:
                    missing_count += 1
                    continue
                values.append(value)
            mean_value = _series_mean(values)
            median_value = _series_median(values)
            std_value = _series_std(values)
            min_value = min(values) if values else None
            max_value = max(values) if values else None
            iqr_value = _series_iqr(values)
            mad_value = _series_mad(values)
            missing_rate = round(missing_count / category_n, 4) if category_n else None
            row = {
                "category": category,
                "dimension": field,
                "n": category_n,
                "value_count": len(values),
                "descriptive_only": descriptive_only,
                "mean": round(mean_value, 6) if mean_value is not None else None,
                "median": round(median_value, 6) if median_value is not None else None,
                "std": round(std_value, 6) if std_value is not None else None,
                "min": round(min_value, 6) if min_value is not None else None,
                "max": round(max_value, 6) if max_value is not None else None,
                "iqr": round(iqr_value, 6) if iqr_value is not None else None,
                "mad": round(mad_value, 6) if mad_value is not None else None,
                "missing_count": missing_count,
                "missing_rate": missing_rate,
            }
            baseline_rows.append(row)
            baseline_map[category][field] = row
    return baseline_rows, baseline_map, warnings


def _build_outliers(
    vectors: Sequence[Mapping[str, Any]],
    *,
    numeric_fields: Sequence[str],
    baseline_map: Mapping[str, Mapping[str, Mapping[str, Any]]],
    min_category_n: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    outliers: list[dict[str, Any]] = []
    warnings: list[str] = []
    for row in vectors:
        category = _norm_text(row.get("category")) or "Uncategorized"
        for field in numeric_fields:
            stats = (baseline_map.get(category) or {}).get(field) or {}
            value = _as_float(row.get(field))
            if value is None:
                continue
            n = int(stats.get("n") or 0)
            mean_value = _as_float(stats.get("mean"))
            median_value = _as_float(stats.get("median"))
            std_value = _as_float(stats.get("std"))
            mad_value = _as_float(stats.get("mad"))
            z_score = None
            robust_z_score = None
            method = "none"
            flag = False
            warning = ""
            if n < min_category_n:
                warning = f"low_sample_n<{min_category_n}"
            else:
                if std_value not in (None, 0.0) and mean_value is not None:
                    z_score = (value - mean_value) / std_value
                if mad_value not in (None, 0.0) and median_value is not None:
                    robust_z_score = 0.6745 * (value - median_value) / mad_value
                if robust_z_score is not None:
                    method = "robust_z_score"
                    flag = abs(robust_z_score) >= 3.5
                elif z_score is not None:
                    method = "z_score"
                    flag = abs(z_score) >= 3.0
                else:
                    warning = "zero_dispersion"
            if warning:
                warnings.append(f"{category}:{field}:{warning}")
            outliers.append(
                {
                    "package_name": row.get("package_name"),
                    "display_name": row.get("display_name"),
                    "category": category,
                    "static_run_id": row.get("static_run_id"),
                    "dimension": field,
                    "value": value,
                    "category_mean": mean_value,
                    "category_median": median_value,
                    "category_std": std_value,
                    "category_mad": mad_value,
                    "z_score": round(z_score, 6) if z_score is not None else None,
                    "robust_z_score": round(robust_z_score, 6) if robust_z_score is not None else None,
                    "outlier_method": method,
                    "outlier_flag": int(flag),
                    "warning": warning,
                }
            )
    return outliers, sorted(set(warnings))


def _build_entropy_and_js(
    vectors: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    entropy_rows: list[dict[str, Any]] = []
    js_rows: list[dict[str, Any]] = []
    per_category_distributions: dict[str, list[list[float]]] = defaultdict(list)
    per_app_distribution: list[tuple[Mapping[str, Any], list[float]]] = []

    for row in vectors:
        family_counts = [
            float(row.get("masvs_privacy_count") or 0),
            float(row.get("masvs_platform_count") or 0),
            float(row.get("masvs_network_count") or 0),
            float(row.get("masvs_storage_count") or 0),
            float(row.get("masvs_code_count") or 0),
            float(row.get("masvs_resilience_count") or 0),
        ]
        total = sum(family_counts)
        if total <= 0:
            distribution = [0.0 for _ in family_counts]
            entropy_value = None
            nonzero = 0
        else:
            distribution = [value / total for value in family_counts]
            entropy_value = -sum(p * math.log(p, 2) for p in distribution if p > 0)
            nonzero = sum(1 for p in distribution if p > 0)
            per_category_distributions[_norm_text(row.get("category")) or "Uncategorized"].append(distribution)
            per_app_distribution.append((row, distribution))
        entropy_rows.append(
            {
                "package_name": row.get("package_name"),
                "display_name": row.get("display_name"),
                "category": row.get("category"),
                "static_run_id": row.get("static_run_id"),
                "total_masvs_family_findings": int(total),
                "nonzero_family_count": nonzero,
                "control_entropy": round(entropy_value, 6) if entropy_value is not None else None,
                "control_dispersion": round((entropy_value / math.log(len(_MASVS_FAMILIES), 2)), 6)
                if entropy_value is not None and len(_MASVS_FAMILIES) > 1
                else None,
                "masvs_privacy_share": round(distribution[0], 6) if total > 0 else None,
                "masvs_platform_share": round(distribution[1], 6) if total > 0 else None,
                "masvs_network_share": round(distribution[2], 6) if total > 0 else None,
                "masvs_storage_share": round(distribution[3], 6) if total > 0 else None,
                "masvs_code_share": round(distribution[4], 6) if total > 0 else None,
                "masvs_resilience_share": round(distribution[5], 6) if total > 0 else None,
            }
        )

    category_means: dict[str, list[float]] = {}
    for category, distributions in per_category_distributions.items():
        if not distributions:
            continue
        sums = [0.0 for _ in _MASVS_FAMILIES]
        for distribution in distributions:
            for idx, value in enumerate(distribution):
                sums[idx] += value
        category_means[category] = [value / len(distributions) for value in sums]

    for row, distribution in per_app_distribution:
        category = _norm_text(row.get("category")) or "Uncategorized"
        mean_distribution = category_means.get(category)
        if not mean_distribution:
            continue
        js_distance = _jensen_shannon_distance(distribution, mean_distribution)
        js_rows.append(
            {
                "package_name": row.get("package_name"),
                "display_name": row.get("display_name"),
                "category": category,
                "static_run_id": row.get("static_run_id"),
                "js_control_distance": round(js_distance, 6) if js_distance is not None else None,
            }
        )
    return entropy_rows, js_rows


def _safe_kl_divergence(p: Sequence[float], q: Sequence[float]) -> float:
    total = 0.0
    for left, right in zip(p, q, strict=False):
        if left <= 0 or right <= 0:
            continue
        total += left * math.log(left / right, 2)
    return total


def _jensen_shannon_distance(p: Sequence[float], q: Sequence[float]) -> float | None:
    if not p or not q or len(p) != len(q):
        return None
    if sum(p) <= 0 or sum(q) <= 0:
        return None
    m = [(left + right) / 2.0 for left, right in zip(p, q, strict=False)]
    js_div = 0.5 * _safe_kl_divergence(p, m) + 0.5 * _safe_kl_divergence(q, m)
    return math.sqrt(max(js_div, 0.0))


def _build_permission_cooccurrence(per_run_perms: Mapping[int, set[str]]) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, str]] = Counter()
    for permissions in per_run_perms.values():
        sorted_perms = sorted(perm for perm in permissions if perm)
        for left, right in combinations(sorted_perms, 2):
            counts[(left, right)] += 1
    rows = [
        {
            "permission_left": left,
            "permission_right": right,
            "run_cooccurrence_count": count,
        }
        for (left, right), count in sorted(counts.items(), key=lambda item: (-item[1], item[0][0], item[0][1]))
    ]
    return rows


def _build_pca(
    vectors: Sequence[Mapping[str, Any]],
    *,
    numeric_fields: Sequence[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    try:
        import numpy as np
    except Exception as exc:
        return [], [], {"status": "skipped", "reason": f"numpy_unavailable:{exc.__class__.__name__}"}

    rows: list[Mapping[str, Any]] = []
    matrix_rows: list[list[float]] = []
    for row in vectors:
        values: list[float] = []
        missing = False
        for field in numeric_fields:
            value = _as_float(row.get(field))
            if value is None:
                missing = True
                break
            values.append(value)
        if missing:
            continue
        rows.append(row)
        matrix_rows.append(values)

    p = len(numeric_fields)
    if not matrix_rows or len(matrix_rows) < max(20, 3 * max(1, p)):
        return [], [], {
            "status": "skipped",
            "reason": "insufficient_complete_rows",
            "complete_rows": len(matrix_rows),
            "feature_count": p,
        }

    X = np.asarray(matrix_rows, dtype=float)
    means = X.mean(axis=0)
    stds = X.std(axis=0, ddof=1)
    keep_idx = [idx for idx, std in enumerate(stds.tolist()) if float(std) > 0.0]
    if len(keep_idx) < 2:
        return [], [], {
            "status": "skipped",
            "reason": "insufficient_nonconstant_features",
            "complete_rows": len(matrix_rows),
            "feature_count": p,
            "retained_feature_count": len(keep_idx),
        }
    X = X[:, keep_idx]
    retained_fields = [numeric_fields[idx] for idx in keep_idx]
    means = means[keep_idx]
    stds = stds[keep_idx]
    Z = (X - means) / stds
    if Z.shape[0] < max(20, 3 * Z.shape[1]):
        return [], [], {
            "status": "skipped",
            "reason": "insufficient_complete_rows_after_filter",
            "complete_rows": int(Z.shape[0]),
            "retained_feature_count": int(Z.shape[1]),
        }

    U, singular_values, Vt = np.linalg.svd(Z, full_matrices=False)
    explained_variance = (singular_values**2) / max(Z.shape[0] - 1, 1)
    total_variance = explained_variance.sum()
    explained_ratio = explained_variance / total_variance if total_variance > 0 else explained_variance
    components: list[dict[str, Any]] = []
    for pc_idx in range(Vt.shape[0]):
        for feature_idx, feature in enumerate(retained_fields):
            components.append(
                {
                    "component": f"PC{pc_idx + 1}",
                    "feature": feature,
                    "loading": round(float(Vt[pc_idx, feature_idx]), 6),
                    "explained_variance_ratio": round(float(explained_ratio[pc_idx]), 6),
                }
            )
    coordinates = U * singular_values
    app_rows: list[dict[str, Any]] = []
    for row_idx, row in enumerate(rows):
        app_rows.append(
            {
                "package_name": row.get("package_name"),
                "display_name": row.get("display_name"),
                "category": row.get("category"),
                "static_run_id": row.get("static_run_id"),
                "pc1": round(float(coordinates[row_idx, 0]), 6) if coordinates.shape[1] >= 1 else None,
                "pc2": round(float(coordinates[row_idx, 1]), 6) if coordinates.shape[1] >= 2 else None,
            }
        )
    meta = {
        "status": "generated",
        "complete_rows": int(Z.shape[0]),
        "retained_feature_count": int(Z.shape[1]),
        "retained_features": retained_fields,
    }
    return components, app_rows, meta


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                fieldnames.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_scalar(row.get(key)) for key in fieldnames})


def _csv_scalar(value: Any) -> Any:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True)
    if isinstance(value, bool):
        return int(value)
    return value


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, default=str)
        handle.write("\n")


def _default_output_dir() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return _REPO_ROOT / "output" / "audit" / "static_exposure" / stamp


def _summary_counts(vectors: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    categories = Counter(_norm_text(row.get("category")) or "Uncategorized" for row in vectors)
    return {
        "row_count": len(vectors),
        "category_count": len(categories),
        "categories": dict(sorted(categories.items())),
    }


def _log(verbose: bool, message: str) -> None:
    if verbose:
        sys.stderr.write(message.rstrip() + "\n")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.session and args.latest:
        sys.stderr.write("Choose either --session or --latest, not both.\n")
        return 1

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
        from scytaledroid.StaticAnalysis.modules.categories import resolve_category_with_provenance
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    _log(args.verbose, f"[static-exposure] output_dir={output_dir}")

    selection_mode = "session" if args.session else "latest_preferred"
    runs = _load_runs(core_q, session=args.session)
    inventory_by_package = _load_latest_inventory_metadata()
    runs = _apply_category_resolution(
        runs,
        resolve_category_with_provenance=resolve_category_with_provenance,
        inventory_by_package=inventory_by_package,
    )
    _log(args.verbose, f"[static-exposure] selected_runs={len(runs)} mode={selection_mode}")

    if not runs:
        summary = {
            "report_type": "experimental_static_exposure_analytics",
            "selection_mode": selection_mode,
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "output_dir": str(output_dir),
            "row_count": 0,
            "warnings": ["no_completed_static_runs_selected"],
            "generated_files": ["summary.json"],
            "skipped_files": [],
        }
        _write_json(output_dir / "summary.json", summary)
        print(output_dir)
        return 0

    run_ids = [run.static_run_id for run in runs]
    apk_set_ids = [int(run.apk_set_id) for run in runs if run.apk_set_id]

    permission_matrix, per_run_perms = _load_permission_matrix(core_q, run_ids)
    permission_signals = _load_permission_signals(core_q, run_ids)
    fileproviders = _load_fileprovider_stats(core_q, run_ids)
    strings = _load_string_summary(core_q, run_ids)
    findings = _load_findings(core_q, run_ids)
    apk_sets = _load_apk_set_stats(core_q, apk_set_ids)
    handoff_runs = _load_handoff_presence(core_q, run_ids)

    vectors, gaps = _build_vectors(
        runs,
        permission_matrix=permission_matrix,
        permission_signals=permission_signals,
        fileproviders=fileproviders,
        strings=strings,
        findings=findings,
        apk_sets=apk_sets,
        handoff_runs=handoff_runs,
        include_partial=bool(args.include_partial),
    )
    category_gaps = _build_category_resolution_gaps(runs)
    category_coverage = _category_coverage_summary(runs)
    category_quality_warnings: list[str] = []
    if int(category_coverage.get("after_unknown_review_count") or 0) > 0:
        category_quality_warnings.append(
            f"category_quality:unknown_review_rows={int(category_coverage.get('after_unknown_review_count') or 0)}"
        )
    if int(category_coverage.get("heuristic_category_count") or 0) > 0:
        category_quality_warnings.append(
            f"category_quality:heuristic_rows={int(category_coverage.get('heuristic_category_count') or 0)}"
        )
    numeric_fields = _numeric_fields(include_partial=bool(args.include_partial))
    baselines, baseline_map, baseline_warnings = _build_category_baselines(
        vectors,
        numeric_fields=numeric_fields,
        min_category_n=max(1, int(args.min_category_n)),
    )
    outliers, outlier_warnings = _build_outliers(
        vectors,
        numeric_fields=numeric_fields,
        baseline_map=baseline_map,
        min_category_n=max(1, int(args.min_category_n)),
    )
    entropy_rows, js_rows = _build_entropy_and_js(vectors)
    permission_pairs = _build_permission_cooccurrence(per_run_perms)

    generated_files: list[str] = []
    skipped_files: list[dict[str, Any]] = []

    _write_csv(output_dir / "static_exposure_vectors.csv", vectors)
    generated_files.append("static_exposure_vectors.csv")
    _write_csv(output_dir / "category_baselines.csv", baselines)
    generated_files.append("category_baselines.csv")
    _write_csv(output_dir / "category_outliers.csv", outliers)
    generated_files.append("category_outliers.csv")
    _write_csv(output_dir / "masvs_entropy.csv", entropy_rows)
    generated_files.append("masvs_entropy.csv")
    _write_csv(output_dir / "permission_cooccurrence.csv", permission_pairs)
    generated_files.append("permission_cooccurrence.csv")
    _write_csv(output_dir / "evidence_completeness_gaps.csv", gaps)
    generated_files.append("evidence_completeness_gaps.csv")
    _write_csv(output_dir / "category_resolution_gaps.csv", category_gaps)
    generated_files.append("category_resolution_gaps.csv")

    if js_rows:
        _write_csv(output_dir / "js_control_distances.csv", js_rows)
        generated_files.append("js_control_distances.csv")
    else:
        skipped_files.append({"file": "js_control_distances.csv", "reason": "no_nonzero_masvs_distributions"})

    pca_meta: dict[str, Any] = {"status": "skipped", "reason": "disabled"}
    if not args.no_pca:
        pca_components, pca_coords, pca_meta = _build_pca(vectors, numeric_fields=numeric_fields)
        if pca_components and pca_coords:
            _write_csv(output_dir / "pca_components.csv", pca_components)
            _write_csv(output_dir / "pca_app_coordinates.csv", pca_coords)
            generated_files.extend(["pca_components.csv", "pca_app_coordinates.csv"])
        else:
            skipped_files.append({"file": "pca_components.csv", **pca_meta})
            skipped_files.append({"file": "pca_app_coordinates.csv", **pca_meta})
    else:
        skipped_files.append({"file": "pca_components.csv", "reason": "disabled_by_flag"})
        skipped_files.append({"file": "pca_app_coordinates.csv", "reason": "disabled_by_flag"})

    db_name = (core_q.run_sql("SELECT DATABASE() AS dbname", fetch="one_dict") or {}).get("dbname")
    summary = {
        "report_type": "experimental_static_exposure_analytics",
        "selection_mode": selection_mode,
        "session_filter": args.session,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "database_name": db_name,
        "output_dir": str(output_dir),
        "include_partial": bool(args.include_partial),
        "min_category_n": max(1, int(args.min_category_n)),
        "strong_dimensions": [
            "permission exposure",
            "dangerous permission count",
            "provider/FileProvider exposure",
            "network/cleartext exposure",
            "secrets/string exposure",
            "MASVS family counts",
            "split/install-set complexity",
        ],
        "partial_dimensions_included": [
            "component exposure",
            "storage/backup posture",
            "evidence completeness proxy",
        ]
        if args.include_partial
        else [],
        "omitted_weak_dimensions": [
            "SDK inventory",
            "robust crypto scalar",
            "WebView scalar",
            "dynamic-loading scalar",
            "native-hardening scalar",
        ],
        "selection_summary": _summary_counts(vectors),
        "category_coverage": category_coverage,
        "surface_presence": {
            "permission_matrix_runs": len(permission_matrix),
            "permission_signal_runs": len(permission_signals),
            "fileprovider_runs": len(fileproviders),
            "string_summary_runs": len(strings),
            "findings_runs": len(findings),
            "apk_set_rows": len(apk_sets),
            "handoff_ready_runs": len(handoff_runs),
        },
        "warnings": sorted(set(baseline_warnings + outlier_warnings + category_quality_warnings)),
        "generated_files": generated_files + ["summary.json"],
        "skipped_files": skipped_files,
        "pca": pca_meta,
        "notes": [
            "This bundle is experimental measurement over canonical static evidence.",
            "It does not replace existing reports, grades, or permission posture surfaces.",
            "Output labels intentionally avoid generic overall risk wording.",
            "masvs_code_count currently maps from the repo's CRYPTO/CODE-family surfaces for distributional measurement.",
            "category provenance is explicit; heuristic and review classifications should not be treated as curated truth.",
        ],
    }
    _write_json(output_dir / "summary.json", summary)

    print(output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
