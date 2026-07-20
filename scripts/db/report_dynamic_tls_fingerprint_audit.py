#!/usr/bin/env python3
"""Read-only audit of TLS fingerprint population and diversity across dynamic evidence."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scytaledroid.DynamicAnalysis.run_qualification import analysis_included_rows
from scytaledroid.Publication.app_category_policy import app_display_name

FOCUS_PACKAGES: dict[str, str] = {
    package_name: app_display_name(package_name, package_name)
    for package_name in (
        "bbc.mobile.news.ww",
        "com.cnn.mobile.android.phone",
        "com.facebook.katana",
        "com.facebook.orca",
        "com.guardian",
        "com.twitter.android",
        "com.whatsapp",
        "com.zhiliaoapp.musically",
    )
}

FINGERPRINT_RUN_FIELDS = (
    "app_label",
    "package_name",
    "version_code",
    "version_name",
    "run_id",
    "run_profile",
    "interaction_mode",
    "mode_bucket",
    "valid_dataset_run",
    "countable",
    "technical_validity_state",
    "quota_state",
    "pcap_valid",
    "pcap_bytes",
    "domains_count",
    "sni_count",
    "tls_client_hello_count",
    "tls_server_hello_count",
    "unique_ja3_count",
    "unique_ja3s_count",
    "unique_ja4_count",
    "top_ja3",
    "top_ja3_share",
    "top_ja4",
    "top_ja4_share",
    "top_alpn",
    "top_sni",
    "service_families_observed",
    "service_categories_csv",
    "service_keys_csv",
    "owner_classes_csv",
    "role_classes_csv",
    "quic_candidate_packets",
    "tls_handshake_packets",
    "invalid_reason_code",
)

FINGERPRINT_APP_ROLLUP_FIELDS = (
    "app_label",
    "package_name",
    "countable_runs",
    "analysis_included_runs",
    "supplemental_runs",
    "median_unique_ja3_count",
    "median_unique_ja4_count",
    "median_unique_ja3s_count",
    "max_unique_ja4_count",
    "median_top_ja4_share",
    "baseline_fingerprint_diversity",
    "interactive_fingerprint_diversity",
    "baseline_median_unique_ja4_count",
    "interactive_median_unique_ja4_count",
    "service_families_observed",
    "interpretation",
)

FINGERPRINT_PAPER_TABLE_FIELDS = (
    "app",
    "package_name",
    "countable_runs",
    "analysis_included_runs",
    "runtime_domains_median",
    "unique_ja4_median",
    "unique_ja3_median",
    "top_ja4_share_median",
    "main_service_families",
    "interpretation",
)

FINGERPRINT_BASELINE_INTERACTIVE_FIELDS = (
    "app_label",
    "package_name",
    "baseline_runs",
    "interactive_runs",
    "baseline_median_unique_ja4_count",
    "interactive_median_unique_ja4_count",
    "baseline_median_top_ja4_share",
    "interactive_median_top_ja4_share",
)

FINGERPRINT_RECOMPUTE_MISMATCH_FIELDS = (
    "dynamic_run_id",
    "package_name",
    "app_label",
    "run_profile",
    "domains_count",
    "db_unique_ja4_count",
    "recomputed_unique_ja4_count",
    "recomputed_top_ja4",
    "pcap_bytes",
    "evidence_path",
    "diagnosis",
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package",
        action="append",
        default=[],
        help="Restrict the audit to one or more package names. May be passed more than once.",
    )
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    parser.add_argument(
        "--stdout-json",
        action="store_true",
        help="Print summary JSON to stdout after writing report files.",
    )
    parser.add_argument(
        "--recompute-top-values",
        action="store_true",
        help=(
            "Read saved PCAPs to recompute top JA3/JA4/ALPN/SNI values when old pcap_report.json "
            "files do not already contain TLS fingerprint summaries."
        ),
    )
    return parser


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]], *, fieldnames: Sequence[str] | None = None) -> None:
    row_list = list(rows)
    resolved_fieldnames: list[str] = [str(key) for key in (fieldnames or ())]
    for row in row_list:
        for key in row:
            if key not in resolved_fieldnames:
                resolved_fieldnames.append(str(key))
    if not resolved_fieldnames:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=resolved_fieldnames)
        writer.writeheader()
        for row in row_list:
            writer.writerow({key: row.get(key) for key in resolved_fieldnames})


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_tls_fingerprint_audit" / stamp


def _sql_list_filters(packages: Sequence[str]) -> tuple[str, tuple[str, ...]]:
    normalized = tuple(sorted({_norm_text(value).lower() for value in packages if _norm_text(value)}))
    if not normalized:
        return "", ()
    placeholders = ", ".join(["%s"] * len(normalized))
    return f"WHERE LOWER(TRIM(ctx.package_name)) IN ({placeholders})", normalized


def _interaction_mode(run_profile: str, interaction_level: str) -> str:
    profile = _norm_text(run_profile).lower()
    level = _norm_text(interaction_level).lower()
    if profile.startswith("baseline"):
        return "baseline"
    if "script" in profile:
        return "scripted"
    if "manual" in profile:
        return "manual"
    if level:
        return level
    if profile.startswith("interaction") or profile.startswith("interactive"):
        return "interactive"
    return "unknown"


def _mode_bucket(run_profile: str, interaction_level: str) -> str:
    return "baseline" if _interaction_mode(run_profile, interaction_level) == "baseline" else "interactive"


def _first_top_value(items: Any) -> str:
    if not isinstance(items, list) or not items:
        return ""
    first = items[0]
    if not isinstance(first, Mapping):
        return ""
    return _norm_text(first.get("value"))


def _first_top_count(items: Any) -> int | None:
    if not isinstance(items, list) or not items:
        return None
    first = items[0]
    if not isinstance(first, Mapping):
        return None
    return _safe_int(first.get("count"))


def _find_pcap_path(evidence_root: Path) -> Path | None:
    capture_dir = evidence_root / "artifacts" / "pcapdroid_capture"
    for name in ("capture.pcap", "capture.pcapng"):
        direct = capture_dir / name
        if direct.is_file():
            return direct
    for path in sorted(capture_dir.glob("*.pcap*")):
        if path.is_file() and path.suffix.lower() in {".pcap", ".pcapng"}:
            return path
    return None


def _coerce_tls_items(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    data = dict(payload or {})
    data.setdefault("top_ja3", [])
    data.setdefault("top_ja4", [])
    data.setdefault("top_ja3s", [])
    data.setdefault("top_alpn", [])
    data.setdefault("top_sni_from_client_hello", [])
    return data


def _load_run_rows(packages: Sequence[str]) -> list[dict[str, Any]]:
    from scytaledroid.Database.db_core import db_queries as core_q

    where_sql, params = _sql_list_filters(packages)
    query = f"""
        SELECT
          ctx.dynamic_run_id,
          ctx.package_name,
          ctx.app_label,
          ctx.version_code,
          ctx.version_name,
          ctx.effective_run_profile,
          ctx.effective_interaction_level,
          ctx.technical_validity_state,
          ctx.quota_state,
          ctx.valid_dataset_run,
          ctx.countable,
          ctx.pcap_valid,
          ctx.pcap_bytes,
          ctx.distinct_observed_domains,
          ctx.tls_sni_unique_count,
          ctx.tls_client_hello_count,
          ctx.tls_server_hello_count,
          ctx.unique_ja3_count,
          ctx.unique_ja3s_count,
          ctx.unique_ja4_count,
          ctx.top1_ja3_share,
          ctx.top1_ja4_share,
          ctx.top1_ja3s_share,
          ctx.tls_handshake_packets,
          ctx.quic_candidate_packets,
          ctx.matched_service_count,
          ctx.owner_classes_csv,
          ctx.role_classes_csv,
          ctx.service_keys_csv,
          ds.evidence_path,
          ds.pcap_relpath,
          ds.invalid_reason_code
        FROM v_dynamic_run_context_v1 ctx
        JOIN dynamic_sessions ds
          ON ds.dynamic_run_id = ctx.dynamic_run_id
        {where_sql}
        ORDER BY ctx.package_name, ctx.ended_at_utc, ctx.dynamic_run_id
    """
    return core_q.run_sql(
        query,
        params,
        fetch="all",
        dictionary=True,
        query_name="dynamic.tls_fingerprint_audit.run_rows",
    ) or []


def _load_service_family_rows(packages: Sequence[str]) -> dict[str, dict[str, str]]:
    from scytaledroid.Database.db_core import db_queries as core_q

    where_sql, params = _sql_list_filters(packages)
    query = f"""
        SELECT
          ctx.dynamic_run_id,
          GROUP_CONCAT(DISTINCT svc.service_category ORDER BY svc.service_category SEPARATOR ',') AS service_categories_csv,
          GROUP_CONCAT(DISTINCT svc.owner_class ORDER BY svc.owner_class SEPARATOR ',') AS service_owner_classes_csv,
          GROUP_CONCAT(DISTINCT svc.owner_name ORDER BY svc.owner_name SEPARATOR ',') AS service_owner_names_csv
        FROM v_dynamic_run_context_v1 ctx
        LEFT JOIN dynamic_domain_observations obs
          ON obs.dynamic_run_id = ctx.dynamic_run_id
        LEFT JOIN dynamic_service_domain_map sdm
          ON sdm.is_active = 1
         AND (
              LOWER(TRIM(COALESCE(sdm.package_name_scope, ''))) = ''
              OR CONVERT(sdm.package_name_scope USING utf8mb4) COLLATE utf8mb4_general_ci =
                 CONVERT(obs.package_name USING utf8mb4) COLLATE utf8mb4_general_ci
         )
         AND (
              (
                UPPER(TRIM(COALESCE(sdm.match_type, ''))) = 'EXACT'
                AND LOWER(TRIM(COALESCE(obs.observed_domain, ''))) = LOWER(TRIM(COALESCE(sdm.domain_pattern, '')))
              )
              OR
              (
                UPPER(TRIM(COALESCE(sdm.match_type, ''))) = 'SUFFIX'
                AND (
                  LOWER(TRIM(COALESCE(obs.observed_domain, ''))) = LOWER(TRIM(COALESCE(sdm.domain_pattern, '')))
                  OR LOWER(TRIM(COALESCE(obs.observed_domain, ''))) LIKE CONCAT('%%.', LOWER(TRIM(COALESCE(sdm.domain_pattern, ''))))
                )
              )
         )
        LEFT JOIN dynamic_service_catalog svc
          ON svc.service_id = sdm.service_id
         AND svc.is_active = 1
        {where_sql}
        GROUP BY ctx.dynamic_run_id
    """
    rows = core_q.run_sql(
        query,
        params,
        fetch="all",
        dictionary=True,
        query_name="dynamic.tls_fingerprint_audit.service_families",
    ) or []
    return {
        _norm_text(row.get("dynamic_run_id")): {
            "service_categories_csv": _norm_text(row.get("service_categories_csv")),
            "service_owner_classes_csv": _norm_text(row.get("service_owner_classes_csv")),
            "service_owner_names_csv": _norm_text(row.get("service_owner_names_csv")),
        }
        for row in rows
        if _norm_text(row.get("dynamic_run_id"))
    }


def _load_direct_recompute_rows(packages: Sequence[str]) -> list[dict[str, Any]]:
    from scytaledroid.Database.db_core import db_queries as core_q

    where_sql, params = _sql_list_filters(packages)
    query = f"""
        SELECT
          ctx.dynamic_run_id,
          ctx.package_name,
          ctx.app_label,
          ctx.effective_run_profile,
          ctx.valid_dataset_run,
          ctx.countable,
          ctx.distinct_observed_domains,
          ctx.tls_sni_unique_count,
          ctx.tls_client_hello_count,
          ctx.tls_server_hello_count,
          ctx.unique_ja4_count,
          ds.evidence_path
        FROM v_dynamic_run_context_v1 ctx
        JOIN dynamic_sessions ds
          ON ds.dynamic_run_id = ctx.dynamic_run_id
        {where_sql if where_sql else 'WHERE 1=1'}
          AND ds.pcap_valid = 1
        ORDER BY ctx.package_name, ctx.ended_at_utc DESC
    """
    return core_q.run_sql(
        query,
        params,
        fetch="all",
        dictionary=True,
        query_name="dynamic.tls_fingerprint_audit.recompute_candidates",
    ) or []


def _summarize_population(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    pcap_valid_rows = [row for row in rows if _safe_int(row.get("pcap_valid")) == 1]
    tech_valid_rows = [row for row in rows if _norm_text(row.get("technical_validity_state")) == "TECH_VALID"]
    fingerprint_rows = [row for row in rows if (_safe_int(row.get("unique_ja4_count")) or 0) > 0]
    domain_rows = [
        row
        for row in rows
        if (_safe_int(row.get("distinct_observed_domains")) or _safe_int(row.get("domains_count")) or 0) > 0
    ]
    return {
        "total_runs": total,
        "pcap_valid_runs": len(pcap_valid_rows),
        "tech_valid_runs": len(tech_valid_rows),
        "runs_with_domains": len(domain_rows),
        "runs_with_ja3": sum(1 for row in rows if (_safe_int(row.get("unique_ja3_count")) or 0) > 0),
        "runs_with_ja3s": sum(1 for row in rows if (_safe_int(row.get("unique_ja3s_count")) or 0) > 0),
        "runs_with_ja4": len(fingerprint_rows),
        "pcap_valid_fingerprint_rate": round(len(fingerprint_rows) / len(pcap_valid_rows), 4) if pcap_valid_rows else 0.0,
        "domain_to_fingerprint_rate": round(len(fingerprint_rows) / len(domain_rows), 4) if domain_rows else 0.0,
        "runs_with_domains_but_no_ja4": sum(
            1
            for row in rows
            if (_safe_int(row.get("distinct_observed_domains")) or _safe_int(row.get("domains_count")) or 0) > 0
            and (_safe_int(row.get("unique_ja4_count")) or 0) == 0
        ),
        "runs_with_ja4_but_no_domains": sum(
            1
            for row in rows
            if (_safe_int(row.get("unique_ja4_count")) or 0) > 0
            and (_safe_int(row.get("distinct_observed_domains")) or _safe_int(row.get("domains_count")) or 0) == 0
        ),
    }


def _load_governance_consistency(packages: Sequence[str]) -> dict[str, Any]:
    from scytaledroid.Database.db_core import db_queries as core_q

    where_sql, params = _sql_list_filters(packages)
    query = f"""
        SELECT
          COUNT(*) AS compared_rows,
          SUM(
            CASE
              WHEN (ctx.valid_dataset_run <=> ds.valid_dataset_run)
               AND (ctx.countable <=> ds.countable)
              THEN 0 ELSE 1
            END
          ) AS mismatched_rows,
          SUM(
            CASE
              WHEN NOT (ctx.valid_dataset_run <=> ds.valid_dataset_run)
              THEN 1 ELSE 0
            END
          ) AS valid_dataset_run_mismatches,
          SUM(
            CASE
              WHEN NOT (ctx.countable <=> ds.countable)
              THEN 1 ELSE 0
            END
          ) AS countable_mismatches
        FROM v_dynamic_run_context_v1 ctx
        JOIN dynamic_sessions ds
          ON ds.dynamic_run_id = ctx.dynamic_run_id
        {where_sql}
    """
    row = core_q.run_sql(
        query,
        params,
        fetch="one",
        dictionary=True,
        query_name="dynamic.tls_fingerprint_audit.governance_consistency",
    ) or {}
    return {
        "compared_rows": _safe_int(row.get("compared_rows")) or 0,
        "mismatched_rows": _safe_int(row.get("mismatched_rows")) or 0,
        "valid_dataset_run_mismatches": _safe_int(row.get("valid_dataset_run_mismatches")) or 0,
        "countable_mismatches": _safe_int(row.get("countable_mismatches")) or 0,
    }


def _fmt_extra(count: int, suffix: str = "") -> str:
    if count <= 0:
        return ""
    return f"+{count}{suffix}"


def _interpret_rollup(row: Mapping[str, Any]) -> str:
    baseline_div = _safe_float(row.get("baseline_median_unique_ja4_count")) or 0.0
    interactive_div = _safe_float(row.get("interactive_median_unique_ja4_count")) or 0.0
    dominant = _safe_float(row.get("median_top_ja4_share")) or 0.0
    category_text = _norm_text(row.get("service_families_observed") or row.get("service_categories_observed"))
    label = _norm_text(row.get("app_label"))
    if "messaging" in category_text and baseline_div <= 2 and dominant >= 0.75:
        return "Low-volume messaging baseline with a small, stable encrypted-service stack."
    if "advertising" in category_text or "analytics" in category_text or baseline_div >= 8:
        return "High fingerprint diversity consistent with adtech, analytics, and CDN-mediated traffic."
    if interactive_div > baseline_div + 1:
        return "Interactive runs broaden the encrypted-service mix beyond baseline behavior."
    if dominant >= 0.75:
        return "Handshake traffic is dominated by one primary client stack despite multiple domains."
    if label in {"X (Twitter)", "X"} and (_safe_int(row.get("supplemental_runs")) or 0) > 0:
        return "Current-build baseline includes supplemental quiet runs that still yield usable encrypted fingerprints."
    return "Moderate fingerprint diversity; domains and handshake signals are complementary."


def _service_family_text(row: Mapping[str, Any]) -> str:
    parts = [
        _norm_text(row.get("service_categories_csv")),
        _norm_text(row.get("service_keys_csv")),
    ]
    merged: list[str] = []
    for part in parts:
        for token in [value.strip() for value in part.split(",") if value.strip()]:
            if token not in merged:
                merged.append(token)
    return ", ".join(merged)


def generate_report(
    *,
    packages: Sequence[str] | None = None,
    output_dir: Path | None = None,
    recompute_top_values: bool = False,
) -> dict[str, Any]:
    from scytaledroid.DynamicAnalysis.pcap.fingerprints import summarize_tls_fingerprints

    package_filter = list(packages or [])
    run_rows = [dict(row) for row in _load_run_rows(package_filter)]
    service_families = _load_service_family_rows(package_filter)
    output_root = output_dir or _default_output_dir()
    output_root.mkdir(parents=True, exist_ok=True)

    run_csv_rows: list[dict[str, Any]] = []
    per_app_runs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    recompute_mismatches: list[dict[str, Any]] = []
    missing_reason_counts = Counter()

    for row in run_rows:
        run_id = _norm_text(row.get("dynamic_run_id"))
        package_name = _norm_text(row.get("package_name")).lower()
        app_label = _norm_text(row.get("app_label")) or FOCUS_PACKAGES.get(package_name) or package_name
        evidence_root = Path(_norm_text(row.get("evidence_path")))
        pcap_report = _read_json(evidence_root / "analysis" / "pcap_report.json")
        tls_payload = _coerce_tls_items((pcap_report or {}).get("tls_fingerprints"))
        recompute_payload: dict[str, Any] | None = None

        need_recompute = recompute_top_values and (
            not tls_payload.get("top_ja4")
            or not tls_payload.get("top_ja3")
            or not tls_payload.get("top_alpn")
        )
        if need_recompute:
            pcap_path = _find_pcap_path(evidence_root)
            if pcap_path and pcap_path.exists():
                try:
                    recompute_payload = summarize_tls_fingerprints(pcap_path, top_n=5)
                except Exception as exc:  # noqa: BLE001
                    missing_reason_counts[f"recompute_failed:{type(exc).__name__}"] += 1
                else:
                    if not tls_payload.get("top_ja4"):
                        tls_payload = _coerce_tls_items(recompute_payload)
            else:
                missing_reason_counts["pcap_missing_for_recompute"] += 1

        service_row = service_families.get(run_id, {})
        interaction_mode = _interaction_mode(
            _norm_text(row.get("effective_run_profile")),
            _norm_text(row.get("effective_interaction_level")),
        )
        mode_bucket = _mode_bucket(
            _norm_text(row.get("effective_run_profile")),
            _norm_text(row.get("effective_interaction_level")),
        )
        top_ja3 = _first_top_value(tls_payload.get("top_ja3"))
        top_ja4 = _first_top_value(tls_payload.get("top_ja4"))
        top_alpn = _first_top_value(tls_payload.get("top_alpn"))
        top_sni = _first_top_value(tls_payload.get("top_sni_from_client_hello")) or _first_top_value((pcap_report or {}).get("top_sni"))
        top_ja3_share = _safe_float(row.get("top1_ja3_share"))
        top_ja4_share = _safe_float(row.get("top1_ja4_share"))

        if (_safe_int(row.get("distinct_observed_domains")) or 0) > 0 and (_safe_int(row.get("unique_ja4_count")) or 0) == 0:
            if recompute_payload and (_safe_int(recompute_payload.get("unique_ja4_count")) or 0) > 0:
                recompute_mismatches.append(
                    {
                        "dynamic_run_id": run_id,
                        "package_name": package_name,
                        "app_label": app_label,
                        "run_profile": _norm_text(row.get("effective_run_profile")),
                        "domains_count": _safe_int(row.get("distinct_observed_domains")) or 0,
                        "db_unique_ja4_count": _safe_int(row.get("unique_ja4_count")) or 0,
                        "recomputed_unique_ja4_count": _safe_int(recompute_payload.get("unique_ja4_count")) or 0,
                        "recomputed_top_ja4": _first_top_value(recompute_payload.get("top_ja4")),
                        "pcap_bytes": _safe_int(row.get("pcap_bytes")) or 0,
                        "evidence_path": str(evidence_root),
                        "diagnosis": "db_or_reindex_gap",
                    }
                )
                missing_reason_counts["db_or_reindex_gap"] += 1
            else:
                quic_packets = _safe_int(row.get("quic_candidate_packets")) or 0
                tls_packets = _safe_int(row.get("tls_handshake_packets")) or 0
                if quic_packets > 0 and tls_packets <= 0:
                    missing_reason_counts["quic_dominant_no_tls_handshake"] += 1
                elif tls_packets <= 0:
                    missing_reason_counts["no_tls_handshake_visible"] += 1
                else:
                    missing_reason_counts["domains_present_tls_missing_unexplained"] += 1

        run_record = {
            "app_label": app_label,
            "package_name": package_name,
            "version_code": _safe_int(row.get("version_code")),
            "version_name": _norm_text(row.get("version_name")),
            "run_id": run_id,
            "run_profile": _norm_text(row.get("effective_run_profile")),
            "interaction_mode": interaction_mode,
            "mode_bucket": mode_bucket,
            "valid_dataset_run": _safe_int(row.get("valid_dataset_run")),
            "countable": _safe_int(row.get("countable")),
            "technical_validity_state": _norm_text(row.get("technical_validity_state")),
            "quota_state": _norm_text(row.get("quota_state")),
            "pcap_valid": _safe_int(row.get("pcap_valid")),
            "pcap_bytes": _safe_int(row.get("pcap_bytes")),
            "domains_count": _safe_int(row.get("distinct_observed_domains")),
            "sni_count": _safe_int(row.get("tls_sni_unique_count")),
            "tls_client_hello_count": _safe_int(row.get("tls_client_hello_count")),
            "tls_server_hello_count": _safe_int(row.get("tls_server_hello_count")),
            "unique_ja3_count": _safe_int(row.get("unique_ja3_count")),
            "unique_ja3s_count": _safe_int(row.get("unique_ja3s_count")),
            "unique_ja4_count": _safe_int(row.get("unique_ja4_count")),
            "top_ja3": top_ja3,
            "top_ja3_share": top_ja3_share,
            "top_ja4": top_ja4,
            "top_ja4_share": top_ja4_share,
            "top_alpn": top_alpn,
            "top_sni": top_sni,
            "service_families_observed": _service_family_text({**row, **service_row}),
            "service_categories_csv": _norm_text(service_row.get("service_categories_csv")),
            "service_keys_csv": _norm_text(row.get("service_keys_csv")),
            "owner_classes_csv": _norm_text(row.get("owner_classes_csv")),
            "role_classes_csv": _norm_text(row.get("role_classes_csv")),
            "quic_candidate_packets": _safe_int(row.get("quic_candidate_packets")),
            "tls_handshake_packets": _safe_int(row.get("tls_handshake_packets")),
            "invalid_reason_code": _norm_text(row.get("invalid_reason_code")),
        }
        run_csv_rows.append(run_record)
        per_app_runs[package_name].append(run_record)

    app_rollup_rows: list[dict[str, Any]] = []
    paper_table_rows: list[dict[str, Any]] = []
    baseline_vs_interactive_rows: list[dict[str, Any]] = []

    for package_name in sorted(per_app_runs):
        app_runs = per_app_runs[package_name]
        app_label = _norm_text(app_runs[0].get("app_label")) if app_runs else package_name
        countable_runs = [row for row in app_runs if _safe_int(row.get("valid_dataset_run")) == 1 and _safe_int(row.get("countable")) == 1]
        analysis_runs = analysis_included_rows(app_runs)
        supplemental_runs = [row for row in app_runs if _norm_text(row.get("quota_state")) == "SUPPLEMENTAL_VALID"]
        baseline_runs = [row for row in app_runs if row.get("mode_bucket") == "baseline" and _safe_int(row.get("valid_dataset_run")) == 1]
        interactive_runs = [row for row in app_runs if row.get("mode_bucket") == "interactive" and _safe_int(row.get("valid_dataset_run")) == 1]
        baseline_ja4 = [int(row["unique_ja4_count"]) for row in baseline_runs if row.get("unique_ja4_count") is not None]
        interactive_ja4 = [int(row["unique_ja4_count"]) for row in interactive_runs if row.get("unique_ja4_count") is not None]
        all_ja4 = [int(row["unique_ja4_count"]) for row in app_runs if row.get("unique_ja4_count") is not None]
        all_ja3 = [int(row["unique_ja3_count"]) for row in app_runs if row.get("unique_ja3_count") is not None]
        all_ja3s = [int(row["unique_ja3s_count"]) for row in app_runs if row.get("unique_ja3s_count") is not None]
        top_ja4_shares = [float(row["top_ja4_share"]) for row in app_runs if row.get("top_ja4_share") is not None]
        service_family_counter = Counter()
        for row in app_runs:
            for token in [value.strip() for value in _norm_text(row.get("service_families_observed")).split(",") if value.strip()]:
                service_family_counter[token] += 1
        service_families_text = ", ".join(key for key, _count in service_family_counter.most_common(6))
        rollup = {
            "app_label": app_label,
            "package_name": package_name,
            "countable_runs": len(countable_runs),
            "analysis_included_runs": len(analysis_runs),
            "supplemental_runs": len(supplemental_runs),
            "median_unique_ja3_count": round(median(all_ja3), 2) if all_ja3 else None,
            "median_unique_ja4_count": round(median(all_ja4), 2) if all_ja4 else None,
            "median_unique_ja3s_count": round(median(all_ja3s), 2) if all_ja3s else None,
            "max_unique_ja4_count": max(all_ja4) if all_ja4 else None,
            "median_top_ja4_share": round(median(top_ja4_shares), 4) if top_ja4_shares else None,
            "baseline_fingerprint_diversity": round(median(baseline_ja4), 2) if baseline_ja4 else None,
            "interactive_fingerprint_diversity": round(median(interactive_ja4), 2) if interactive_ja4 else None,
            "baseline_median_unique_ja4_count": round(median(baseline_ja4), 2) if baseline_ja4 else None,
            "interactive_median_unique_ja4_count": round(median(interactive_ja4), 2) if interactive_ja4 else None,
            "service_families_observed": service_families_text,
            "interpretation": "",
        }
        rollup["interpretation"] = _interpret_rollup(rollup)
        app_rollup_rows.append(rollup)

        analysis_domains = [int(row["domains_count"]) for row in analysis_runs if row.get("domains_count") is not None]
        paper_table_rows.append(
            {
                "app": app_label,
                "package_name": package_name,
                "countable_runs": len(countable_runs),
                "analysis_included_runs": len(analysis_runs),
                "runtime_domains_median": round(median(analysis_domains), 2) if analysis_domains else None,
                "unique_ja4_median": rollup["median_unique_ja4_count"],
                "unique_ja3_median": rollup["median_unique_ja3_count"],
                "top_ja4_share_median": rollup["median_top_ja4_share"],
                "main_service_families": service_families_text,
                "interpretation": rollup["interpretation"],
            }
        )

        baseline_vs_interactive_rows.append(
            {
                "app_label": app_label,
                "package_name": package_name,
                "baseline_runs": len(baseline_runs),
                "interactive_runs": len(interactive_runs),
                "baseline_median_unique_ja4_count": rollup["baseline_median_unique_ja4_count"],
                "interactive_median_unique_ja4_count": rollup["interactive_median_unique_ja4_count"],
                "baseline_median_top_ja4_share": round(
                    median([float(row["top_ja4_share"]) for row in baseline_runs if row.get("top_ja4_share") is not None]),
                    4,
                ) if [row for row in baseline_runs if row.get("top_ja4_share") is not None] else None,
                "interactive_median_top_ja4_share": round(
                    median([float(row["top_ja4_share"]) for row in interactive_runs if row.get("top_ja4_share") is not None]),
                    4,
                ) if [row for row in interactive_runs if row.get("top_ja4_share") is not None] else None,
            }
        )

    _write_csv(output_root / "fingerprint_run_rows.csv", run_csv_rows, fieldnames=FINGERPRINT_RUN_FIELDS)
    _write_csv(output_root / "fingerprint_app_rollup.csv", app_rollup_rows, fieldnames=FINGERPRINT_APP_ROLLUP_FIELDS)
    _write_csv(output_root / "fingerprint_paper_table.csv", paper_table_rows, fieldnames=FINGERPRINT_PAPER_TABLE_FIELDS)
    _write_csv(
        output_root / "fingerprint_baseline_vs_interactive.csv",
        baseline_vs_interactive_rows,
        fieldnames=FINGERPRINT_BASELINE_INTERACTIVE_FIELDS,
    )
    _write_csv(
        output_root / "fingerprint_recompute_mismatches.csv",
        recompute_mismatches,
        fieldnames=FINGERPRINT_RECOMPUTE_MISMATCH_FIELDS,
    )

    focus_rollups = [row for row in app_rollup_rows if _norm_text(row.get("package_name")) in FOCUS_PACKAGES]
    focus_runs = [row for row in run_csv_rows if _norm_text(row.get("package_name")) in FOCUS_PACKAGES]
    population = _summarize_population(run_rows)

    summary = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "packages_filtered": sorted({_norm_text(value).lower() for value in package_filter if _norm_text(value)}) or None,
        "population_summary": population,
        "focus_population_summary": _summarize_population(focus_runs),
        "governance_consistency": _load_governance_consistency(package_filter),
        "app_rollup_focus": focus_rollups,
        "recompute_mismatch_count": len(recompute_mismatches),
        "missing_fingerprint_reason_counts": dict(sorted(missing_reason_counts.items())),
        "validation_checks": {
            "no_db_writes": True,
            "recompute_top_values_used": recompute_top_values,
            "runs_with_domains_but_no_ja4": population["runs_with_domains_but_no_ja4"],
            "runs_with_ja4_but_no_domains": population["runs_with_ja4_but_no_domains"],
        },
        "output_files": {
            "fingerprint_run_rows_csv": str((output_root / "fingerprint_run_rows.csv").resolve()),
            "fingerprint_app_rollup_csv": str((output_root / "fingerprint_app_rollup.csv").resolve()),
            "fingerprint_paper_table_csv": str((output_root / "fingerprint_paper_table.csv").resolve()),
            "fingerprint_baseline_vs_interactive_csv": str((output_root / "fingerprint_baseline_vs_interactive.csv").resolve()),
            "fingerprint_recompute_mismatches_csv": str((output_root / "fingerprint_recompute_mismatches.csv").resolve()),
            "summary_json": str((output_root / "summary.json").resolve()),
        },
    }
    (output_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    summary = generate_report(
        packages=args.package,
        output_dir=output_dir,
        recompute_top_values=bool(args.recompute_top_values),
    )
    if args.stdout_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(json.dumps({"summary_json": summary["output_files"]["summary_json"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
