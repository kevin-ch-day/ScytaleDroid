#!/usr/bin/env python3
"""Read-only audit for dynamic baseline sufficiency and low-signal policy impact."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

BASELINE_FIELDS: tuple[str, ...] = (
    "dynamic_run_id",
    "package_name",
    "app_label",
    "version_code",
    "static_run_id",
    "evidence_scope",
    "profile",
    "interaction_mode",
    "quota_state",
    "valid_dataset_run",
    "countable",
    "current_low_signal",
    "current_low_signal_reasons",
    "proposed_low_signal",
    "proposed_low_signal_reasons",
    "policy_change",
    "pcap_valid",
    "pcap_bytes",
    "duration_s",
    "packet_count",
    "domain_count",
    "network_indicator_rows",
    "domain_observation_rows",
    "local_pack_present",
    "pcap_features_present",
    "classification",
    "evidence_path",
)

ROLLUP_FIELDS: tuple[str, ...] = (
    "package_name",
    "app_label",
    "version_code",
    "profile",
    "evidence_scope",
    "rows",
    "valid_rows",
    "countable_rows",
    "current_low_signal_rows",
    "proposed_low_signal_rows",
    "policy_change_rows",
    "pcap_bytes_min",
    "pcap_bytes_median",
    "pcap_bytes_max",
    "packet_count_median",
    "domain_count_median",
)

IMPACT_FIELDS: tuple[str, ...] = (
    "dynamic_run_id",
    "package_name",
    "app_label",
    "version_code",
    "static_run_id",
    "evidence_scope",
    "profile",
    "quota_state",
    "countable",
    "current_low_signal",
    "current_low_signal_reasons",
    "proposed_low_signal",
    "proposed_low_signal_reasons",
    "impact",
    "pcap_bytes",
    "packet_count",
    "duration_s",
    "domain_count",
)

QUOTA_DRY_RUN_FIELDS: tuple[str, ...] = (
    "dynamic_run_id",
    "package_name",
    "app_label",
    "version_code",
    "profile",
    "quota_state",
    "current_countable",
    "dry_run_countable",
    "current_low_signal",
    "dry_run_low_signal",
    "countability_change",
    "low_signal_change",
    "dry_run_extra_run",
    "pcap_bytes",
    "packet_count",
    "duration_s",
    "domain_count",
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", action="append", default=[], help="Restrict to one or more package names.")
    parser.add_argument("--output-dir", default=None, help="Optional explicit output directory.")
    parser.add_argument("--static-session-stamp", default="20260630-rdb-full", help="Static session stamp that defines current RDB scope.")
    parser.add_argument("--scope-label", default="Research Dataset Beta", help="Static session scope label that defines current RDB scope.")
    parser.add_argument("--stdout-json", action="store_true", help="Print summary JSON to stdout after writing report files.")
    return parser


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_baseline_sufficiency" / stamp


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fields: Sequence[str] | None = None) -> None:
    row_list = list(rows)
    if fields is None:
        fieldnames: list[str] = []
        for row in row_list:
            for key in row:
                if key not in fieldnames:
                    fieldnames.append(str(key))
    else:
        fieldnames = list(fields)
    if not row_list:
        path.write_text(",".join(fieldnames) + "\n" if fieldnames else "", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in row_list:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _is_true(value: Any) -> bool:
    return value in (True, 1, "1", "true", "TRUE", "yes", "YES")


def _safe_int(value: Any, default: int | None = 0) -> int | None:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float | None = 0.0) -> float | None:
    try:
        if value in (None, ""):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _median(values: Sequence[int | float | None]) -> int | float | None:
    clean = [float(value) for value in values if value is not None]
    if not clean:
        return None
    value = median(clean)
    return int(value) if float(value).is_integer() else value


def _current_rdb_identity_sets(session_stamp: str, scope_label: str) -> tuple[set[str], set[tuple[str, str]]]:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception:
        return set(), set()

    queries = (
        """
        SELECT sar.id AS static_run_id,
               LOWER(TRIM(a.package_name)) AS package_name,
               CAST(av.version_code AS CHAR) AS version_code
        FROM static_analysis_runs sar
        LEFT JOIN static_analysis_sessions sas
          ON sas.static_session_id = sar.static_session_id
        LEFT JOIN app_versions av
          ON av.id = sar.app_version_id
        LEFT JOIN apps a
          ON a.id = av.app_id
        WHERE sas.session_stamp = %s
          AND sas.scope_label = %s
        """,
        """
        SELECT sar.id AS static_run_id,
               LOWER(TRIM(a.package_name)) AS package_name,
               CAST(av.version_code AS CHAR) AS version_code
        FROM static_analysis_runs sar
        LEFT JOIN app_versions av
          ON av.id = sar.app_version_id
        LEFT JOIN apps a
          ON a.id = av.app_id
        WHERE sar.session_stamp = %s
          AND sar.scope_label = %s
        """,
    )
    rows: list[Mapping[str, Any]] = []
    for query in queries:
        try:
            rows = core_q.run_sql(
                query,
                (session_stamp, scope_label),
                fetch="all",
                dictionary=True,
                query_name="dynamic.baseline_sufficiency.static_scope",
            ) or []
        except Exception:
            rows = []
        if rows:
            break

    static_ids = {_norm_text(row.get("static_run_id")) for row in rows if _norm_text(row.get("static_run_id"))}
    package_versions = {
        (_norm_text(row.get("package_name")).lower(), _norm_text(row.get("version_code")))
        for row in rows
        if _norm_text(row.get("package_name")) and _norm_text(row.get("version_code"))
    }
    return static_ids, package_versions


def _evidence_scope(row: Mapping[str, Any], static_ids: set[str], package_versions: set[tuple[str, str]]) -> str:
    static_run_id = _norm_text(row.get("static_run_id"))
    package_name = _norm_text(row.get("package_name")).lower()
    version_code = _norm_text(row.get("version_code"))
    if static_run_id and static_run_id in static_ids:
        return "current_rdb"
    if package_name and version_code and (package_name, version_code) in package_versions:
        return "current_rdb"
    if _norm_text(row.get("evidence_era")) == "MODERN_FINALIZED":
        return "modern_non_rdb"
    return "legacy_or_local"


def _proposed_low_signal(row: Mapping[str, Any]) -> tuple[bool | None, list[str]]:
    evidence_path = _norm_text(row.get("evidence_path"))
    if not evidence_path:
        return (True if _is_true(row.get("low_signal")) else False if row.get("low_signal") is not None else None, _json_list(row.get("low_signal_reasons_json")))
    run_dir = Path(evidence_path)
    if not run_dir.exists():
        return (True if _is_true(row.get("low_signal")) else False if row.get("low_signal") is not None else None, _json_list(row.get("low_signal_reasons_json")))
    from scytaledroid.DynamicAnalysis.pcap.low_signal import compute_low_signal_for_run

    decision = compute_low_signal_for_run(
        run_dir,
        package_name=_norm_text(row.get("package_name")),
        run_profile=_norm_text(row.get("profile")),
    )
    if not isinstance(decision, Mapping):
        return (True if _is_true(row.get("low_signal")) else False if row.get("low_signal") is not None else None, _json_list(row.get("low_signal_reasons_json")))
    reasons = decision.get("low_signal_reasons") if isinstance(decision.get("low_signal_reasons"), list) else []
    return (bool(decision.get("low_signal")), [str(reason) for reason in reasons])


def _json_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    text = _norm_text(value)
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return [text]
    if isinstance(payload, list):
        return [str(item) for item in payload]
    return [text]


def _is_baseline(row: Mapping[str, Any]) -> bool:
    return _norm_text(row.get("profile")).lower().startswith("baseline")


def _build_baseline_rows(rows: Sequence[Mapping[str, Any]], static_ids: set[str], package_versions: set[tuple[str, str]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        if not _is_baseline(row):
            continue
        current_reasons = _json_list(row.get("low_signal_reasons_json"))
        proposed_low, proposed_reasons = _proposed_low_signal(row)
        current_low = True if _is_true(row.get("low_signal")) else False if row.get("low_signal") is not None else None
        policy_change = current_low is not None and proposed_low is not None and current_low != proposed_low
        out.append(
            {
                "dynamic_run_id": _norm_text(row.get("dynamic_run_id")),
                "package_name": _norm_text(row.get("package_name")),
                "app_label": _norm_text(row.get("app_label")),
                "version_code": _norm_text(row.get("version_code")),
                "static_run_id": _norm_text(row.get("static_run_id")),
                "evidence_scope": _evidence_scope(row, static_ids, package_versions),
                "profile": _norm_text(row.get("profile")),
                "interaction_mode": _norm_text(row.get("interaction_mode")),
                "quota_state": _norm_text(row.get("quota_state")),
                "valid_dataset_run": row.get("valid_dataset_run"),
                "countable": row.get("countable"),
                "current_low_signal": current_low,
                "current_low_signal_reasons": json.dumps(current_reasons, sort_keys=True),
                "proposed_low_signal": proposed_low,
                "proposed_low_signal_reasons": json.dumps(proposed_reasons, sort_keys=True),
                "policy_change": bool(policy_change),
                "pcap_valid": row.get("pcap_valid"),
                "pcap_bytes": _safe_int(row.get("pcap_bytes"), None),
                "duration_s": _safe_float(row.get("duration_s"), None),
                "packet_count": _safe_int(row.get("packet_count"), None),
                "domain_count": _safe_int(row.get("domain_count"), None),
                "network_indicator_rows": _safe_int(row.get("network_indicator_rows"), None),
                "domain_observation_rows": _safe_int(row.get("domain_observation_rows"), None),
                "local_pack_present": _norm_text(row.get("local_pack_present")),
                "pcap_features_present": _norm_text(row.get("pcap_features_present")),
                "classification": _norm_text(row.get("classification")),
                "evidence_path": _norm_text(row.get("evidence_path")),
            }
        )
    return out


def _prefer_db_governance_fields(
    merged_rows: Sequence[Mapping[str, Any]],
    db_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    db_by_id = {
        _norm_text(row.get("dynamic_run_id")): row
        for row in db_rows
        if _norm_text(row.get("dynamic_run_id"))
    }
    governance_fields = (
        "valid_dataset_run",
        "countable",
        "quota_state",
        "technical_validity_state",
        "cohort_eligibility_state",
        "low_signal",
        "low_signal_reasons_json",
        "invalid_reason_code",
        "pcap_valid",
    )
    out: list[dict[str, Any]] = []
    for row in merged_rows:
        run_id = _norm_text(row.get("dynamic_run_id"))
        merged = dict(row)
        db_row = db_by_id.get(run_id)
        if db_row:
            for field in governance_fields:
                if field in db_row and db_row.get(field) not in (None, ""):
                    merged[field] = db_row.get(field)
        out.append(merged)
    return out


def _build_rollups(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        key = (
            _norm_text(row.get("package_name")),
            _norm_text(row.get("app_label")),
            _norm_text(row.get("version_code")),
            _norm_text(row.get("profile")),
            _norm_text(row.get("evidence_scope")),
        )
        grouped[key].append(row)
    out: list[dict[str, Any]] = []
    for (package_name, app_label, version_code, profile, evidence_scope), items in sorted(grouped.items()):
        pcap_values = [_safe_int(row.get("pcap_bytes"), None) for row in items]
        pcap_clean = [value for value in pcap_values if value is not None]
        out.append(
            {
                "package_name": package_name,
                "app_label": app_label,
                "version_code": version_code,
                "profile": profile,
                "evidence_scope": evidence_scope,
                "rows": len(items),
                "valid_rows": sum(1 for row in items if _is_true(row.get("valid_dataset_run"))),
                "countable_rows": sum(1 for row in items if _is_true(row.get("countable"))),
                "current_low_signal_rows": sum(1 for row in items if row.get("current_low_signal") is True),
                "proposed_low_signal_rows": sum(1 for row in items if row.get("proposed_low_signal") is True),
                "policy_change_rows": sum(1 for row in items if row.get("policy_change") is True),
                "pcap_bytes_min": min(pcap_clean) if pcap_clean else None,
                "pcap_bytes_median": _median(pcap_clean),
                "pcap_bytes_max": max(pcap_clean) if pcap_clean else None,
                "packet_count_median": _median([_safe_int(row.get("packet_count"), None) for row in items]),
                "domain_count_median": _median([_safe_int(row.get("domain_count"), None) for row in items]),
            }
        )
    return out


def _build_impact_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    impact: list[dict[str, Any]] = []
    for row in rows:
        if row.get("policy_change") is not True:
            continue
        impact.append(
            {
                "dynamic_run_id": row.get("dynamic_run_id"),
                "package_name": row.get("package_name"),
                "app_label": row.get("app_label"),
                "version_code": row.get("version_code"),
                "static_run_id": row.get("static_run_id"),
                "evidence_scope": row.get("evidence_scope"),
                "profile": row.get("profile"),
                "quota_state": row.get("quota_state"),
                "countable": row.get("countable"),
                "current_low_signal": row.get("current_low_signal"),
                "current_low_signal_reasons": row.get("current_low_signal_reasons"),
                "proposed_low_signal": row.get("proposed_low_signal"),
                "proposed_low_signal_reasons": row.get("proposed_low_signal_reasons"),
                "impact": "low_signal_reclassification_candidate",
                "pcap_bytes": row.get("pcap_bytes"),
                "packet_count": row.get("packet_count"),
                "duration_s": row.get("duration_s"),
                "domain_count": row.get("domain_count"),
            }
        )
    return impact


def _build_quota_dry_run_rows(
    rows: Sequence[Mapping[str, Any]],
    static_ids: set[str],
    package_versions: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig, _apply_quota_marking

    current_rows: list[dict[str, Any]] = []
    for row in rows:
        if _evidence_scope(row, static_ids, package_versions) != "current_rdb":
            continue
        current_low = True if _is_true(row.get("low_signal")) else False if row.get("low_signal") is not None else None
        proposed_low = current_low
        proposed_reasons: list[str] = _json_list(row.get("low_signal_reasons_json"))
        if _is_baseline(row):
            proposed_low, proposed_reasons = _proposed_low_signal(row)
        policy_repaired_noncountable = (
            _is_baseline(row)
            and _is_true(row.get("valid_dataset_run"))
            and not _is_true(row.get("countable"))
            and current_low is True
            and proposed_low is False
        )
        current_rows.append(
            {
                "run_id": _norm_text(row.get("dynamic_run_id")),
                "package_name": _norm_text(row.get("package_name")),
                "app_label": _norm_text(row.get("app_label")),
                "version_code": _norm_text(row.get("version_code")),
                "run_profile": _norm_text(row.get("profile")),
                "valid_dataset_run": _is_true(row.get("valid_dataset_run")),
                "paper_eligible": _norm_text(row.get("quota_state")) != "SUPPLEMENTAL_NONPAPER",
                "countable": None if policy_repaired_noncountable else _is_true(row.get("countable")),
                "low_signal": proposed_low,
                "low_signal_reasons": proposed_reasons,
                "started_at": _norm_text(row.get("started_at_utc") or row.get("ended_at_utc")),
                "ended_at": _norm_text(row.get("ended_at_utc")),
                "_current_countable": _is_true(row.get("countable")),
                "_current_low_signal": current_low,
                "_quota_state": _norm_text(row.get("quota_state")),
                "_pcap_bytes": _safe_int(row.get("pcap_bytes"), None),
                "_packet_count": _safe_int(row.get("packet_count"), None),
                "_duration_s": _safe_float(row.get("duration_s"), None),
                "_domain_count": _safe_int(row.get("domain_count"), None),
            }
        )

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in current_rows:
        grouped[(_norm_text(row.get("package_name")), _norm_text(row.get("version_code")))].append(row)

    out: list[dict[str, Any]] = []
    for (_package_name, _version_code), group_rows in sorted(grouped.items()):
        app_entry = {"runs": [dict(row) for row in group_rows]}
        _apply_quota_marking(app_entry, DatasetTrackerConfig())
        for row in app_entry["runs"]:
            current_countable = bool(row.get("_current_countable"))
            dry_countable = bool(row.get("countable"))
            current_low = row.get("_current_low_signal")
            dry_low = row.get("low_signal")
            out.append(
                {
                    "dynamic_run_id": row.get("run_id"),
                    "package_name": row.get("package_name"),
                    "app_label": row.get("app_label"),
                    "version_code": row.get("version_code"),
                    "profile": row.get("run_profile"),
                    "quota_state": row.get("_quota_state"),
                    "current_countable": current_countable,
                    "dry_run_countable": dry_countable,
                    "current_low_signal": current_low,
                    "dry_run_low_signal": dry_low,
                    "countability_change": current_countable != dry_countable,
                    "low_signal_change": current_low is not None and dry_low is not None and current_low != dry_low,
                    "dry_run_extra_run": int(row.get("extra_run") or 0),
                    "pcap_bytes": row.get("_pcap_bytes"),
                    "packet_count": row.get("_packet_count"),
                    "duration_s": row.get("_duration_s"),
                    "domain_count": row.get("_domain_count"),
                }
            )
    return sorted(out, key=lambda item: (_norm_text(item.get("package_name")), _norm_text(item.get("version_code")), _norm_text(item.get("dynamic_run_id"))))


def _quota_cap_violations(rows: Sequence[Mapping[str, Any]], *, countable_field: str = "countable") -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for row in rows:
        if row.get("evidence_scope") != "current_rdb" or not _is_true(row.get(countable_field)):
            continue
        profile = _norm_text(row.get("profile")).lower()
        bucket = "baseline" if profile.startswith("baseline") else "interactive" if profile.startswith("interaction") else "unknown"
        grouped[(_norm_text(row.get("package_name")), _norm_text(row.get("version_code")))][bucket] += 1
    violations: list[dict[str, Any]] = []
    for (package_name, version_code), counts in sorted(grouped.items()):
        if counts["baseline"] > 3 or counts["interactive"] > 4:
            violations.append(
                {
                    "package_name": package_name,
                    "version_code": version_code,
                    "baseline_countable": counts["baseline"],
                    "interactive_countable": counts["interactive"],
                }
            )
    return violations


def _quota_cap_violations_from_dry_run(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    scoped = [dict(row, evidence_scope="current_rdb", countable=row.get("dry_run_countable")) for row in rows]
    return _quota_cap_violations(scoped)


def _build_markdown(summary: Mapping[str, Any], impact_rows: Sequence[Mapping[str, Any]], violations: Sequence[Mapping[str, Any]]) -> str:
    lines = [
        "# Dynamic Baseline Sufficiency Audit",
        "",
        f"- Generated: {summary.get('generated_at_utc')}",
        f"- Baseline rows: {summary.get('baseline_rows_total')}",
        f"- Current RDB baseline rows: {summary.get('current_rdb_baseline_rows')}",
        f"- Policy change candidates: {summary.get('policy_change_rows')}",
        f"- Current quota cap violations: {len(violations)}",
        f"- Dry-run countable rows after policy: {summary.get('dry_run_countable_rows')}",
        f"- Dry-run countability changes: {summary.get('dry_run_countability_change_rows')}",
        f"- Dry-run quota cap violations: {summary.get('dry_run_quota_cap_violation_rows')}",
        "",
        "## Policy Impact",
        "",
    ]
    if impact_rows:
        lines.append("| App | Run | Scope | Current | Proposed | Evidence |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for row in impact_rows[:20]:
            evidence = f"{row.get('pcap_bytes')} bytes, {row.get('packet_count')} packets, {row.get('domain_count')} domains"
            lines.append(
                f"| {row.get('app_label') or row.get('package_name')} | {row.get('dynamic_run_id')} | "
                f"{row.get('evidence_scope')} | {row.get('current_low_signal')} | "
                f"{row.get('proposed_low_signal')} | {evidence} |"
            )
    else:
        lines.append("No baseline low-signal policy changes were detected.")
    if violations:
        lines.extend(["", "## Quota Cap Violations", ""])
        for row in violations:
            lines.append(
                f"- {row.get('package_name')} {row.get('version_code')}: "
                f"baseline={row.get('baseline_countable')} interactive={row.get('interactive_countable')}"
            )
    return "\n".join(lines) + "\n"


def generate_report(
    *,
    packages: Sequence[str] | None = None,
    output_dir: Path | None = None,
    static_session_stamp: str = "20260630-rdb-full",
    scope_label: str = "Research Dataset Beta",
) -> dict[str, Any]:
    from scripts.db import report_dynamic_legacy_corpus as legacy_report

    target_dir = output_dir or _default_output_dir()
    target_dir.mkdir(parents=True, exist_ok=True)

    package_filter = [value for value in (packages or []) if _norm_text(value)]
    db_rows = legacy_report._load_db_rows(package_filter)
    local_rows = legacy_report._scan_local_evidence_packs(package_filter)
    merged_raw_rows = _prefer_db_governance_fields(
        legacy_report._merge_records(db_rows, local_rows),
        db_rows,
    )
    merged_rows = [legacy_report._finalize_record(row) for row in merged_raw_rows]
    static_ids, package_versions = _current_rdb_identity_sets(static_session_stamp, scope_label)
    baseline_rows = _build_baseline_rows(merged_rows, static_ids, package_versions)
    rollups = _build_rollups(baseline_rows)
    impact_rows = _build_impact_rows(baseline_rows)
    quota_dry_run_rows = _build_quota_dry_run_rows(merged_rows, static_ids, package_versions)
    violations = _quota_cap_violations(baseline_rows)
    dry_run_violations = _quota_cap_violations_from_dry_run(quota_dry_run_rows)

    _write_csv(target_dir / "baseline_run_rows.csv", baseline_rows, BASELINE_FIELDS)
    _write_csv(target_dir / "baseline_app_profile_rollup.csv", rollups, ROLLUP_FIELDS)
    _write_csv(target_dir / "proposed_policy_impact.csv", impact_rows, IMPACT_FIELDS)
    _write_csv(target_dir / "quota_dry_run_after_policy.csv", quota_dry_run_rows, QUOTA_DRY_RUN_FIELDS)

    summary = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "output_dir": str(target_dir),
        "static_session_stamp": static_session_stamp,
        "scope_label": scope_label,
        "packages_filtered": sorted({_norm_text(value).lower() for value in package_filter}) or None,
        "static_scope_static_run_ids": len(static_ids),
        "baseline_rows_total": len(baseline_rows),
        "current_rdb_baseline_rows": sum(1 for row in baseline_rows if row.get("evidence_scope") == "current_rdb"),
        "current_rdb_quota_valid_baseline_rows": sum(
            1
            for row in baseline_rows
            if row.get("evidence_scope") == "current_rdb" and _is_true(row.get("countable"))
        ),
        "current_low_signal_rows": sum(1 for row in baseline_rows if row.get("current_low_signal") is True),
        "proposed_low_signal_rows": sum(1 for row in baseline_rows if row.get("proposed_low_signal") is True),
        "policy_change_rows": len(impact_rows),
        "policy_change_current_rdb_rows": sum(1 for row in impact_rows if row.get("evidence_scope") == "current_rdb"),
        "quota_cap_violation_rows": len(violations),
        "dry_run_countable_rows": sum(1 for row in quota_dry_run_rows if row.get("dry_run_countable") is True),
        "dry_run_countability_change_rows": sum(1 for row in quota_dry_run_rows if row.get("countability_change") is True),
        "dry_run_low_signal_change_rows": sum(1 for row in quota_dry_run_rows if row.get("low_signal_change") is True),
        "dry_run_quota_cap_violation_rows": len(dry_run_violations),
        "legacy_rows_touched": 0,
        "output_files": {
            "summary_json": str((target_dir / "summary.json").resolve()),
            "baseline_run_rows_csv": str((target_dir / "baseline_run_rows.csv").resolve()),
            "baseline_app_profile_rollup_csv": str((target_dir / "baseline_app_profile_rollup.csv").resolve()),
            "proposed_policy_impact_csv": str((target_dir / "proposed_policy_impact.csv").resolve()),
            "quota_dry_run_after_policy_csv": str((target_dir / "quota_dry_run_after_policy.csv").resolve()),
            "paper_findings_md": str((target_dir / "paper_findings.md").resolve()),
        },
    }
    (target_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (target_dir / "paper_findings.md").write_text(_build_markdown(summary, impact_rows, violations), encoding="utf-8")
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).expanduser() if args.output_dir else None
    summary = generate_report(
        packages=args.package,
        output_dir=output_dir,
        static_session_stamp=args.static_session_stamp,
        scope_label=args.scope_label,
    )
    if args.stdout_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"[OK] Dynamic baseline sufficiency audit written: {summary['output_dir']}")
        print(
            "[OK] "
            f"baseline_rows={summary['baseline_rows_total']} "
            f"policy_changes={summary['policy_change_rows']} "
            f"quota_cap_violations={summary['quota_cap_violation_rows']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
