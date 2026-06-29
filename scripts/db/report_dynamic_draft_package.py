#!/usr/bin/env python3
"""Read-only dynamic corpus ledger and paper-draft package export.

This exporter is intentionally additive. It does not mutate evidence packs,
dynamic DB rows, or derived context tables. It packages the current dynamic
corpus into a paper-draft friendly bundle with special focus on run coverage,
PCAP/artifact integrity, DB domain-index adoption, and X/Twitter status.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

X_TWITTER_ANCHOR = {
    "package_name": "com.twitter.android",
    "app_label": "X (Twitter)",
    "historical_anchor_source": "ICECCO_2026_Android_DynamicBehavior",
    "historical_mu_idle_rdi": 0.0710,
    "historical_mu_interactive_rdi": 0.9262,
    "historical_delta_rdi": 0.8552,
}

BASELINE_REQUIRED = 3
INTERACTIVE_REQUIRED = 4


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Write outputs to this directory instead of output/paper/dynamic_draft_<YYYYMMDD>/.",
    )
    return parser


def _dynamic_root() -> Path:
    from scytaledroid.Config import app_config

    return Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"


def _default_output_dir() -> Path:
    return _REPO_ROOT / "output" / "paper" / f"dynamic_draft_{datetime.now(tz=UTC).strftime('%Y%m%d')}"


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fields})


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _safe_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_boolish(value: Any) -> bool | None:
    if value is True or value == 1:
        return True
    if value is False or value == 0:
        return False
    text = _norm_text(value).lower()
    if text in {"1", "true", "yes"}:
        return True
    if text in {"0", "false", "no"}:
        return False
    return None


def _mode_from_profile(run_profile: str) -> str:
    profile = _norm_text(run_profile).lower()
    if "baseline" in profile:
        return "idle"
    if "manual" in profile or "script" in profile:
        return "interactive"
    return "unknown"


def _interaction_label(run_profile: str) -> str:
    profile = _norm_text(run_profile).lower()
    if "baseline" in profile:
        return "baseline"
    if "manual" in profile:
        return "manual"
    if "script" in profile:
        return "scripted"
    return "unknown"


def _scenario_id(manifest: dict[str, Any]) -> str:
    scenario = manifest.get("scenario") if isinstance(manifest.get("scenario"), dict) else {}
    return _norm_text(scenario.get("id"))


def _window_scores_expected_for_manifest(manifest: dict[str, Any]) -> bool:
    scenario_id = _scenario_id(manifest).lower()
    if scenario_id in {"paper3_profile_v3", "profile_v3_phase2_capture"}:
        return True
    return scenario_id.startswith("profile_v3")


def _evidence_governance_class(
    *,
    valid_dataset_run: bool | None,
    countable: bool | None,
    low_signal: bool,
    paper_eligible: bool | None,
    cohort_eligibility: str,
) -> str:
    if valid_dataset_run is not True:
        return "INVALID_OR_EXCLUDED"
    if countable is True:
        return "COUNTABLE"
    if paper_eligible is False or cohort_eligibility.upper() == "EXCLUDED":
        return "SUPPLEMENTAL_NONPAPER"
    if low_signal:
        return "SUPPLEMENTAL_LOW_SIGNAL"
    return "SUPPLEMENTAL_EXTRA"


def _evidence_governance_class_from_db(
    *,
    quota_state: str,
    technical_validity_state: str,
    valid_dataset_run: bool | None,
    countable: bool | None,
    low_signal: bool,
    paper_eligible: bool | None,
    cohort_eligibility: str,
) -> str:
    quota_state_norm = _norm_text(quota_state).upper()
    technical_state_norm = _norm_text(technical_validity_state).upper()
    if technical_state_norm == "TECH_INVALID":
        return "INVALID_OR_EXCLUDED"
    if technical_state_norm == "TECH_VALID":
        if quota_state_norm == "QUOTA_VALID":
            return "COUNTABLE"
        if quota_state_norm == "SUPPLEMENTAL_VALID":
            if paper_eligible is False or _norm_text(cohort_eligibility).upper() == "EXCLUDED":
                return "SUPPLEMENTAL_NONPAPER"
            if low_signal:
                return "SUPPLEMENTAL_LOW_SIGNAL"
            return "SUPPLEMENTAL_EXTRA"
        if quota_state_norm == "QUOTA_INELIGIBLE":
            return "INVALID_OR_EXCLUDED"
    return _evidence_governance_class(
        valid_dataset_run=valid_dataset_run,
        countable=countable,
        low_signal=low_signal,
        paper_eligible=paper_eligible,
        cohort_eligibility=cohort_eligibility,
    )


def _build_identity_key(row: Mapping[str, Any]) -> tuple[int, str, str]:
    version_code_raw = _safe_int(row.get("version_code"))
    version_code = version_code_raw if version_code_raw is not None else -1
    base_sha = _norm_text(row.get("base_apk_sha256"))
    version_name = _norm_text(row.get("version_name"))
    return (version_code, base_sha, version_name)


def _current_build_phase_status(*, baseline_countable: int, interactive_countable: int) -> tuple[str, str]:
    if baseline_countable < BASELINE_REQUIRED:
        return ("BASELINE_NEEDED", "baseline")
    if interactive_countable < INTERACTIVE_REQUIRED:
        return ("INTERACTIVE_NEEDED", "interactive")
    return ("COMPLETE", "—")


def _pcap_relpath(run_dir: Path, manifest: dict[str, Any]) -> str:
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), list) else []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        if artifact.get("type") == "pcapdroid_capture":
            rel = _norm_text(artifact.get("relative_path"))
            if rel:
                return rel
    capture_dir = run_dir / "artifacts" / "pcapdroid_capture"
    for candidate in sorted(capture_dir.glob("*.pcap*")):
        return str(candidate.relative_to(run_dir))
    return ""


def _pcap_exists(run_dir: Path, relpath: str) -> bool:
    if not relpath:
        return False
    return (run_dir / relpath).exists()


def _window_scores_path(run_dir: Path) -> Path | None:
    ml_root = run_dir / "analysis" / "ml"
    if not ml_root.exists():
        return None
    candidates = sorted(ml_root.glob("*/window_scores.csv"))
    if candidates:
        return candidates[0]
    candidate = ml_root / "window_scores.csv"
    return candidate if candidate.exists() else None


def _load_profile_catalog() -> dict[str, dict[str, str]]:
    catalog_path = _REPO_ROOT / "profiles" / "profile_v3_app_catalog.json"
    payload = _read_json(catalog_path) or {}
    out: dict[str, dict[str, str]] = {}
    for package, row in payload.items():
        if not isinstance(row, dict):
            continue
        out[_norm_text(package).lower()] = {
            "app": _norm_text(row.get("app")),
            "app_category": _norm_text(row.get("app_category")),
        }
    return out


def _load_app_labels(packages: set[str]) -> dict[str, str]:
    if not packages:
        return {}
    try:
        from scytaledroid.Database.db_core import db_queries as core_q

        placeholders = ", ".join(["%s"] * len(packages))
        rows = core_q.run_sql(
            f"""
            SELECT LOWER(TRIM(package_name)) AS package_name,
                   NULLIF(display_name, '') AS display_name
            FROM apps
            WHERE LOWER(TRIM(package_name)) IN ({placeholders})
            """,
            tuple(sorted(packages)),
            fetch="all",
            dictionary=True,
            query_name="dynamic_draft.app_labels",
        ) or []
    except Exception:
        return {}
    out: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        package = _norm_text(row.get("package_name")).lower()
        display_name = _norm_text(row.get("display_name"))
        if package and display_name:
            out[package] = display_name
    return out


def _load_active_cohort_context() -> dict[str, Any]:
    try:
        from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_context

        context = active_research_cohort_context()
    except Exception:
        context = {}
    return dict(context) if isinstance(context, dict) else {}


def _load_dynamic_sessions() -> dict[str, dict[str, Any]]:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q

        rows = core_q.run_sql(
            """
            SELECT
              ds.dynamic_run_id,
              ds.package_name,
              ds.device_serial,
              ds.base_apk_sha256,
              ds.artifact_set_hash,
              ds.status,
              COALESCE(ctx.valid_dataset_run, ds.valid_dataset_run) AS valid_dataset_run,
              COALESCE(ctx.invalid_reason_code, ds.invalid_reason_code) AS invalid_reason_code,
              CASE
                WHEN ctx.quota_state = 'QUOTA_VALID' THEN 1
                WHEN ctx.quota_state IN ('SUPPLEMENTAL_VALID', 'QUOTA_INELIGIBLE', 'QUOTA_LEGACY_UNKNOWN') THEN 0
                ELSE ds.countable
              END AS countable,
              ds.pcap_relpath,
              ds.pcap_bytes,
              ds.pcap_valid,
              COALESCE(ctx.effective_run_profile, ds.operator_run_profile) AS operator_run_profile,
              ds.duration_seconds,
              ds.version_name,
              ds.version_code,
              ds.evidence_path,
              ctx.quota_state,
              ctx.technical_validity_state,
              ctx.cohort_paper_eligible,
              ctx.cohort_eligibility_state,
              ctx.low_signal
            FROM dynamic_sessions ds
            LEFT JOIN v_dynamic_run_context_v1 ctx
              ON ctx.dynamic_run_id = ds.dynamic_run_id
            """,
            (),
            fetch="all",
            dictionary=True,
            query_name="dynamic_draft.dynamic_sessions",
        ) or []
    except Exception:
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        run_id = _norm_text(row.get("dynamic_run_id"))
        if run_id:
            out[run_id] = dict(row)
    return out


def _load_domain_index_rows() -> dict[str, dict[str, int]]:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q

        rows = core_q.run_sql(
            """
            SELECT
              dynamic_run_id,
              COUNT(*) AS observation_rows,
              COUNT(DISTINCT root_domain) AS root_domain_count
            FROM dynamic_domain_observations
            GROUP BY dynamic_run_id
            """,
            (),
            fetch="all",
            dictionary=True,
            query_name="dynamic_draft.domain_index_rows",
        ) or []
    except Exception:
        return {}
    out: dict[str, dict[str, int]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        run_id = _norm_text(row.get("dynamic_run_id"))
        if run_id:
            out[run_id] = {
                "observation_rows": int(row.get("observation_rows") or 0),
                "root_domain_count": int(row.get("root_domain_count") or 0),
            }
    return out


def _load_validity_report(root: Path) -> dict[str, dict[str, Any]]:
    from scytaledroid.DynamicAnalysis.tools.evidence.verify_core import verify_dynamic_evidence_packs

    report = verify_dynamic_evidence_packs(root)
    out: dict[str, dict[str, Any]] = {}
    for row in report.get("runs") or []:
        if isinstance(row, dict):
            run_id = _norm_text(row.get("run_id"))
            if run_id:
                out[run_id] = dict(row)
    return out


def _service_signal_summary(report: dict[str, Any], package_name: str) -> dict[str, Any]:
    from scytaledroid.DynamicAnalysis.pcap.context_summary import summarize_pcap_service_context

    bundle = summarize_pcap_service_context(report, package_name=package_name)
    service_context = bundle.get("service_context") if isinstance(bundle.get("service_context"), dict) else {}
    service_signals = bundle.get("service_signals") if isinstance(bundle.get("service_signals"), dict) else {}
    return {
        "service_count": int(service_context.get("service_count") or 0),
        "signal_count": int(service_signals.get("signal_count") or 0),
        "unresolved_service_count": int(service_context.get("unresolved_domain_count") or 0),
        "unresolved_signal_count": len(service_signals.get("services_without_signal_mappings") or []),
    }


def _normalize_issues_csv(verify_row: dict[str, Any]) -> str:
    from scytaledroid.DynamicAnalysis.pcap.diagnostics import verify_issue_codes_csv

    return verify_issue_codes_csv(verify_row)


def _classify_missing_domain_observation_case(row: dict[str, Any], verify_row: dict[str, Any]) -> tuple[str, str]:
    from scytaledroid.DynamicAnalysis.pcap.diagnostics import canonical_pcap_failure_code, export_pcap_failure_detail

    if int(row.get("pcap_report_exists") or 0) != 1 or int(row.get("domain_observations_in_db") or 0) == 1:
        return ("not_missing", "No missing dynamic-domain-observation condition is present.")

    valid_dataset_run = int(row.get("valid_dataset_run") or 0)
    invalid_reason = _norm_text(row.get("invalid_reason_code"))
    canonical = canonical_pcap_failure_code(
        report_status="skip" if int(row.get("pcap_report_exists") or 0) == 1 else "",
        invalid_reason_code=invalid_reason,
        verify_row=verify_row,
    )
    export_detail = export_pcap_failure_detail(canonical)

    if valid_dataset_run == 0 and invalid_reason == "PCAP_MISSING":
        if export_detail == "invalid_pcap_artifact_missing":
            return (
                "invalid_pcap_artifact_missing",
                "Invalid run: PCAP artifact missing, so absent domain observations reflect unusable capture evidence, not DB index lag.",
            )
        if export_detail:
            return (
                export_detail,
                "Invalid run: PCAP unavailable, so absent domain observations do not indicate normal DB index lag.",
            )
        return (
            "invalid_pcap_missing",
            "Invalid run: PCAP missing, so absent domain observations do not indicate normal DB index lag.",
        )

    if valid_dataset_run == 0:
        return (
            "invalid_non_pcap",
            "Invalid run: absent domain observations are attached to an excluded run and should not be treated as publication-grade index lag.",
        )

    return (
        "index_lag_candidate",
        "Potential DB index lag: run has evidence on disk but no dynamic_domain_observations rows yet.",
    )


def _split_missing_domain_rows(
    rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    invalid_rows: list[dict[str, Any]] = []
    index_lag_rows: list[dict[str, Any]] = []
    for row in rows:
        reason = _norm_text(row.get("reason"))
        if reason == "index_lag_candidate":
            index_lag_rows.append(row)
        else:
            invalid_rows.append(row)
    return invalid_rows, index_lag_rows


def _raw_pcap_failure_detail(run_dir: Path, manifest: dict[str, Any], row: dict[str, Any], verify_row: dict[str, Any]) -> str:
    from scytaledroid.DynamicAnalysis.pcap.diagnostics import (
        canonical_pcap_failure_code,
        dataset_pcap_failure_detail,
        raw_pcap_failure_detail_from_canonical,
    )

    dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
    raw_detail = _norm_text(dataset.get("pcap_failure_detail"))
    invalid_reason = _norm_text(row.get("invalid_reason_code") or dataset.get("invalid_reason_code")).upper()
    canonical = canonical_pcap_failure_code(
        report_status="skip" if int(row.get("pcap_report_exists") or 0) == 1 else "",
        invalid_reason_code=invalid_reason,
        verify_row=verify_row,
    )
    pcap_size_bytes = _safe_int(row.get("pcap_bytes")) or _safe_int(dataset.get("pcap_size_bytes")) or 0
    if not raw_detail and (invalid_reason.startswith("PCAP_") or canonical):
        raw_detail = _norm_text(dataset_pcap_failure_detail(run_dir, pcap_size_int=pcap_size_bytes))
    if not raw_detail:
        raw_detail = raw_pcap_failure_detail_from_canonical(canonical)
    return raw_detail


def _draft_bullets(summary: dict[str, Any], x_rows: list[dict[str, Any]], rdi_row: dict[str, Any]) -> str:
    invalid_pcap_by_raw = dict(summary.get("runs_missing_domain_observations_invalid_pcap_by_raw_detail") or {})
    lines = [
        "# Dynamic Draft Results",
        "",
        "## What We Can Claim Tonight",
        "",
        f"- Dynamic evidence packs scanned: {summary['dynamic_runs_scanned']}.",
        f"- Dynamic session rows in DB: {summary['dynamic_sessions_in_db']}.",
        f"- Valid dataset runs in the current evidence corpus: {summary['valid_dataset_runs_scanned']}.",
        f"- Quota-valid runs in the current evidence corpus: {summary['countable_runs_scanned']}.",
        f"- Apps seen in the current evidence corpus: {summary['apps_seen']}.",
        f"- Runs with PCAP artifacts present: {summary['runs_with_pcap']}.",
        f"- Runs with `pcap_report.json`: {summary['runs_with_pcap_report']}.",
        f"- Runs with `pcap_features.json`: {summary['runs_with_pcap_features']}.",
        f"- Runs where per-run ML window scores are expected: {summary['runs_with_window_scores_expected']}.",
        f"- Runs with per-run ML window score artifacts present: {summary['runs_with_window_scores_available']}.",
        f"- Valid supplemental runs retained outside quota: {summary['valid_supplemental_runs_scanned']}.",
        f"- Supplemental low-signal runs retained: {summary['supplemental_low_signal_runs_scanned']}.",
        f"- Supplemental extra-after-quota runs retained: {summary['supplemental_extra_runs_scanned']}.",
        f"- Supplemental non-paper runs retained: {summary['supplemental_nonpaper_runs_scanned']}.",
        f"- Current-build valid runs in the local corpus: {summary['current_build_valid_runs_scanned']}.",
        f"- Historical-build valid runs retained in the local corpus: {summary['historical_valid_runs_scanned']}.",
        f"- Packages with multiple build variants in the local corpus: {summary['packages_with_multiple_builds_in_corpus']}.",
        f"- Apps current-build complete by 3+4 phase targets: {summary['apps_current_build_complete']}.",
        f"- Apps still needing current-build baseline: {summary['apps_current_build_need_baseline']}.",
        f"- Apps still needing current-build interactive: {summary['apps_current_build_need_interactive']}.",
        f"- Active cohort: {summary['active_cohort_label']} ({summary['active_cohort_app_count']} apps).",
        f"- Active cohort apps with local evidence: {summary['active_cohort_apps_with_local_evidence']}.",
        f"- Active cohort apps complete: {summary['active_cohort_apps_complete']}.",
        f"- Active cohort apps still needing baseline/no local evidence: {summary['active_cohort_apps_need_baseline']}.",
        f"- Active cohort apps still needing interactive: {summary['active_cohort_apps_need_interactive']}.",
        f"- Runs already indexed into `dynamic_domain_observations`: {summary['runs_with_domain_observations_db']}.",
        f"- Runs missing `dynamic_domain_observations` rows: {summary['runs_missing_domain_observations_db']}.",
        f"- Missing-row cases classified as invalid PCAP evidence: {summary['runs_missing_domain_observations_invalid_pcap']}.",
        f"- Missing-row cases still consistent with possible DB index lag: {summary['runs_missing_domain_observations_index_lag']}.",
        "",
        "## Domain Index Status",
        "",
    ]
    if invalid_pcap_by_raw:
        detail_bits = [f"{key}={value}" for key, value in sorted(invalid_pcap_by_raw.items())]
        lines.append(f"- Invalid-PCAP missing-row breakdown: {', '.join(detail_bits)}.")
    if int(summary.get("runs_missing_domain_observations_index_lag") or 0) == 0:
        lines.extend(
            [
                "- No current evidence-backed runs are still classified as DB domain-index lag candidates.",
                "- Remaining missing `dynamic_domain_observations` rows are invalid-PCAP exclusions, not indexing debt.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "- Some current evidence-backed runs still appear consistent with domain-index lag and may benefit from backfill/reindex review.",
                "",
            ]
        )
    if int(summary.get("runs_with_window_scores_expected") or 0) == 0:
        lines.extend(
            [
                "- Current corpus is composed of `basic_usage` runs; missing `analysis/ml/v1/window_scores.csv` is expected for these runs.",
                "",
            ]
        )
    elif int(summary.get("runs_missing_window_scores_when_expected") or 0) == 0:
        lines.extend(
            [
                "- All runs that were expected to materialize per-run ML window scores did so successfully.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "- Some runs that were expected to materialize per-run ML window scores are still missing those artifacts.",
                "",
            ]
        )
    lines.extend(
        [
        "## X/Twitter Coverage",
        "",
        ]
    )
    if x_rows:
        idle = sum(1 for row in x_rows if row.get("mode") == "idle")
        interactive = sum(1 for row in x_rows if row.get("mode") == "interactive")
        valid = sum(1 for row in x_rows if int(row.get("valid_dataset_run") or 0) == 1)
        indexed = sum(1 for row in x_rows if int(row.get("domain_observations_in_db") or 0) == 1)
        lines.extend(
            [
                f"- X/Twitter runs found: {len(x_rows)}.",
                f"- X/Twitter idle runs: {idle}.",
                f"- X/Twitter interactive runs: {interactive}.",
                f"- X/Twitter valid runs: {valid}.",
                f"- X/Twitter runs already indexed into DB domain context: {indexed}.",
            ]
        )
    else:
        lines.append("- No X/Twitter runs were found in the current evidence corpus.")
    if rdi_row.get("current_rdi_available"):
        lines.append(
            f"- Current X/Twitter RDI is available: idle={rdi_row['current_mu_idle_rdi']} "
            f"interactive={rdi_row['current_mu_interactive_rdi']} delta={rdi_row['current_delta_rdi']}."
        )
    else:
        lines.append(
            "- Current X/Twitter RDI is not available from the present evidence/export surfaces; "
            "only the prior paper anchor is available tonight."
        )
    lines.extend(
        [
            f"- Historical X/Twitter anchor: idle={X_TWITTER_ANCHOR['historical_mu_idle_rdi']:.4f} "
            f"interactive={X_TWITTER_ANCHOR['historical_mu_interactive_rdi']:.4f} "
            f"delta={X_TWITTER_ANCHOR['historical_delta_rdi']:.4f}.",
            "",
            "## Limitations / Future Work",
            "",
            (
                "- DB-derived domain/service/signal indexing still has current evidence-backed lag candidates."
                if int(summary.get("runs_missing_domain_observations_index_lag") or 0) > 0
                else "- DB-derived domain/service/signal indexing is aligned for current valid evidence; remaining gaps are invalid-PCAP exclusions."
            ),
            "- Missing `dynamic_domain_observations` rows should be interpreted through raw PCAP failure detail before treating them as DB lag.",
            "- Current enriched static-to-dynamic bridge evidence still relies partly on embedded plans and read-only overlay analysis.",
            "- Current corpus does not expose ready-to-use RDI artifacts for the newly collected X/Twitter runs.",
            (
                f"- Established backfill command for the domain index: `{summary['proposed_domain_backfill_command']}`."
                if int(summary.get("runs_missing_domain_observations_index_lag") or 0) > 0
                else f"- Established backfill command remains available if new index-lag candidates appear: `{summary['proposed_domain_backfill_command']}`."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def _draft_paragraphs(summary: dict[str, Any], x_rows: list[dict[str, Any]], rdi_row: dict[str, Any]) -> str:
    invalid_pcap_by_raw = dict(summary.get("runs_missing_domain_observations_invalid_pcap_by_raw_detail") or {})
    valid_runs = int(summary.get("valid_dataset_runs_scanned") or 0)
    total_runs = int(summary.get("dynamic_runs_scanned") or 0)
    countable_runs = int(summary.get("countable_runs_scanned") or 0)
    apps_seen = int(summary.get("apps_seen") or 0)
    domain_indexed = int(summary.get("runs_with_domain_observations_db") or 0)
    missing_domain_rows = int(summary.get("runs_missing_domain_observations_db") or 0)
    invalid_pcap_missing = int(summary.get("runs_missing_domain_observations_invalid_pcap") or 0)
    index_lag_missing = int(summary.get("runs_missing_domain_observations_index_lag") or 0)
    expected_window_scores = int(summary.get("runs_with_window_scores_expected") or 0)
    available_window_scores = int(summary.get("runs_with_window_scores_available") or 0)
    missing_window_scores = int(summary.get("runs_missing_window_scores_when_expected") or 0)

    x_total = len(x_rows)
    x_valid = sum(1 for row in x_rows if int(row.get("valid_dataset_run") or 0) == 1)
    x_indexed = sum(1 for row in x_rows if int(row.get("domain_observations_in_db") or 0) == 1)
    x_idle = sum(1 for row in x_rows if row.get("mode") == "idle")
    x_interactive = sum(1 for row in x_rows if row.get("mode") == "interactive")

    paragraphs = [
        (
            f"The current dynamic corpus contains {total_runs} evidence packs across {apps_seen} apps, "
            f"with {valid_runs} runs presently classified as valid dataset evidence and {countable_runs} runs "
            f"currently classified as quota-valid under the cohort protocol. PCAP-derived reports are present for "
            f"{int(summary.get('runs_with_pcap_report') or 0)} runs and feature exports are present for "
            f"{int(summary.get('runs_with_pcap_features') or 0)} runs. Outside quota, the corpus presently retains "
            f"{int(summary.get('valid_supplemental_runs_scanned') or 0)} valid supplemental runs, including "
            f"{int(summary.get('supplemental_low_signal_runs_scanned') or 0)} low-signal runs, "
            f"{int(summary.get('supplemental_extra_runs_scanned') or 0)} extra-after-quota runs, and "
            f"{int(summary.get('supplemental_nonpaper_runs_scanned') or 0)} non-paper supplemental runs. "
            f"Within the local corpus, {int(summary.get('current_build_valid_runs_scanned') or 0)} valid runs align "
            f"to the latest observed build per app, while {int(summary.get('historical_valid_runs_scanned') or 0)} "
            f"valid runs belong to older retained builds. By the current 3-baseline / 4-interactive target, "
            f"{int(summary.get('apps_current_build_complete') or 0)} apps are complete, "
            f"{int(summary.get('apps_current_build_need_baseline') or 0)} still need baseline coverage, and "
            f"{int(summary.get('apps_current_build_need_interactive') or 0)} still need interactive coverage. "
            f"For the active cohort {summary.get('active_cohort_label') or 'Research cohort'}, "
            f"{int(summary.get('active_cohort_apps_with_local_evidence') or 0)} of "
            f"{int(summary.get('active_cohort_app_count') or 0)} cohort apps currently have local evidence, "
            f"{int(summary.get('active_cohort_apps_complete') or 0)} are complete, "
            f"{int(summary.get('active_cohort_apps_need_baseline') or 0)} still need baseline or first local capture, "
            f"and {int(summary.get('active_cohort_apps_need_interactive') or 0)} still need interactive coverage."
        ),
    ]

    if index_lag_missing == 0:
        detail_bits = ", ".join(f"{key}={value}" for key, value in sorted(invalid_pcap_by_raw.items()))
        paragraphs.append(
            (
                f"DB-backed domain indexing is aligned for current valid evidence: {domain_indexed} runs are already "
                f"materialized in `dynamic_domain_observations`, and no remaining runs are currently classified as "
                f"evidence-backed index-lag candidates. The {missing_domain_rows} remaining missing-domain cases are "
                f"all invalid-PCAP exclusions rather than indexing debt"
                + (f" ({detail_bits})" if detail_bits else "")
                + "."
            )
        )
    else:
        paragraphs.append(
            (
                f"DB-backed domain indexing covers {domain_indexed} runs, but {index_lag_missing} runs still appear "
                f"consistent with evidence-backed index lag. The remaining missing-domain cases should therefore be "
                f"split between invalid-PCAP exclusions ({invalid_pcap_missing}) and true indexing follow-up "
                f"candidates ({index_lag_missing})."
            )
        )

    if expected_window_scores == 0:
        paragraphs.append(
            "The present corpus is composed of `basic_usage` scenario runs rather than profile-v3 strict captures, so the absence of `analysis/ml/v1/window_scores.csv` artifacts should not be treated as missing evidence or a failed ML derivation contract for this package."
        )
    elif missing_window_scores == 0:
        paragraphs.append(
            f"All {available_window_scores} runs that were expected to emit per-run ML window-score artifacts did so successfully."
        )
    else:
        paragraphs.append(
            f"{missing_window_scores} runs were expected to emit per-run ML window-score artifacts, but only {available_window_scores} currently expose those files."
        )

    if x_total > 0:
        x_sentence = (
            f"X/Twitter currently contributes {x_total} runs to the corpus, all {x_idle} of which are idle-mode "
            f"captures and {x_interactive} of which are interactive captures. {x_valid} of those runs are presently "
            f"valid and {x_indexed} are already indexed into DB-backed domain context."
        )
        if rdi_row.get("current_rdi_available"):
            x_sentence += (
                f" Current corpus RDI is available for X/Twitter with idle={rdi_row['current_mu_idle_rdi']}, "
                f"interactive={rdi_row['current_mu_interactive_rdi']}, and delta={rdi_row['current_delta_rdi']}."
            )
        else:
            x_sentence += (
                " Current corpus RDI is not yet available from the present export surfaces, so the prior paper anchor "
                "remains the only directly reportable X/Twitter RDI reference tonight."
            )
        paragraphs.append(x_sentence)

    paragraphs.append(
        "The main remaining limitations are capture-quality rather than service/signal taxonomy coverage: unresolved "
        "domain-context rows are no longer the blocker, but invalid PCAP artifacts still constrain a small number of "
        "runs and prevent those packs from contributing to publication-grade domain-observation tables."
    )

    return "\n\n".join(paragraphs)


def generate_report(*, output_dir: Path | None = None) -> dict[str, Any]:
    root = _dynamic_root()
    output_root = output_dir or _default_output_dir()
    output_root.mkdir(parents=True, exist_ok=True)

    verify_by_run = _load_validity_report(root)
    sessions_by_run = _load_dynamic_sessions()
    domain_index_by_run = _load_domain_index_rows()
    catalog = _load_profile_catalog()

    manifest_paths = sorted(root.glob("*/run_manifest.json"))
    packages = {
        _norm_text((_read_json(path) or {}).get("target", {}).get("package_name")).lower()
        for path in manifest_paths
        if _norm_text((_read_json(path) or {}).get("target", {}).get("package_name"))
    }
    label_map = _load_app_labels(packages)

    ledger_rows: list[dict[str, Any]] = []
    app_rollup: dict[str, dict[str, Any]] = {}
    service_signal_rollup: dict[str, dict[str, Any]] = {}
    missing_domain_rows: list[dict[str, Any]] = []
    x_rows: list[dict[str, Any]] = []

    for manifest_path in manifest_paths:
        run_dir = manifest_path.parent
        manifest = _read_json(manifest_path) or {}
        run_id = _norm_text(manifest.get("dynamic_run_id") or manifest.get("run_id") or run_dir.name)
        target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
        dataset = manifest.get("dataset") if isinstance(manifest.get("dataset"), dict) else {}
        operator = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
        report = _read_json(run_dir / "analysis" / "pcap_report.json") or {}
        features = _read_json(run_dir / "analysis" / "pcap_features.json") or {}

        package_name = _norm_text(target.get("package_name")).lower()
        session_row = sessions_by_run.get(run_id, {})
        verify_row = verify_by_run.get(run_id, {})
        domain_row = domain_index_by_run.get(run_id, {})

        app_label = (
            _norm_text(target.get("display_name"))
            or _norm_text(target.get("app_label"))
            or label_map.get(package_name, "")
            or catalog.get(package_name, {}).get("app", "")
            or package_name
        )
        run_profile = (
            _norm_text(operator.get("run_profile"))
            or _norm_text(dataset.get("run_profile"))
            or _norm_text(session_row.get("operator_run_profile"))
        )
        mode = _mode_from_profile(run_profile)
        interaction_label = _interaction_label(run_profile)
        pcap_relpath = _norm_text(session_row.get("pcap_relpath")) or _pcap_relpath(run_dir, manifest)
        pcap_exists = _pcap_exists(run_dir, pcap_relpath)
        pcap_bytes = (
            _safe_int(report.get("pcap_size_bytes"))
            or _safe_int(session_row.get("pcap_bytes"))
            or (_safe_int((run_dir / pcap_relpath).stat().st_size) if pcap_exists else None)
        )
        window_scores = _window_scores_path(run_dir)
        scenario_id = _scenario_id(manifest)
        window_scores_expected = _window_scores_expected_for_manifest(manifest)
        valid_dataset_run = _normalize_boolish(session_row.get("valid_dataset_run"))
        if valid_dataset_run is None:
            valid_dataset_run = _normalize_boolish(dataset.get("valid_dataset_run"))
        countable = _normalize_boolish(session_row.get("countable"))
        if countable is None:
            countable = _normalize_boolish(dataset.get("countable"))
        low_signal_db = _normalize_boolish(session_row.get("low_signal"))
        low_signal = low_signal_db if low_signal_db is not None else (_normalize_boolish(dataset.get("low_signal")) is True)
        paper_eligible = _normalize_boolish(session_row.get("cohort_paper_eligible"))
        if paper_eligible is None:
            paper_eligible = _normalize_boolish(dataset.get("paper_eligible"))
        cohort_eligibility = _norm_text(session_row.get("cohort_eligibility_state")) or _norm_text(dataset.get("cohort_eligibility"))
        quota_state = _norm_text(session_row.get("quota_state"))
        technical_validity_state = _norm_text(session_row.get("technical_validity_state"))
        invalid_reason = _norm_text(session_row.get("invalid_reason_code")) or _norm_text(dataset.get("invalid_reason_code"))
        evidence_governance_class = _evidence_governance_class_from_db(
            quota_state=quota_state,
            technical_validity_state=technical_validity_state,
            valid_dataset_run=valid_dataset_run,
            countable=countable,
            low_signal=low_signal,
            paper_eligible=paper_eligible,
            cohort_eligibility=cohort_eligibility,
        )
        service_signal = _service_signal_summary(report, package_name) if report else {
            "service_count": 0,
            "signal_count": 0,
            "unresolved_service_count": 0,
            "unresolved_signal_count": 0,
        }

        row = {
            "dynamic_run_id": run_id,
            "session_id": run_id,
            "package_name": package_name,
            "app_label": app_label,
            "device_serial": _norm_text(session_row.get("device_serial")) or _norm_text(target.get("device_serial")),
            "version_code": _safe_int(session_row.get("version_code")),
            "version_name": _norm_text(session_row.get("version_name")) or _norm_text(target.get("version_name")),
            "base_apk_sha256": _norm_text(session_row.get("base_apk_sha256")) or _norm_text((manifest.get("run_identity") or {}).get("base_apk_sha256")),
            "artifact_set_hash": _norm_text(session_row.get("artifact_set_hash")) or _norm_text((manifest.get("run_identity") or {}).get("artifact_set_hash")),
            "mode": mode,
            "interaction_label": interaction_label,
            "run_profile": run_profile,
            "status": _norm_text(session_row.get("status")) or _norm_text(manifest.get("status")) or "unknown",
            "scenario_id": scenario_id,
            "valid_dataset_run": 1 if valid_dataset_run is True else 0 if valid_dataset_run is False else "",
            "invalid_reason_code": invalid_reason,
            "countable": 1 if countable is True else 0 if countable is False else "",
            "cohort_eligibility": cohort_eligibility,
            "quota_state": quota_state,
            "technical_validity_state": technical_validity_state,
            "paper_eligible": 1 if paper_eligible is True else 0 if paper_eligible is False else "",
            "low_signal": int(low_signal),
            "low_signal_reasons_csv": ",".join(str(item) for item in (dataset.get("low_signal_reasons") or []) if str(item)),
            "evidence_governance_class": evidence_governance_class,
            "pcap_relpath": pcap_relpath,
            "pcap_exists": int(pcap_exists),
            "pcap_bytes": pcap_bytes or 0,
            "pcap_report_exists": int((run_dir / "analysis" / "pcap_report.json").exists()),
            "pcap_features_exists": int((run_dir / "analysis" / "pcap_features.json").exists()),
            "window_scores_exists": int(window_scores is not None),
            "window_scores_expected": int(window_scores_expected),
            "window_scores_relpath": str(window_scores.relative_to(run_dir)) if window_scores else "",
            "domain_observations_in_db": int(bool(domain_row)),
            "domain_observation_rows_db": int(domain_row.get("observation_rows") or 0),
            "root_domains_db": int(domain_row.get("root_domain_count") or 0),
            "service_count_fs": int(service_signal["service_count"]),
            "signal_count_fs": int(service_signal["signal_count"]),
            "unresolved_service_count_fs": int(service_signal["unresolved_service_count"]),
            "unresolved_signal_count_fs": int(service_signal["unresolved_signal_count"]),
            "duration_seconds": _safe_int(session_row.get("duration_seconds")) or _safe_int(dataset.get("actual_sampling_seconds")) or 0,
            "evidence_root": str(run_dir.resolve()),
        }
        ledger_rows.append(row)

        agg = app_rollup.setdefault(
            package_name,
            {
                "package_name": package_name,
                "app_label": app_label,
                "runs_total": 0,
                "valid_runs": 0,
                "countable_runs": 0,
                "idle_runs": 0,
                "interactive_runs": 0,
                "pcap_backed_runs": 0,
                "pcap_report_runs": 0,
                "pcap_features_runs": 0,
                "window_scores_runs": 0,
                "supplemental_valid_runs": 0,
                "supplemental_low_signal_runs": 0,
                "supplemental_extra_runs": 0,
                "supplemental_nonpaper_runs": 0,
                "domain_indexed_runs": 0,
                "domain_observation_rows_db": 0,
            },
        )
        agg["runs_total"] += 1
        agg["valid_runs"] += int(row["valid_dataset_run"] == 1)
        agg["countable_runs"] += int(row["countable"] == 1)
        agg["idle_runs"] += int(mode == "idle")
        agg["interactive_runs"] += int(mode == "interactive")
        agg["pcap_backed_runs"] += int(row["pcap_exists"] == 1)
        agg["pcap_report_runs"] += int(row["pcap_report_exists"] == 1)
        agg["pcap_features_runs"] += int(row["pcap_features_exists"] == 1)
        agg["window_scores_runs"] += int(row["window_scores_exists"] == 1)
        agg["supplemental_valid_runs"] += int(
            row["evidence_governance_class"] in {"SUPPLEMENTAL_LOW_SIGNAL", "SUPPLEMENTAL_EXTRA", "SUPPLEMENTAL_NONPAPER"}
        )
        agg["supplemental_low_signal_runs"] += int(row["evidence_governance_class"] == "SUPPLEMENTAL_LOW_SIGNAL")
        agg["supplemental_extra_runs"] += int(row["evidence_governance_class"] == "SUPPLEMENTAL_EXTRA")
        agg["supplemental_nonpaper_runs"] += int(row["evidence_governance_class"] == "SUPPLEMENTAL_NONPAPER")
        agg["domain_indexed_runs"] += int(row["domain_observations_in_db"] == 1)
        agg["domain_observation_rows_db"] += int(row["domain_observation_rows_db"] or 0)

        svc = service_signal_rollup.setdefault(
            package_name,
            {
                "package_name": package_name,
                "app_label": app_label,
                "runs_seen": 0,
                "valid_runs": 0,
                "domain_indexed_runs": 0,
                "domain_observation_rows_db": 0,
                "root_domains_db": 0,
                "service_count_fs_total": 0,
                "signal_count_fs_total": 0,
                "unresolved_service_count_fs_total": 0,
                "unresolved_signal_count_fs_total": 0,
            },
        )
        svc["runs_seen"] += 1
        svc["valid_runs"] += int(row["valid_dataset_run"] == 1)
        svc["domain_indexed_runs"] += int(row["domain_observations_in_db"] == 1)
        svc["domain_observation_rows_db"] += int(row["domain_observation_rows_db"] or 0)
        svc["root_domains_db"] += int(row["root_domains_db"] or 0)
        svc["service_count_fs_total"] += int(row["service_count_fs"] or 0)
        svc["signal_count_fs_total"] += int(row["signal_count_fs"] or 0)
        svc["unresolved_service_count_fs_total"] += int(row["unresolved_service_count_fs"] or 0)
        svc["unresolved_signal_count_fs_total"] += int(row["unresolved_signal_count_fs"] or 0)

        if row["pcap_report_exists"] == 1 and row["domain_observations_in_db"] == 0:
            missing_reason, missing_summary = _classify_missing_domain_observation_case(row, verify_row)
            missing_domain_rows.append(
                {
                    "dynamic_run_id": run_id,
                    "package_name": package_name,
                    "app_label": app_label,
                    "mode": mode,
                    "interaction_label": interaction_label,
                    "valid_dataset_run": row["valid_dataset_run"],
                    "countable": row["countable"],
                    "status": row["status"],
                    "invalid_reason_code": row["invalid_reason_code"],
                    "pcap_bytes": row["pcap_bytes"],
                    "evidence_root": row["evidence_root"],
                    "reason": missing_reason,
                    "reason_summary": missing_summary,
                    "pcap_failure_detail_raw": _raw_pcap_failure_detail(run_dir, manifest, row, verify_row),
                    "verifier_issue_codes": _normalize_issues_csv(verify_row),
                }
            )

        if package_name == "com.twitter.android":
            x_rows.append(row)

    app_rows = sorted(app_rollup.values(), key=lambda row: (row["package_name"]))
    service_signal_rows = sorted(service_signal_rollup.values(), key=lambda row: (row["package_name"]))
    x_rows_sorted = sorted(x_rows, key=lambda row: (row["mode"], row["dynamic_run_id"]))
    active_cohort_context = _load_active_cohort_context()
    active_cohort_label = _norm_text(active_cohort_context.get("display_name")) or "Research cohort"
    active_cohort_key = _norm_text(active_cohort_context.get("cohort_key")).lower()
    active_cohort_packages = tuple(
        _norm_text(package).lower()
        for package in (active_cohort_context.get("packages") or ())
        if _norm_text(package)
    )
    by_package_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in ledger_rows:
        by_package_rows[str(row.get("package_name") or "")].append(row)

    current_build_rollup_rows: list[dict[str, Any]] = []
    for package_name, rows in sorted(by_package_rows.items()):
        if not package_name:
            continue
        current_build_key = max((_build_identity_key(row) for row in rows), default=(-1, "", ""))
        current_rows = [row for row in rows if _build_identity_key(row) == current_build_key]
        historical_rows = [row for row in rows if _build_identity_key(row) != current_build_key]
        baseline_countable = sum(
            1
            for row in current_rows
            if str(row.get("mode") or "") == "idle" and int(row.get("countable") or 0) == 1
        )
        interactive_countable = sum(
            1
            for row in current_rows
            if str(row.get("mode") or "") == "interactive" and int(row.get("countable") or 0) == 1
        )
        readiness_state, next_capture_phase = _current_build_phase_status(
            baseline_countable=baseline_countable,
            interactive_countable=interactive_countable,
        )
        current_build_rollup_rows.append(
            {
                "package_name": package_name,
                "app_label": _norm_text(current_rows[0].get("app_label")) if current_rows else _norm_text(rows[0].get("app_label")),
                "current_version_code": current_build_key[0] if current_build_key[0] >= 0 else "",
                "current_version_name": current_build_key[2],
                "current_base_apk_sha256": current_build_key[1],
                "build_variants_seen": len({_build_identity_key(row) for row in rows}),
                "current_build_readiness_state": readiness_state,
                "next_capture_phase": next_capture_phase,
                "current_build_runs_total": len(current_rows),
                "current_build_valid_runs": sum(1 for row in current_rows if int(row.get("valid_dataset_run") or 0) == 1),
                "current_build_countable_runs": sum(1 for row in current_rows if int(row.get("countable") or 0) == 1),
                "current_build_baseline_countable_runs": baseline_countable,
                "current_build_interactive_countable_runs": interactive_countable,
                "current_build_baseline_supplemental_runs": sum(
                    1
                    for row in current_rows
                    if str(row.get("mode") or "") == "idle"
                    and str(row.get("evidence_governance_class") or "")
                    in {"SUPPLEMENTAL_LOW_SIGNAL", "SUPPLEMENTAL_EXTRA", "SUPPLEMENTAL_NONPAPER"}
                ),
                "current_build_interactive_supplemental_runs": sum(
                    1
                    for row in current_rows
                    if str(row.get("mode") or "") == "interactive"
                    and str(row.get("evidence_governance_class") or "")
                    in {"SUPPLEMENTAL_LOW_SIGNAL", "SUPPLEMENTAL_EXTRA", "SUPPLEMENTAL_NONPAPER"}
                ),
                "current_build_supplemental_valid_runs": sum(
                    1
                    for row in current_rows
                    if str(row.get("evidence_governance_class") or "")
                    in {"SUPPLEMENTAL_LOW_SIGNAL", "SUPPLEMENTAL_EXTRA", "SUPPLEMENTAL_NONPAPER"}
                ),
                "current_build_supplemental_low_signal_runs": sum(
                    1 for row in current_rows if str(row.get("evidence_governance_class") or "") == "SUPPLEMENTAL_LOW_SIGNAL"
                ),
                "current_build_supplemental_extra_runs": sum(
                    1 for row in current_rows if str(row.get("evidence_governance_class") or "") == "SUPPLEMENTAL_EXTRA"
                ),
                "current_build_supplemental_nonpaper_runs": sum(
                    1 for row in current_rows if str(row.get("evidence_governance_class") or "") == "SUPPLEMENTAL_NONPAPER"
                ),
                "current_build_invalid_or_excluded_runs": sum(
                    1 for row in current_rows if str(row.get("evidence_governance_class") or "") == "INVALID_OR_EXCLUDED"
                ),
                "current_build_domain_indexed_runs": sum(
                    1 for row in current_rows if int(row.get("domain_observations_in_db") or 0) == 1
                ),
                "historical_runs_total": len(historical_rows),
                "historical_valid_runs": sum(1 for row in historical_rows if int(row.get("valid_dataset_run") or 0) == 1),
                "historical_countable_runs": sum(1 for row in historical_rows if int(row.get("countable") or 0) == 1),
            }
        )

    current_build_rollup_by_package = {
        _norm_text(row.get("package_name")).lower(): row
        for row in current_build_rollup_rows
        if _norm_text(row.get("package_name"))
    }
    active_cohort_readiness_rows: list[dict[str, Any]] = []
    for package_name in active_cohort_packages:
        existing = current_build_rollup_by_package.get(package_name)
        if existing:
            active_cohort_readiness_rows.append(
                {
                    "cohort_key": active_cohort_key,
                    "cohort_label": active_cohort_label,
                    **existing,
                }
            )
            continue
        active_cohort_readiness_rows.append(
            {
                "cohort_key": active_cohort_key,
                "cohort_label": active_cohort_label,
                "package_name": package_name,
                "app_label": label_map.get(package_name, "") or catalog.get(package_name, {}).get("app", "") or package_name,
                "current_version_code": "",
                "current_version_name": "",
                "current_base_apk_sha256": "",
                "build_variants_seen": 0,
                "current_build_readiness_state": "NO_LOCAL_EVIDENCE",
                "next_capture_phase": "baseline",
                "current_build_runs_total": 0,
                "current_build_valid_runs": 0,
                "current_build_countable_runs": 0,
                "current_build_baseline_countable_runs": 0,
                "current_build_interactive_countable_runs": 0,
                "current_build_baseline_supplemental_runs": 0,
                "current_build_interactive_supplemental_runs": 0,
                "current_build_supplemental_valid_runs": 0,
                "current_build_supplemental_low_signal_runs": 0,
                "current_build_supplemental_extra_runs": 0,
                "current_build_supplemental_nonpaper_runs": 0,
                "current_build_invalid_or_excluded_runs": 0,
                "current_build_domain_indexed_runs": 0,
                "historical_runs_total": 0,
                "historical_valid_runs": 0,
                "historical_countable_runs": 0,
            }
        )

    rdi_summary = {
        **X_TWITTER_ANCHOR,
        "current_rdi_available": False,
        "current_mu_idle_rdi": "",
        "current_mu_interactive_rdi": "",
        "current_delta_rdi": "",
        "current_source": "",
        "note": "No current profile-v3 manifest or per-run ML window score export is available for present X/Twitter runs.",
    }

    invalid_missing_rows, index_lag_rows = _split_missing_domain_rows(missing_domain_rows)
    missing_reason_counts = Counter(row["reason"] for row in missing_domain_rows)
    invalid_pcap_missing = sum(
        count for reason, count in missing_reason_counts.items() if reason.startswith("invalid_pcap_")
    )
    invalid_other_missing = sum(
        count
        for reason, count in missing_reason_counts.items()
        if reason.startswith("invalid_") and not reason.startswith("invalid_pcap_")
    )
    index_lag_missing = int(missing_reason_counts.get("index_lag_candidate", 0))
    invalid_pcap_by_raw_detail = dict(
        sorted(
            Counter(
                _norm_text(row.get("pcap_failure_detail_raw"))
                for row in missing_domain_rows
                if str(row.get("reason") or "").startswith("invalid_pcap_")
                and _norm_text(row.get("pcap_failure_detail_raw"))
            ).items()
        )
    )

    summary = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "repo_root": str(_REPO_ROOT),
        "dynamic_evidence_root": str(root.resolve()),
        "dynamic_runs_scanned": len(ledger_rows),
        "dynamic_sessions_in_db": len(sessions_by_run),
        "valid_dataset_runs_scanned": sum(1 for row in ledger_rows if row["valid_dataset_run"] == 1),
        "countable_runs_scanned": sum(1 for row in ledger_rows if row["countable"] == 1),
        "apps_seen": len({row["package_name"] for row in ledger_rows}),
        "scenario_counts": dict(sorted(Counter(_norm_text(row.get("scenario_id")) for row in ledger_rows).items())),
        "runs_with_pcap": sum(1 for row in ledger_rows if row["pcap_exists"] == 1),
        "runs_with_pcap_report": sum(1 for row in ledger_rows if row["pcap_report_exists"] == 1),
        "runs_with_pcap_features": sum(1 for row in ledger_rows if row["pcap_features_exists"] == 1),
        "runs_with_window_scores": sum(1 for row in ledger_rows if row["window_scores_exists"] == 1),
        "runs_with_window_scores_expected": sum(1 for row in ledger_rows if row["window_scores_expected"] == 1),
        "runs_with_window_scores_available": sum(
            1 for row in ledger_rows if row["window_scores_expected"] == 1 and row["window_scores_exists"] == 1
        ),
        "runs_missing_window_scores_when_expected": sum(
            1 for row in ledger_rows if row["window_scores_expected"] == 1 and row["window_scores_exists"] == 0
        ),
        "valid_supplemental_runs_scanned": sum(
            1
            for row in ledger_rows
            if row["evidence_governance_class"] in {"SUPPLEMENTAL_LOW_SIGNAL", "SUPPLEMENTAL_EXTRA", "SUPPLEMENTAL_NONPAPER"}
        ),
        "supplemental_low_signal_runs_scanned": sum(
            1 for row in ledger_rows if row["evidence_governance_class"] == "SUPPLEMENTAL_LOW_SIGNAL"
        ),
        "supplemental_extra_runs_scanned": sum(
            1 for row in ledger_rows if row["evidence_governance_class"] == "SUPPLEMENTAL_EXTRA"
        ),
        "supplemental_nonpaper_runs_scanned": sum(
            1 for row in ledger_rows if row["evidence_governance_class"] == "SUPPLEMENTAL_NONPAPER"
        ),
        "packages_with_multiple_builds_in_corpus": sum(
            1 for row in current_build_rollup_rows if int(row.get("build_variants_seen") or 0) > 1
        ),
        "apps_current_build_complete": sum(
            1 for row in current_build_rollup_rows if str(row.get("current_build_readiness_state") or "") == "COMPLETE"
        ),
        "apps_current_build_need_baseline": sum(
            1 for row in current_build_rollup_rows if str(row.get("current_build_readiness_state") or "") == "BASELINE_NEEDED"
        ),
        "apps_current_build_need_interactive": sum(
            1 for row in current_build_rollup_rows if str(row.get("current_build_readiness_state") or "") == "INTERACTIVE_NEEDED"
        ),
        "active_cohort_key": active_cohort_key,
        "active_cohort_label": active_cohort_label,
        "active_cohort_app_count": len(active_cohort_readiness_rows),
        "active_cohort_apps_with_local_evidence": sum(
            1 for row in active_cohort_readiness_rows if int(row.get("current_build_runs_total") or 0) > 0
        ),
        "active_cohort_apps_complete": sum(
            1 for row in active_cohort_readiness_rows if str(row.get("current_build_readiness_state") or "") == "COMPLETE"
        ),
        "active_cohort_apps_need_baseline": sum(
            1
            for row in active_cohort_readiness_rows
            if str(row.get("current_build_readiness_state") or "") in {"BASELINE_NEEDED", "NO_LOCAL_EVIDENCE"}
        ),
        "active_cohort_apps_need_interactive": sum(
            1 for row in active_cohort_readiness_rows if str(row.get("current_build_readiness_state") or "") == "INTERACTIVE_NEEDED"
        ),
        "active_cohort_apps_no_local_evidence": sum(
            1 for row in active_cohort_readiness_rows if str(row.get("current_build_readiness_state") or "") == "NO_LOCAL_EVIDENCE"
        ),
        "current_build_countable_runs_scanned": sum(
            int(row.get("current_build_countable_runs") or 0) for row in current_build_rollup_rows
        ),
        "current_build_valid_runs_scanned": sum(
            int(row.get("current_build_valid_runs") or 0) for row in current_build_rollup_rows
        ),
        "historical_valid_runs_scanned": sum(
            int(row.get("historical_valid_runs") or 0) for row in current_build_rollup_rows
        ),
        "runs_with_domain_observations_db": sum(1 for row in ledger_rows if row["domain_observations_in_db"] == 1),
        "runs_missing_domain_observations_db": len(missing_domain_rows),
        "runs_missing_domain_observations_invalid_rows": len(invalid_missing_rows),
        "runs_missing_domain_observations_index_lag_rows": len(index_lag_rows),
        "runs_missing_domain_observations_invalid_pcap": invalid_pcap_missing,
        "runs_missing_domain_observations_invalid_pcap_by_raw_detail": invalid_pcap_by_raw_detail,
        "runs_missing_domain_observations_invalid_other": invalid_other_missing,
        "runs_missing_domain_observations_index_lag": index_lag_missing,
        "x_twitter_runs": len(x_rows_sorted),
        "x_twitter_idle_runs": sum(1 for row in x_rows_sorted if row["mode"] == "idle"),
        "x_twitter_interactive_runs": sum(1 for row in x_rows_sorted if row["mode"] == "interactive"),
        "x_twitter_valid_runs": sum(1 for row in x_rows_sorted if row["valid_dataset_run"] == 1),
        "proposed_domain_backfill_command": "PYTHONPATH=. python scripts/db/backfill_dynamic_domain_context.py --apply --json",
        "output_files": {
            "dynamic_run_ledger_csv": str((output_root / "dynamic_run_ledger.csv").resolve()),
            "dynamic_run_summary_json": str((output_root / "dynamic_run_summary.json").resolve()),
            "app_coverage_table_csv": str((output_root / "app_coverage_table.csv").resolve()),
            "app_current_build_governance_csv": str((output_root / "app_current_build_governance.csv").resolve()),
            "active_cohort_current_build_readiness_csv": str((output_root / "active_cohort_current_build_readiness.csv").resolve()),
            "x_twitter_run_table_csv": str((output_root / "x_twitter_run_table.csv").resolve()),
            "x_twitter_rdi_summary_csv": str((output_root / "x_twitter_rdi_summary.csv").resolve()),
            "missing_domain_observation_runs_csv": str((output_root / "missing_domain_observation_runs.csv").resolve()),
            "invalid_domain_observation_runs_csv": str((output_root / "invalid_domain_observation_runs.csv").resolve()),
            "domain_index_lag_runs_csv": str((output_root / "domain_index_lag_runs.csv").resolve()),
            "service_signal_coverage_csv": str((output_root / "service_signal_coverage.csv").resolve()),
            "draft_results_bullets_md": str((output_root / "draft_results_bullets.md").resolve()),
            "draft_results_paragraphs_md": str((output_root / "draft_results_paragraphs.md").resolve()),
        },
        "no_db_writes": True,
    }

    _write_csv(output_root / "dynamic_run_ledger.csv", ledger_rows)
    _write_csv(output_root / "app_coverage_table.csv", app_rows)
    _write_csv(output_root / "app_current_build_governance.csv", current_build_rollup_rows)
    _write_csv(output_root / "active_cohort_current_build_readiness.csv", active_cohort_readiness_rows)
    _write_csv(output_root / "x_twitter_run_table.csv", x_rows_sorted)
    _write_csv(output_root / "x_twitter_rdi_summary.csv", [rdi_summary])
    _write_csv(output_root / "missing_domain_observation_runs.csv", missing_domain_rows)
    _write_csv(output_root / "invalid_domain_observation_runs.csv", invalid_missing_rows)
    _write_csv(output_root / "domain_index_lag_runs.csv", index_lag_rows)
    _write_csv(output_root / "service_signal_coverage.csv", service_signal_rows)
    (output_root / "draft_results_bullets.md").write_text(
        _draft_bullets(summary, x_rows_sorted, rdi_summary) + "\n",
        encoding="utf-8",
    )
    (output_root / "draft_results_paragraphs.md").write_text(
        _draft_paragraphs(summary, x_rows_sorted, rdi_summary) + "\n",
        encoding="utf-8",
    )
    (output_root / "dynamic_run_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    summary = generate_report(output_dir=output_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
