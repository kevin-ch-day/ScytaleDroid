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


def _load_dynamic_sessions() -> dict[str, dict[str, Any]]:
    try:
        from scytaledroid.Database.db_core import db_queries as core_q

        rows = core_q.run_sql(
            """
            SELECT
              dynamic_run_id,
              package_name,
              device_serial,
              base_apk_sha256,
              artifact_set_hash,
              status,
              valid_dataset_run,
              invalid_reason_code,
              countable,
              pcap_relpath,
              pcap_bytes,
              pcap_valid,
              operator_run_profile,
              duration_seconds,
              version_name,
              version_code,
              evidence_path
            FROM dynamic_sessions
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
        f"- Countable runs in the current evidence corpus: {summary['countable_runs_scanned']}.",
        f"- Apps seen in the current evidence corpus: {summary['apps_seen']}.",
        f"- Runs with PCAP artifacts present: {summary['runs_with_pcap']}.",
        f"- Runs with `pcap_report.json`: {summary['runs_with_pcap_report']}.",
        f"- Runs with `pcap_features.json`: {summary['runs_with_pcap_features']}.",
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

    x_total = len(x_rows)
    x_valid = sum(1 for row in x_rows if int(row.get("valid_dataset_run") or 0) == 1)
    x_indexed = sum(1 for row in x_rows if int(row.get("domain_observations_in_db") or 0) == 1)
    x_idle = sum(1 for row in x_rows if row.get("mode") == "idle")
    x_interactive = sum(1 for row in x_rows if row.get("mode") == "interactive")

    paragraphs = [
        (
            f"The current dynamic corpus contains {total_runs} evidence packs across {apps_seen} apps, "
            f"with {valid_runs} runs presently classified as valid dataset evidence and {countable_runs} runs "
            f"counted toward the cohort protocol. PCAP-derived reports are present for "
            f"{int(summary.get('runs_with_pcap_report') or 0)} runs and feature exports are present for "
            f"{int(summary.get('runs_with_pcap_features') or 0)} runs."
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
        valid_dataset_run = _normalize_boolish(session_row.get("valid_dataset_run"))
        if valid_dataset_run is None:
            valid_dataset_run = _normalize_boolish(dataset.get("valid_dataset_run"))
        countable = _normalize_boolish(session_row.get("countable"))
        if countable is None:
            countable = _normalize_boolish(dataset.get("countable"))
        invalid_reason = _norm_text(session_row.get("invalid_reason_code")) or _norm_text(dataset.get("invalid_reason_code"))
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
            "base_apk_sha256": _norm_text(session_row.get("base_apk_sha256")) or _norm_text((manifest.get("run_identity") or {}).get("base_apk_sha256")),
            "artifact_set_hash": _norm_text(session_row.get("artifact_set_hash")) or _norm_text((manifest.get("run_identity") or {}).get("artifact_set_hash")),
            "mode": mode,
            "interaction_label": interaction_label,
            "run_profile": run_profile,
            "status": _norm_text(session_row.get("status")) or _norm_text(manifest.get("status")) or "unknown",
            "valid_dataset_run": 1 if valid_dataset_run is True else 0 if valid_dataset_run is False else "",
            "invalid_reason_code": invalid_reason,
            "countable": 1 if countable is True else 0 if countable is False else "",
            "pcap_relpath": pcap_relpath,
            "pcap_exists": int(pcap_exists),
            "pcap_bytes": pcap_bytes or 0,
            "pcap_report_exists": int((run_dir / "analysis" / "pcap_report.json").exists()),
            "pcap_features_exists": int((run_dir / "analysis" / "pcap_features.json").exists()),
            "window_scores_exists": int(window_scores is not None),
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

    rdi_summary = {
        **X_TWITTER_ANCHOR,
        "current_rdi_available": False,
        "current_mu_idle_rdi": "",
        "current_mu_interactive_rdi": "",
        "current_delta_rdi": "",
        "current_source": "",
        "note": "No current profile-v3 manifest or per-run ML window score export is available for present X/Twitter runs.",
    }

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
        "runs_with_pcap": sum(1 for row in ledger_rows if row["pcap_exists"] == 1),
        "runs_with_pcap_report": sum(1 for row in ledger_rows if row["pcap_report_exists"] == 1),
        "runs_with_pcap_features": sum(1 for row in ledger_rows if row["pcap_features_exists"] == 1),
        "runs_with_window_scores": sum(1 for row in ledger_rows if row["window_scores_exists"] == 1),
        "runs_with_domain_observations_db": sum(1 for row in ledger_rows if row["domain_observations_in_db"] == 1),
        "runs_missing_domain_observations_db": len(missing_domain_rows),
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
            "x_twitter_run_table_csv": str((output_root / "x_twitter_run_table.csv").resolve()),
            "x_twitter_rdi_summary_csv": str((output_root / "x_twitter_rdi_summary.csv").resolve()),
            "missing_domain_observation_runs_csv": str((output_root / "missing_domain_observation_runs.csv").resolve()),
            "service_signal_coverage_csv": str((output_root / "service_signal_coverage.csv").resolve()),
            "draft_results_bullets_md": str((output_root / "draft_results_bullets.md").resolve()),
            "draft_results_paragraphs_md": str((output_root / "draft_results_paragraphs.md").resolve()),
        },
        "no_db_writes": True,
    }

    _write_csv(output_root / "dynamic_run_ledger.csv", ledger_rows)
    _write_csv(output_root / "app_coverage_table.csv", app_rows)
    _write_csv(output_root / "x_twitter_run_table.csv", x_rows_sorted)
    _write_csv(output_root / "x_twitter_rdi_summary.csv", [rdi_summary])
    _write_csv(output_root / "missing_domain_observation_runs.csv", missing_domain_rows)
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
