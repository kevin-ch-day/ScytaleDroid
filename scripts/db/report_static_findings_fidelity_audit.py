#!/usr/bin/env python3
"""Read-only audit of static findings fidelity for one session.

Builds an artifact-first audit bundle that compares runtime finding totals from
run-health / archived static reports against canonical DB finding persistence.
The goal is to make finding-cap behavior explicit without changing detector or
DB behavior.

Examples:

  PYTHONPATH=. python scripts/db/report_static_findings_fidelity_audit.py --session 20260613-all-full
  PYTHONPATH=. python scripts/db/report_static_findings_fidelity_audit.py --session 20260613-all-full --verbose
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

OUTPUT_FILES: tuple[str, ...] = (
    "summary.json",
    "finding_fidelity_by_package.csv",
    "finding_fidelity_by_detector.csv",
    "finding_fidelity_by_severity.csv",
    "finding_fidelity_by_artifact_grain.csv",
    "capped_findings_examples.csv",
    "db_consumer_fidelity_gaps.csv",
    "recommended_next_action.json",
)

SEVERITY_ORDER: tuple[str, ...] = ("P0", "P1", "P2", "HIGH", "MEDIUM", "LOW", "INFO", "NOTE", "UNKNOWN")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--session",
        "--session-stamp",
        dest="session_stamp",
        default=None,
        help="Static session stamp. Defaults to the newest static run-health file.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Write outputs to this directory instead of output/audit/static_findings_fidelity/<stamp>/.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print compact progress to stderr.",
    )
    return parser


def _log(verbose: bool, message: str) -> None:
    if verbose:
        sys.stderr.write(f"{message}\n")


def _norm_text(value: Any) -> str:
    return str(value or "").strip()


def _norm_text_or_none(value: Any) -> str | None:
    text = _norm_text(value)
    return text or None


def _package_key(value: Any) -> str | None:
    text = _norm_text_or_none(value)
    return text.lower() if text else None


def _safe_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    row_list = list(rows)
    if not row_list:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    for row in row_list:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in row_list:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _repo_rel(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(_REPO_ROOT.resolve()))
    except Exception:
        return str(path)


def _run_health_dir(data_dir: Path) -> Path:
    return data_dir / "store" / "apk"


def _reports_archive_root(data_dir: Path) -> Path:
    return data_dir / "static_analysis" / "reports" / "archive"


def _latest_run_health_session(data_dir: Path) -> str | None:
    candidates = sorted(_run_health_dir(data_dir).glob("*_run_health.json"))
    if not candidates:
        return None
    latest = max(candidates, key=lambda p: (p.stat().st_mtime, p.name))
    return latest.name.removesuffix("_run_health.json")


def _resolve_session_stamp(data_dir: Path, requested: str | None) -> str | None:
    token = _norm_text_or_none(requested)
    if token:
        return token
    return _latest_run_health_session(data_dir)


def _report_generated_at(payload: Mapping[str, Any]) -> str:
    return _norm_text(payload.get("generated_at") or payload.get("generated_at_utc"))


def _coerce_severity_label(value: Any) -> str:
    text = _norm_text(value).upper()
    return text or "UNKNOWN"


def _severity_counts_from_report(payload: Mapping[str, Any]) -> Counter[str]:
    metadata = payload.get("metadata")
    metadata_map = metadata if isinstance(metadata, Mapping) else {}
    pipeline_summary = metadata_map.get("pipeline_summary")
    summary_map = pipeline_summary if isinstance(pipeline_summary, Mapping) else {}
    severity_counts = summary_map.get("severity_counts")
    counter: Counter[str] = Counter()
    if isinstance(severity_counts, Mapping):
        for key, value in severity_counts.items():
            sev = _coerce_severity_label(key)
            count = _safe_int(value) or 0
            if count > 0:
                counter[sev] += count
    if counter:
        return counter
    for finding in payload.get("findings") or []:
        if not isinstance(finding, Mapping):
            continue
        severity_gate = finding.get("severity_gate")
        gate_value = severity_gate.get("value") if isinstance(severity_gate, Mapping) else None
        sev = _coerce_severity_label(gate_value or finding.get("severity") or finding.get("severity_raw"))
        counter[sev] += 1
    return counter


def _report_per_finding_flags(payload: Mapping[str, Any]) -> bool:
    for finding in payload.get("findings") or []:
        if not isinstance(finding, Mapping):
            continue
        if "persisted" in finding or "capped" in finding:
            return True
    return False


def _report_fidelity_metadata(payload: Mapping[str, Any]) -> Mapping[str, Any] | None:
    metadata = payload.get("metadata")
    metadata_map = metadata if isinstance(metadata, Mapping) else {}
    fidelity = metadata_map.get("findings_fidelity")
    return fidelity if isinstance(fidelity, Mapping) else None


def _report_example_finding(payload: Mapping[str, Any]) -> tuple[str | None, str | None]:
    for finding in payload.get("findings") or []:
        if not isinstance(finding, Mapping):
            continue
        title = _norm_text_or_none(finding.get("title") or finding.get("finding_id"))
        evidence = finding.get("evidence")
        if isinstance(evidence, list) and evidence:
            first = evidence[0]
            if isinstance(first, Mapping):
                description = _norm_text_or_none(first.get("description"))
                if description:
                    return title, description
        return title, None
    return None, None


def _load_archive_reports(
    archive_dir: Path,
) -> tuple[dict[str, dict[str, Any]], Counter[str], dict[str, Any], list[str]]:
    package_index: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    session_runtime_severity: Counter[str] = Counter()
    archive_stats: dict[str, Any] = {
        "reports_with_fidelity_metadata": 0,
        "reports_missing_fidelity_metadata": 0,
        "metadata_grain_distribution": Counter(),
        "per_finding_persisted_flags_available": False,
    }

    for path in sorted(archive_dir.glob("*.json")):
        payload = _read_json(path)
        if not isinstance(payload, Mapping):
            warnings.append(f"invalid_report_json:{_repo_rel(path)}")
            continue
        fidelity_metadata = _report_fidelity_metadata(payload)
        if fidelity_metadata is not None:
            archive_stats["reports_with_fidelity_metadata"] += 1
            grain = _norm_text_or_none(fidelity_metadata.get("cap_metadata_grain")) or "unknown"
            cast_counter = archive_stats["metadata_grain_distribution"]
            if isinstance(cast_counter, Counter):
                cast_counter[grain] += 1
            if bool(fidelity_metadata.get("per_finding_persistence_status_available")):
                archive_stats["per_finding_persisted_flags_available"] = True
        else:
            archive_stats["reports_missing_fidelity_metadata"] += 1
        manifest = payload.get("manifest")
        manifest_map = manifest if isinstance(manifest, Mapping) else {}
        metadata = payload.get("metadata")
        metadata_map = metadata if isinstance(metadata, Mapping) else {}
        package_name = _package_key(
            manifest_map.get("package_name")
            or metadata_map.get("package_name")
            or metadata_map.get("normalized_package_name")
        )
        if not package_name:
            warnings.append(f"report_missing_package_name:{_repo_rel(path)}")
            continue
        display_name = _norm_text_or_none(
            metadata_map.get("app_label")
            or manifest_map.get("app_label")
            or package_name
        )
        is_split = bool(metadata_map.get("is_split_member"))
        bucket = package_index.setdefault(
            package_name,
            {
                "display_name": display_name,
                "artifact_count": 0,
                "base_artifact_count": 0,
                "split_artifact_count": 0,
                "report_paths": [],
                "base_reports": [],
                "split_reports": [],
                "report_examples": [],
            },
        )
        bucket["artifact_count"] += 1
        if is_split:
            bucket["split_artifact_count"] += 1
            bucket["split_reports"].append(path)
        else:
            bucket["base_artifact_count"] += 1
            bucket["base_reports"].append(path)
        bucket["report_paths"].append(path)
        ex_title, ex_key = _report_example_finding(payload)
        if ex_title or ex_key:
            bucket["report_examples"].append(
                {
                    "title": ex_title,
                    "component_or_evidence_key": ex_key,
                    "report_path": _repo_rel(path),
                }
            )

    for bucket in package_index.values():
        base_reports: list[Path] = list(bucket.get("base_reports") or [])
        if not base_reports:
            continue
        payloads: list[tuple[str, dict[str, Any], Path]] = []
        for path in base_reports:
            payload = _read_json(path)
            if isinstance(payload, Mapping):
                payloads.append((_report_generated_at(payload), payload, path))
        if not payloads:
            continue
        payloads.sort(key=lambda item: (item[0], str(item[2])), reverse=True)
        _, base_payload, base_path = payloads[0]
        severity_counts = _severity_counts_from_report(base_payload)
        session_runtime_severity.update(severity_counts)
        bucket["base_report_path"] = base_path
        bucket["base_runtime_severity_counts"] = dict(severity_counts)
        bucket["base_runtime_findings_total"] = int(sum(severity_counts.values()))
        base_fidelity = _report_fidelity_metadata(base_payload)
        bucket["report_level_fidelity_metadata_available"] = base_fidelity is not None
        bucket["cap_metadata_grain"] = (
            _norm_text_or_none(base_fidelity.get("cap_metadata_grain")) if isinstance(base_fidelity, Mapping) else None
        )
        bucket["per_finding_persisted_flags_available"] = bool(
            _report_per_finding_flags(base_payload)
            or (
                isinstance(base_fidelity, Mapping)
                and bool(base_fidelity.get("per_finding_persistence_status_available"))
            )
        )

    return package_index, session_runtime_severity, archive_stats, warnings


def _load_run_health(data_dir: Path, session_stamp: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[str]]:
    warnings: list[str] = []
    path = _run_health_dir(data_dir) / f"{session_stamp}_run_health.json"
    payload = _read_json(path)
    if not isinstance(payload, Mapping):
        warnings.append(f"run_health_missing:{_repo_rel(path)}")
        return {}, {}, warnings

    package_rows: dict[str, dict[str, Any]] = {}
    for app in payload.get("apps") or []:
        if not isinstance(app, Mapping):
            continue
        package_name = _package_key(app.get("package_name"))
        if not package_name:
            continue
        finding_persistence = app.get("finding_persistence")
        persistence_map = finding_persistence if isinstance(finding_persistence, Mapping) else {}
        package_rows[package_name] = {
            "display_name": _norm_text_or_none(app.get("app_label") or app.get("package_name")),
            "runtime_findings": _safe_int(persistence_map.get("runtime_findings")),
            "persisted_findings_db": _safe_int(persistence_map.get("persisted_findings_db")),
            "capped_not_persisted": _safe_int(persistence_map.get("capped_not_persisted")),
            "capped_by_detector": {
                str(k): int(v or 0)
                for k, v in (persistence_map.get("capped_by_detector") or {}).items()
            }
            if isinstance(persistence_map.get("capped_by_detector"), Mapping)
            else {},
            "artifact_count": _safe_int(app.get("discovered_artifacts")),
            "final_status": _norm_text_or_none(app.get("final_status")),
            "report_paths_short": list(app.get("report_paths_short") or []),
        }
    return dict(payload), package_rows, warnings


def _table_exists(core_q: Any, name: str) -> bool:
    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS c
        FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = %s
        """,
        (name,),
        fetch="one",
        dictionary=True,
        query_name="report_static_findings_fidelity.table_exists",
    )
    return int((row or {}).get("c") or 0) > 0


def _view_exists(core_q: Any, name: str) -> bool:
    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS c
        FROM information_schema.views
        WHERE table_schema = DATABASE() AND table_name = %s
        """,
        (name,),
        fetch="one",
        dictionary=True,
        query_name="report_static_findings_fidelity.view_exists",
    )
    return int((row or {}).get("c") or 0) > 0


def _load_optional_db(session_stamp: str) -> tuple[dict[str, Any], list[str]]:
    notes: list[str] = []
    state: dict[str, Any] = {
        "db_name": None,
        "run_rows": {},
        "package_persisted_by_severity": defaultdict(Counter),
        "detector_persisted_totals": Counter(),
        "detector_persisted_p0": Counter(),
        "detector_packages": defaultdict(set),
        "surface_presence": {},
    }
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:  # noqa: BLE001
        notes.append(f"db_unavailable:import_failed:{type(exc).__name__}")
        return state, notes

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        notes.append("db_unavailable:engine_disabled")
        return state, notes

    try:
        db_row = core_q.run_sql(
            "SELECT DATABASE() AS dbname",
            fetch="one",
            dictionary=True,
            query_name="report_static_findings_fidelity.db_name",
        )
        state["db_name"] = _norm_text_or_none((db_row or {}).get("dbname"))
    except Exception as exc:  # noqa: BLE001
        notes.append(f"db_unavailable:connect_failed:{type(exc).__name__}")
        return state, notes

    state["surface_presence"] = {
        "static_analysis_runs": _table_exists(core_q, "static_analysis_runs"),
        "static_analysis_findings": _table_exists(core_q, "static_analysis_findings"),
        "vw_static_finding_surfaces_latest": _view_exists(core_q, "vw_static_finding_surfaces_latest"),
        "v_static_handoff_v1": _view_exists(core_q, "v_static_handoff_v1"),
        "v_static_masvs_matrix_v1": _view_exists(core_q, "v_static_masvs_matrix_v1"),
    }

    if not state["surface_presence"]["static_analysis_runs"]:
        notes.append("db_unavailable:static_analysis_runs_missing")
        return state, notes

    try:
        rows = core_q.run_sql(
            """
            SELECT
              sar.id AS static_run_id,
              a.package_name,
              COALESCE(NULLIF(a.display_name, ''), a.package_name) AS display_name,
              sar.findings_total AS persisted_findings_db,
              sar.findings_runtime_total,
              sar.findings_capped_total,
              sar.findings_capped_by_detector_json
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE sar.session_stamp = %s
            """,
            (session_stamp,),
            fetch="all",
            dictionary=True,
            query_name="report_static_findings_fidelity.run_rows",
        ) or []
        run_rows: dict[str, Any] = {}
        for row in rows:
            package_name = _package_key(row.get("package_name"))
            if not package_name:
                continue
            run_rows[package_name] = dict(row)
        state["run_rows"] = run_rows
    except Exception as exc:  # noqa: BLE001
        notes.append(f"db_warning:run_rows_query_failed:{type(exc).__name__}")

    if not state["surface_presence"]["static_analysis_findings"]:
        notes.append("db_unavailable:static_analysis_findings_missing")
        return state, notes

    try:
        rows = core_q.run_sql(
            """
            SELECT
              a.package_name,
              COALESCE(saf.detector, 'unknown') AS detector_name,
              UPPER(COALESCE(NULLIF(saf.severity_raw, ''), NULLIF(saf.severity, ''), 'UNKNOWN')) AS severity_raw,
              COUNT(*) AS finding_count
            FROM static_analysis_findings saf
            JOIN static_analysis_runs sar ON sar.id = saf.run_id
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            WHERE sar.session_stamp = %s
            GROUP BY a.package_name, detector_name, severity_raw
            """,
            (session_stamp,),
            fetch="all",
            dictionary=True,
            query_name="report_static_findings_fidelity.findings_by_detector_severity",
        ) or []
        package_persisted_by_severity: dict[str, Counter[str]] = defaultdict(Counter)
        detector_persisted_totals: Counter[str] = Counter()
        detector_persisted_p0: Counter[str] = Counter()
        detector_packages: dict[str, set[str]] = defaultdict(set)
        for row in rows:
            package_name = _package_key(row.get("package_name"))
            detector_name = _norm_text_or_none(row.get("detector_name")) or "unknown"
            severity_raw = _coerce_severity_label(row.get("severity_raw"))
            count = _safe_int(row.get("finding_count")) or 0
            if not package_name or count <= 0:
                continue
            package_persisted_by_severity[package_name][severity_raw] += count
            detector_persisted_totals[detector_name] += count
            detector_packages[detector_name].add(package_name)
            if severity_raw == "P0":
                detector_persisted_p0[detector_name] += count
        state["package_persisted_by_severity"] = package_persisted_by_severity
        state["detector_persisted_totals"] = detector_persisted_totals
        state["detector_persisted_p0"] = detector_persisted_p0
        state["detector_packages"] = detector_packages
    except Exception as exc:  # noqa: BLE001
        notes.append(f"db_warning:findings_query_failed:{type(exc).__name__}")

    return state, notes


def _format_counter(counter: Mapping[str, int] | Counter[str], *, topn: int = 5) -> str:
    ranked = sorted(
        ((str(key), int(value)) for key, value in counter.items() if int(value) > 0),
        key=lambda item: (-item[1], item[0]),
    )
    if not ranked:
        return ""
    return ", ".join(f"{key}:{value}" for key, value in ranked[:topn])


def _fidelity_status(runtime_findings: int | None, capped_not_persisted: int | None) -> str:
    runtime = int(runtime_findings or 0)
    capped = int(capped_not_persisted or 0)
    if runtime <= 0:
        return "unknown"
    if capped <= 0:
        return "complete"
    ratio = capped / runtime
    if ratio <= 0.10:
        return "capped_low"
    if ratio <= 0.40:
        return "capped_medium"
    return "capped_high"


def _consumer_gap_rows(surface_presence: Mapping[str, Any]) -> list[dict[str, Any]]:
    def _row(
        *,
        surface: str,
        file_or_view: str,
        uses_persisted_findings: int,
        shows_runtime_findings: int,
        shows_capped_not_persisted: int,
        gap: str,
        recommended_fix: str,
    ) -> dict[str, Any]:
        return {
            "surface": surface,
            "file_or_view": file_or_view,
            "uses_persisted_findings": uses_persisted_findings,
            "shows_runtime_findings": shows_runtime_findings,
            "shows_capped_not_persisted": shows_capped_not_persisted,
            "gap": gap,
            "recommended_fix": recommended_fix,
        }

    return [
        _row(
            surface="Canonical run table",
            file_or_view="static_analysis_runs",
            uses_persisted_findings=1,
            shows_runtime_findings=1,
            shows_capped_not_persisted=1,
            gap="visible_if_rendered",
            recommended_fix="Ensure session/report consumers render runtime_vs_persisted_vs_capped counters.",
        ),
        _row(
            surface="Latest finding surfaces view",
            file_or_view="vw_static_finding_surfaces_latest",
            uses_persisted_findings=1,
            shows_runtime_findings=1,
            shows_capped_not_persisted=1,
            gap="visible_if_rendered",
            recommended_fix="Prefer this surface over plain canonical finding counts when fidelity matters.",
        ),
        _row(
            surface="Static handoff view",
            file_or_view="v_static_handoff_v1",
            uses_persisted_findings=0,
            shows_runtime_findings=0,
            shows_capped_not_persisted=0,
            gap="no_fidelity_fields",
            recommended_fix="Document that handoff readiness does not imply full finding fidelity visibility.",
        ),
        _row(
            surface="MASVS matrix view",
            file_or_view="v_static_masvs_matrix_v1",
            uses_persisted_findings=1,
            shows_runtime_findings=0,
            shows_capped_not_persisted=0,
            gap="hidden_canonical_only",
            recommended_fix="Surface a fidelity warning when MASVS summaries are interpreted as complete runtime findings.",
        ),
        _row(
            surface="Static exposure analytics",
            file_or_view="scripts/db/report_static_exposure_analytics.py",
            uses_persisted_findings=1,
            shows_runtime_findings=0,
            shows_capped_not_persisted=0,
            gap="hidden_canonical_only",
            recommended_fix="Add a fidelity disclaimer or join run-level capped counters into analytics outputs.",
        ),
        _row(
            surface="Archive report lookup API",
            file_or_view="scytaledroid/Api/service.py",
            uses_persisted_findings=0,
            shows_runtime_findings=1,
            shows_capped_not_persisted=0,
            gap="runtime_visible_cap_hidden",
            recommended_fix="Add report-level cap metadata so archive-backed consumers can tell when DB fidelity diverges.",
        ),
    ]


def _recommendation_payload(
    *,
    capped_ratio: float | None,
    top_capped_detector: str | None,
    p0_capped_known: bool,
    p0_capped_total: int | None,
    per_report_cap_metadata_available: bool,
    per_finding_persisted_flags_available: bool,
    db_consumer_warning_required: bool,
    fidelity_audit_should_be_standard: bool,
) -> dict[str, Any]:
    secondary_actions: list[str] = []
    rationale: list[str] = []

    if not per_report_cap_metadata_available:
        recommended_action = "add_per_report_cap_metadata"
        rationale.append("Archived report JSON preserves runtime findings but does not mark persisted vs capped rows.")
    elif db_consumer_warning_required:
        recommended_action = "add_db_summary_counts_for_capped_findings"
        rationale.append("Some DB/view consumers can use canonical findings without clearly surfacing the fidelity gap.")
    else:
        recommended_action = "surface_fidelity_gap_only"
        rationale.append("The main need is visibility, not an immediate cap-policy change.")

    if fidelity_audit_should_be_standard:
        secondary_actions.append("add_static_findings_fidelity_audit_to_standard_post_run_checks")
    if top_capped_detector and top_capped_detector == "ipc_components":
        secondary_actions.append("investigate_ipc_components_noise")
        rationale.append("Capped rows are concentrated in ipc_components, which is a strong candidate for targeted tuning.")
    if not p0_capped_known or (p0_capped_total or 0) > 0:
        secondary_actions.append("make_cap_policy_severity_aware")
        rationale.append("Cap policy is not severity-aware, so high-severity protection is not guaranteed by design.")
    if (capped_ratio or 0.0) >= 0.20:
        secondary_actions.append("preserve_capped_findings_as_artifact_index")
        rationale.append("The capped ratio is large enough that research consumers need explicit alternate evidence access.")

    return {
        "recommended_action": recommended_action,
        "secondary_actions": secondary_actions,
        "rationale": rationale,
        "p0_capped_status": "known" if p0_capped_known else "unknown",
        "no_db_writes": True,
        "experimental_audit": True,
    }


def _best_display_name(*values: object) -> str | None:
    for value in values:
        text = _norm_text_or_none(value)
        if text:
            return text
    return None


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    data_dir = _REPO_ROOT / "data"
    output_root = _REPO_ROOT / "output"
    session_stamp = _resolve_session_stamp(data_dir, args.session_stamp)
    if not session_stamp:
        sys.stderr.write("No static session could be resolved from data/store/apk or the requested --session.\n")
        return 1

    archive_dir = _reports_archive_root(data_dir) / session_stamp
    if not archive_dir.exists():
        sys.stderr.write(f"Static reports archive missing for session {session_stamp}: {archive_dir}\n")
        return 1

    run_health, run_health_packages, run_health_warnings = _load_run_health(data_dir, session_stamp)
    report_index, runtime_severity_counter, archive_report_stats, report_warnings = _load_archive_reports(archive_dir)
    db_state, db_notes = _load_optional_db(session_stamp)

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    audit_output_dir = Path(args.output_dir) if args.output_dir else output_root / "audit" / "static_findings_fidelity" / stamp
    audit_output_dir.mkdir(parents=True, exist_ok=True)

    package_names = set(run_health_packages) | set(report_index) | set(db_state.get("run_rows", {}))

    db_package_severity: Mapping[str, Counter[str]] = db_state.get("package_persisted_by_severity", {})
    detector_persisted_totals: Counter[str] = db_state.get("detector_persisted_totals", Counter())
    detector_persisted_p0: Counter[str] = db_state.get("detector_persisted_p0", Counter())
    detector_packages_db: Mapping[str, set[str]] = db_state.get("detector_packages", {})
    run_rows_db: Mapping[str, Any] = db_state.get("run_rows", {})

    package_rows: list[dict[str, Any]] = []
    detector_capped_totals: Counter[str] = Counter()
    detector_packages_capped: dict[str, set[str]] = defaultdict(set)
    runtime_package_p0_total = 0
    persisted_package_p0_total = 0
    unknown_p0_packages = 0
    total_artifacts_for_capped_packages = 0

    for package_name in sorted(package_names):
        rh = run_health_packages.get(package_name, {})
        rep = report_index.get(package_name, {})
        db_row = run_rows_db.get(package_name, {})
        runtime_findings = _safe_int(rh.get("runtime_findings"))
        if runtime_findings is None:
            runtime_findings = _safe_int(rep.get("base_runtime_findings_total"))
        persisted_findings = _safe_int(rh.get("persisted_findings_db"))
        if persisted_findings is None:
            persisted_findings = _safe_int(db_row.get("persisted_findings_db"))
        capped_not_persisted = _safe_int(rh.get("capped_not_persisted"))
        if capped_not_persisted is None and runtime_findings is not None and persisted_findings is not None:
            capped_not_persisted = max(runtime_findings - persisted_findings, 0)
        runtime_severity_counts = Counter(rep.get("base_runtime_severity_counts") or {})
        persisted_severity_counts = Counter(db_package_severity.get(package_name, Counter()))
        p0_runtime = int(runtime_severity_counts.get("P0", 0))
        p0_persisted = int(persisted_severity_counts.get("P0", 0)) if persisted_severity_counts else None
        p0_capped: int | None
        if p0_persisted is None:
            p0_capped = None
            if p0_runtime > 0:
                unknown_p0_packages += 1
        else:
            p0_capped = max(p0_runtime - p0_persisted, 0)
        runtime_package_p0_total += p0_runtime
        persisted_package_p0_total += int(p0_persisted or 0)

        artifact_count = _safe_int(rep.get("artifact_count"))
        if artifact_count is None:
            artifact_count = _safe_int(rh.get("artifact_count"))
        base_artifact_count = _safe_int(rep.get("base_artifact_count"))
        split_artifact_count = _safe_int(rep.get("split_artifact_count"))
        multi_artifact_package = int((artifact_count or 0) > 1)

        capped_by_detector = Counter(rh.get("capped_by_detector") or {})
        detector_capped_totals.update(capped_by_detector)
        for detector_name, count in capped_by_detector.items():
            if int(count or 0) > 0:
                detector_packages_capped[str(detector_name)].add(package_name)

        if int(capped_not_persisted or 0) > 0:
            total_artifacts_for_capped_packages += int(artifact_count or 0)

        notes: list[str] = []
        if int(capped_not_persisted or 0) > 0 and not rep.get("per_finding_persisted_flags_available"):
            notes.append("per_finding_capped_flags_absent_in_archive_report")
        if multi_artifact_package:
            notes.append("multi_artifact_package")
        if p0_capped is None and p0_runtime > 0:
            notes.append("p0_capped_status_unknown_without_db_or_per_finding_flags")

        capped_ratio = None
        if int(runtime_findings or 0) > 0:
            capped_ratio = round(int(capped_not_persisted or 0) / int(runtime_findings or 0), 6)

        package_rows.append(
            {
                "package_name": package_name,
                "display_name": _best_display_name(
                    rh.get("display_name"),
                    rep.get("display_name"),
                    db_row.get("display_name"),
                    package_name,
                ),
                "runtime_findings": runtime_findings,
                "persisted_db_findings": persisted_findings,
                "capped_not_persisted": capped_not_persisted,
                "capped_ratio": capped_ratio,
                "p0_runtime": p0_runtime,
                "p0_persisted": p0_persisted,
                "p0_capped": p0_capped,
                "artifact_count": artifact_count,
                "base_artifact_count": base_artifact_count,
                "split_artifact_count": split_artifact_count,
                "multi_artifact_package": multi_artifact_package,
                "top_capped_detectors": _format_counter(capped_by_detector, topn=3),
                "fidelity_status": _fidelity_status(runtime_findings, capped_not_persisted),
                "notes": "; ".join(notes) if notes else None,
            }
        )

    runtime_findings_total = _safe_int(((run_health.get("run_rollups") or {}) if isinstance(run_health.get("run_rollups"), Mapping) else {}).get("findings_runtime_total"))
    if runtime_findings_total is None:
        runtime_findings_total = sum(int(row.get("runtime_findings") or 0) for row in package_rows)
    persisted_db_findings_total = _safe_int(((run_health.get("run_rollups") or {}) if isinstance(run_health.get("run_rollups"), Mapping) else {}).get("findings_persisted_db_total"))
    if persisted_db_findings_total is None:
        persisted_db_findings_total = sum(int(row.get("persisted_db_findings") or 0) for row in package_rows)
    capped_not_persisted_total = _safe_int(((run_health.get("run_rollups") or {}) if isinstance(run_health.get("run_rollups"), Mapping) else {}).get("findings_capped_not_persisted_total"))
    if capped_not_persisted_total is None:
        capped_not_persisted_total = sum(int(row.get("capped_not_persisted") or 0) for row in package_rows)

    fidelity_ratio = round(persisted_db_findings_total / runtime_findings_total, 6) if runtime_findings_total else None
    capped_ratio = round(capped_not_persisted_total / runtime_findings_total, 6) if runtime_findings_total else None

    detector_rows: list[dict[str, Any]] = []
    detector_names = set(detector_persisted_totals) | set(detector_capped_totals)
    for detector_name in sorted(detector_names):
        persisted = int(detector_persisted_totals.get(detector_name, 0))
        capped = int(detector_capped_totals.get(detector_name, 0))
        runtime = persisted + capped
        packages_affected = len(set(detector_packages_db.get(detector_name, set())) | set(detector_packages_capped.get(detector_name, set())))
        artifacts_affected = sum(
            int(row.get("artifact_count") or 0)
            for row in package_rows
            if row.get("package_name") in (set(detector_packages_db.get(detector_name, set())) | set(detector_packages_capped.get(detector_name, set())))
        )
        detector_rows.append(
            {
                "detector_name": detector_name,
                "runtime_findings": runtime,
                "persisted_db_findings": persisted,
                "capped_not_persisted": capped,
                "capped_ratio": round(capped / runtime, 6) if runtime > 0 else None,
                "packages_affected": packages_affected,
                "artifacts_affected": artifacts_affected,
                "p0_runtime": None,
                "p0_persisted": int(detector_persisted_p0.get(detector_name, 0)) or 0,
                "p0_capped": None,
                "cap_policy_applies": int(capped > 0),
                "notes": (
                    "runtime_by_detector derived from canonical persisted rows plus run_health capped_by_detector; "
                    "runtime detector severity split unavailable from current artifact contract"
                ),
            }
        )
    detector_rows.sort(key=lambda row: (-int(row.get("capped_not_persisted") or 0), str(row.get("detector_name") or "")))

    package_runtime_severity: dict[str, Counter[str]] = {
        str(row["package_name"]): Counter(report_index.get(str(row["package_name"]), {}).get("base_runtime_severity_counts") or {})
        for row in package_rows
    }
    severity_names = set(runtime_severity_counter) | {
        str(sev)
        for counter in db_package_severity.values()
        for sev in counter.keys()
    }
    severity_rows: list[dict[str, Any]] = []
    for severity in sorted(severity_names, key=lambda sev: (SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER), sev)):
        runtime = int(runtime_severity_counter.get(severity, 0))
        persisted = sum(int(counter.get(severity, 0)) for counter in db_package_severity.values())
        capped = runtime - persisted if runtime >= persisted else None
        packages_affected = sum(
            1
            for package_name in package_names
            if int(package_runtime_severity.get(package_name, Counter()).get(severity, 0)) > 0
            or int(db_package_severity.get(package_name, Counter()).get(severity, 0)) > 0
        )
        notes = None
        if capped is None:
            notes = "persisted severity exceeds runtime artifact severity; inspect session/report mismatch"
        severity_rows.append(
            {
                "severity": severity,
                "runtime_findings": runtime,
                "persisted_db_findings": persisted,
                "capped_not_persisted": capped,
                "capped_ratio": round(capped / runtime, 6) if runtime > 0 and capped is not None else None,
                "packages_affected": packages_affected,
                "notes": notes,
            }
        )

    single_artifact_rows = [row for row in package_rows if int(row.get("artifact_count") or 0) == 1]
    multi_artifact_rows = [row for row in package_rows if int(row.get("artifact_count") or 0) > 1]
    unknown_artifact_rows = [row for row in package_rows if row.get("artifact_count") in (None, "")]

    def _grain_row(grain: str, rows: list[dict[str, Any]], note: str) -> dict[str, Any]:
        runtime = sum(int(row.get("runtime_findings") or 0) for row in rows)
        persisted = sum(int(row.get("persisted_db_findings") or 0) for row in rows)
        capped = sum(int(row.get("capped_not_persisted") or 0) for row in rows)
        return {
            "artifact_grain": grain,
            "runtime_findings": runtime,
            "persisted_db_findings": persisted,
            "capped_not_persisted": capped,
            "capped_ratio": round(capped / runtime, 6) if runtime > 0 else None,
            "artifact_count": sum(int(row.get("artifact_count") or 0) for row in rows),
            "packages_affected": len(rows),
            "notes": note,
        }

    artifact_grain_rows = [
        _grain_row(
            "base_apk",
            single_artifact_rows,
            "Single-artifact packages only; package-level fidelity is effectively base-APK scoped.",
        ),
        _grain_row(
            "split_apk",
            multi_artifact_rows,
            "Multi-artifact packages; capped counts are package-level and split influence is inferred, not per-split proven.",
        ),
        _grain_row(
            "package_rollup",
            package_rows,
            "Canonical persistence fidelity surface from run_health / static_analysis_runs.",
        ),
        _grain_row(
            "unknown",
            unknown_artifact_rows,
            "Packages missing artifact-count context from reports/run_health.",
        ),
    ]

    example_rows: list[dict[str, Any]] = []
    for row in sorted(package_rows, key=lambda item: (-int(item.get("capped_not_persisted") or 0), str(item.get("package_name") or ""))):
        if int(row.get("capped_not_persisted") or 0) <= 0:
            continue
        package_name = _package_key(row.get("package_name")) or ""
        rep = report_index.get(package_name, {})
        examples = rep.get("report_examples") or []
        example = examples[0] if examples else {}
        detectors = str(row.get("top_capped_detectors") or "")
        detector_name = detectors.split(",", 1)[0].split(":", 1)[0].strip() if detectors else None
        base_path = rep.get("base_report_path")
        base_hash = Path(base_path).stem if isinstance(base_path, Path) else None
        example_rows.append(
            {
                "package_name": package_name,
                "display_name": row.get("display_name"),
                "detector_name": detector_name,
                "severity": None,
                "finding_title": example.get("title"),
                "component_or_evidence_key": example.get("component_or_evidence_key"),
                "artifact_path_or_hash": base_hash,
                "artifact_grain": "split_apk" if int(row.get("multi_artifact_package") or 0) else "base_apk",
                "reason_capped": "per_detector_cap",
                "would_have_persisted_rank_if_available": None,
                "source_report_path": _repo_rel(base_path) if isinstance(base_path, Path) else None,
            }
        )
        if len(example_rows) >= 25:
            break

    consumer_gap_rows = _consumer_gap_rows(db_state.get("surface_presence", {}))
    db_consumer_warning_required = any(
        int(row.get("uses_persisted_findings") or 0) == 1
        and int(row.get("shows_capped_not_persisted") or 0) == 0
        for row in consumer_gap_rows
    )

    p0_runtime_findings = int(runtime_severity_counter.get("P0", 0))
    p0_persisted_findings = sum(int(counter.get("P0", 0)) for counter in db_package_severity.values()) if db_package_severity else None
    p0_capped_not_persisted = (
        max(p0_runtime_findings - int(p0_persisted_findings or 0), 0)
        if p0_persisted_findings is not None
        else None
    )
    p0_capped_known = p0_persisted_findings is not None

    warnings = list(run_health_warnings) + list(report_warnings) + list(db_notes)
    assumptions = [
        "run_health.json is the package/session source of truth for runtime_vs_persisted_vs_capped counters",
        "archived base reports provide runtime severity structure but not per-finding persisted/capped flags",
        "static_analysis_findings severity_raw is used as the persisted-side severity source when DB is available",
        "multi-artifact package cap attribution is package-level; split influence is inferred from artifact counts",
    ]

    top_capped_packages = [
        {"package_name": str(row.get("package_name") or ""), "count": int(row.get("capped_not_persisted") or 0)}
        for row in sorted(package_rows, key=lambda item: (-int(item.get("capped_not_persisted") or 0), str(item.get("package_name") or "")))[:10]
        if int(row.get("capped_not_persisted") or 0) > 0
    ]
    top_capped_detectors = [
        {"detector_name": name, "count": int(count)}
        for name, count in detector_capped_totals.most_common(10)
    ]
    top_capped_artifact_grains = [
        {"artifact_grain": str(row.get("artifact_grain") or ""), "count": int(row.get("capped_not_persisted") or 0)}
        for row in sorted(
            [row for row in artifact_grain_rows if str(row.get("artifact_grain")) != "package_rollup"],
            key=lambda item: (-int(item.get("capped_not_persisted") or 0), str(item.get("artifact_grain") or "")),
        )
        if int(row.get("capped_not_persisted") or 0) > 0
    ]

    recommendation = _recommendation_payload(
        capped_ratio=capped_ratio,
        top_capped_detector=top_capped_detectors[0]["detector_name"] if top_capped_detectors else None,
        p0_capped_known=p0_capped_known,
        p0_capped_total=p0_capped_not_persisted,
        per_report_cap_metadata_available=bool(
            int(archive_report_stats.get("reports_with_fidelity_metadata") or 0) > 0
        ),
        per_finding_persisted_flags_available=bool(
            archive_report_stats.get("per_finding_persisted_flags_available")
        ),
        db_consumer_warning_required=db_consumer_warning_required,
        fidelity_audit_should_be_standard=int(capped_not_persisted_total or 0) > 0,
    )

    summary = {
        "report_type": "static_findings_fidelity_audit",
        "generated_at": datetime.now(UTC).isoformat(),
        "session_stamp": session_stamp,
        "repo_root": str(_REPO_ROOT),
        "data_root": str(data_dir),
        "output_dir": str(audit_output_dir),
        "runtime_findings_total": runtime_findings_total,
        "persisted_db_findings_total": persisted_db_findings_total,
        "capped_not_persisted_total": capped_not_persisted_total,
        "fidelity_ratio": fidelity_ratio,
        "capped_ratio": capped_ratio,
        "packages_with_capped_findings": sum(1 for row in package_rows if int(row.get("capped_not_persisted") or 0) > 0),
        "detectors_with_capped_findings": sum(1 for _name, count in detector_capped_totals.items() if int(count) > 0),
        "artifacts_with_capped_findings": total_artifacts_for_capped_packages,
        "p0_runtime_findings": p0_runtime_findings,
        "p0_persisted_findings": p0_persisted_findings,
        "p0_capped_not_persisted": p0_capped_not_persisted,
        "top_capped_packages": top_capped_packages,
        "top_capped_detectors": top_capped_detectors,
        "top_capped_artifact_grains": top_capped_artifact_grains,
        "artifact_reports_preserve_runtime_evidence": int(bool(report_index)),
        "per_report_cap_metadata_available": int(
            int(archive_report_stats.get("reports_with_fidelity_metadata") or 0) > 0
        ),
        "per_finding_persisted_flags_available": int(
            bool(archive_report_stats.get("per_finding_persisted_flags_available"))
        ),
        "reports_with_fidelity_metadata": int(
            archive_report_stats.get("reports_with_fidelity_metadata") or 0
        ),
        "reports_missing_fidelity_metadata": int(
            archive_report_stats.get("reports_missing_fidelity_metadata") or 0
        ),
        "metadata_grain_distribution": dict(
            archive_report_stats.get("metadata_grain_distribution") or {}
        ),
        "db_consumer_warning_required": int(db_consumer_warning_required),
        "cap_policy_detector_aware": True,
        "cap_policy_severity_aware": False,
        "recommended_next_action": recommendation.get("recommended_action"),
        "no_db_writes": True,
        "experimental_audit": True,
        "warnings": warnings,
        "assumptions": assumptions,
        "output_files": list(OUTPUT_FILES),
    }

    _write_json(audit_output_dir / "summary.json", summary)
    _write_csv(audit_output_dir / "finding_fidelity_by_package.csv", package_rows)
    _write_csv(audit_output_dir / "finding_fidelity_by_detector.csv", detector_rows)
    _write_csv(audit_output_dir / "finding_fidelity_by_severity.csv", severity_rows)
    _write_csv(audit_output_dir / "finding_fidelity_by_artifact_grain.csv", artifact_grain_rows)
    _write_csv(audit_output_dir / "capped_findings_examples.csv", example_rows)
    _write_csv(audit_output_dir / "db_consumer_fidelity_gaps.csv", consumer_gap_rows)
    _write_json(audit_output_dir / "recommended_next_action.json", recommendation)

    _log(
        bool(args.verbose),
        (
            "[static-findings-fidelity] "
            f"session={session_stamp} runtime={runtime_findings_total} "
            f"persisted={persisted_db_findings_total} capped={capped_not_persisted_total}"
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
