#!/usr/bin/env python3
"""Read-only audit of static-to-dynamic readiness and evidence continuity.

Builds a filesystem-first readiness bundle over existing ScytaleDroid artifacts:

- dynamic plan inventory
- static-to-dynamic linkage posture
- APK store resolution
- dynamic evidence-pack inventory
- per-plan readiness matrix
- demo candidate shortlist
- blocking gap worklist

Artifact files are the primary evidence source. Database rows and views are used
only as optional corroboration when available.

Examples:

  PYTHONPATH=. python scripts/db/report_dynamic_readiness_audit.py
  PYTHONPATH=. python scripts/db/report_dynamic_readiness_audit.py --verbose
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

READINESS_LEVELS: tuple[str, ...] = (
    "static_plan_ready",
    "identity_linked",
    "apk_store_ready",
    "dynamic_capture_ready",
    "dynamic_evidence_present",
    "analysis_ready",
    "freeze_ready",
    "blocked",
)


@dataclass(frozen=True)
class StaticRunEvidence:
    static_run_id: int
    package_name: str | None
    display_name: str | None
    version_code: str | None
    version_name: str | None
    base_apk_sha256: str | None
    artifact_set_hash: str | None
    signer_set_hash: str | None
    static_handoff_hash: str | None
    baseline_path: str | None
    dynamic_plan_path: str | None
    static_report_path: str | None
    run_manifest_path: str | None
    static_handoff_path: str | None
    manifest_evidence_path: str | None
    dep_path: str | None


@dataclass(frozen=True)
class DbStaticRunRow:
    static_run_id: int
    session_stamp: str | None
    session_label: str | None
    status: str | None
    run_class: str | None
    identity_valid: bool | None
    base_apk_sha256: str | None
    artifact_set_hash: str | None
    static_handoff_hash: str | None
    static_handoff_json_path: str | None


@dataclass(frozen=True)
class DynamicEvidencePack:
    dynamic_run_id: str
    package_name: str | None
    static_run_id: int | None
    base_apk_sha256: str | None
    evidence_pack_path: str
    run_manifest_path: str | None
    static_dynamic_plan_path: str | None
    pcap_paths: tuple[str, ...]
    logcat_paths: tuple[str, ...]
    pcap_features_present: bool
    static_dynamic_overlap_present: bool
    summary_present: bool
    pcap_report_present: bool
    window_params_present: bool
    threshold_present: bool
    rdi_derivable: bool
    freeze_stamped: bool
    run_mode: str | None
    valid_dataset_run: bool | None
    paper_eligible: bool | None
    manifest_status: str | None
    missing_fields: tuple[str, ...]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Write outputs to this directory instead of output/audit/dynamic_readiness/<stamp>/.",
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


def _norm_sha256(value: Any) -> str | None:
    text = _norm_text(value).lower()
    if len(text) == 64 and all(ch in "0123456789abcdef" for ch in text):
        return text
    return None


def _safe_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
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


def _sha256_file(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    rows = list(rows)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(str(key))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fieldnames})


def _repo_inventory_latest_paths(data_dir: Path) -> list[Path]:
    return sorted(data_dir.glob("state/*/inventory/latest.json"))


def _load_latest_inventory_metadata(data_dir: Path) -> dict[str, dict[str, Any]]:
    for path in _repo_inventory_latest_paths(data_dir):
        payload = _read_json(path)
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


def _expected_store_path(data_dir: Path, sha256: str) -> Path:
    return data_dir / "store" / "apk" / "sha256" / sha256[:2] / f"{sha256}.apk"


def _table_exists(core_q: Any, name: str) -> bool:
    row = core_q.run_sql(
        """
        SELECT COUNT(*) AS c FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = %s
        """,
        (name,),
        fetch="one",
        dictionary=True,
        query_name="report_dynamic_readiness.table_exists",
    )
    return bool(row and int(row.get("c") or 0))


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
        query_name="report_dynamic_readiness.view_exists",
    )
    return bool(row and int(row.get("c") or 0))


def _init_optional_db() -> tuple[dict[int, DbStaticRunRow], set[int], dict[str, dict[str, Any]], list[str], str | None]:
    notes: list[str] = []
    static_runs: dict[int, DbStaticRunRow] = {}
    handoff_ids: set[int] = set()
    dynamic_sessions: dict[str, dict[str, Any]] = {}
    db_name: str | None = None
    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
    except Exception as exc:  # noqa: BLE001 - diagnostic script
        notes.append(f"db_unavailable:import_failed:{type(exc).__name__}")
        return static_runs, handoff_ids, dynamic_sessions, notes, db_name

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        notes.append("db_unavailable:engine_disabled")
        return static_runs, handoff_ids, dynamic_sessions, notes, db_name

    try:
        db_row = core_q.run_sql(
            "SELECT DATABASE() AS dbname",
            fetch="one",
            dictionary=True,
            query_name="report_dynamic_readiness.db_name",
        )
        db_name = _norm_text_or_none((db_row or {}).get("dbname"))
    except Exception as exc:  # noqa: BLE001
        notes.append(f"db_unavailable:connect_failed:{type(exc).__name__}")
        return static_runs, handoff_ids, dynamic_sessions, notes, db_name

    if _table_exists(core_q, "static_analysis_runs"):
        try:
            rows = core_q.run_sql(
                """
                SELECT
                  id AS static_run_id,
                  session_stamp,
                  session_label,
                  status,
                  run_class,
                  identity_valid,
                  base_apk_sha256,
                  artifact_set_hash,
                  static_handoff_hash,
                  static_handoff_json_path
                FROM static_analysis_runs
                """,
                (),
                fetch="all",
                dictionary=True,
                query_name="report_dynamic_readiness.static_runs",
            ) or []
            for row in rows:
                run_id = _safe_int(row.get("static_run_id"))
                if run_id is None:
                    continue
                static_runs[run_id] = DbStaticRunRow(
                    static_run_id=run_id,
                    session_stamp=_norm_text_or_none(row.get("session_stamp")),
                    session_label=_norm_text_or_none(row.get("session_label")),
                    status=_norm_text_or_none(row.get("status")),
                    run_class=_norm_text_or_none(row.get("run_class")),
                    identity_valid=bool(row.get("identity_valid")) if row.get("identity_valid") is not None else None,
                    base_apk_sha256=_norm_sha256(row.get("base_apk_sha256")),
                    artifact_set_hash=_norm_sha256(row.get("artifact_set_hash")),
                    static_handoff_hash=_norm_sha256(row.get("static_handoff_hash")),
                    static_handoff_json_path=_norm_text_or_none(row.get("static_handoff_json_path")),
                )
        except Exception as exc:  # noqa: BLE001
            notes.append(f"db_warning:static_runs_query_failed:{type(exc).__name__}")

    if _view_exists(core_q, "v_static_handoff_v1"):
        try:
            rows = core_q.run_sql(
                "SELECT static_run_id FROM v_static_handoff_v1",
                (),
                fetch="all",
                dictionary=True,
                query_name="report_dynamic_readiness.static_handoff_view",
            ) or []
            handoff_ids = {int(row["static_run_id"]) for row in rows if _safe_int(row.get("static_run_id")) is not None}
        except Exception as exc:  # noqa: BLE001
            notes.append(f"db_warning:static_handoff_view_query_failed:{type(exc).__name__}")
    else:
        notes.append("db_note:v_static_handoff_v1_unavailable")

    if _table_exists(core_q, "dynamic_sessions"):
        try:
            rows = core_q.run_sql(
                """
                SELECT
                  dynamic_run_id,
                  package_name,
                  static_run_id,
                  base_apk_sha256,
                  artifact_set_hash,
                  static_handoff_hash,
                  status,
                  valid_dataset_run,
                  evidence_path,
                  version_code,
                  version_name
                FROM dynamic_sessions
                """,
                (),
                fetch="all",
                dictionary=True,
                query_name="report_dynamic_readiness.dynamic_sessions",
            ) or []
            for row in rows:
                run_id = _norm_text(row.get("dynamic_run_id"))
                if run_id:
                    dynamic_sessions[run_id] = dict(row)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"db_warning:dynamic_sessions_query_failed:{type(exc).__name__}")

    return static_runs, handoff_ids, dynamic_sessions, notes, db_name


def _load_freeze_manifest(data_dir: Path) -> tuple[set[str], list[str]]:
    notes: list[str] = []
    try:
        from scytaledroid.DynamicAnalysis.research_cohort_archive import resolve_dataset_freeze_read_path

        path = resolve_dataset_freeze_read_path()
    except Exception:
        path = data_dir / "archive" / "dataset_freeze.json"
    payload = _read_json(path)
    if not isinstance(payload, dict):
        notes.append("freeze_manifest_absent")
        return set(), notes
    ids = payload.get("included_run_ids")
    if not isinstance(ids, list):
        notes.append("freeze_manifest_missing_included_run_ids")
        return set(), notes
    return {str(item).strip() for item in ids if str(item).strip()}, notes


def _load_latest_paper_readiness(output_dir: Path) -> dict[str, Any] | None:
    candidates = sorted(output_dir.glob("audit/dynamic/paper_readiness_audit_*.json"))
    if not candidates:
        return None
    return _read_json(candidates[-1])


def _load_static_run_evidence_index(evidence_root: Path) -> dict[int, StaticRunEvidence]:
    out: dict[int, StaticRunEvidence] = {}
    if not evidence_root.exists():
        return out
    for run_dir in sorted([path for path in evidence_root.iterdir() if path.is_dir()], key=lambda p: p.name):
        run_id = _safe_int(run_dir.name)
        if run_id is None:
            continue
        run_manifest = _read_json(run_dir / "run_manifest.json") or {}
        handoff = _read_json(run_dir / "static_handoff.json") or {}
        artifacts = run_manifest.get("artifacts") if isinstance(run_manifest.get("artifacts"), list) else []
        artifact_by_type: dict[str, str] = {}
        for item in artifacts:
            if not isinstance(item, Mapping):
                continue
            path_val = _norm_text_or_none(item.get("path"))
            type_val = _norm_text_or_none(item.get("type"))
            if path_val and type_val and type_val not in artifact_by_type:
                artifact_by_type[type_val] = path_val
        identity = handoff.get("identity") if isinstance(handoff.get("identity"), Mapping) else {}
        out[run_id] = StaticRunEvidence(
            static_run_id=run_id,
            package_name=_norm_text_or_none(run_manifest.get("package_name")),
            display_name=_norm_text_or_none(run_manifest.get("display_name")),
            version_code=_norm_text_or_none(run_manifest.get("version_code")),
            version_name=_norm_text_or_none(run_manifest.get("version_name")),
            base_apk_sha256=(
                _norm_sha256(run_manifest.get("base_apk_sha256"))
                or _norm_sha256(identity.get("base_apk_sha256"))
            ),
            artifact_set_hash=_norm_sha256(identity.get("artifact_set_hash")),
            signer_set_hash=None,
            static_handoff_hash=_sha256_file(run_dir / "static_handoff.json") if (run_dir / "static_handoff.json").exists() else None,
            baseline_path=artifact_by_type.get("static_baseline_json"),
            dynamic_plan_path=artifact_by_type.get("static_dynamic_plan_json"),
            static_report_path=artifact_by_type.get("static_report"),
            run_manifest_path=str(run_dir / "run_manifest.json") if (run_dir / "run_manifest.json").exists() else None,
            static_handoff_path=str(run_dir / "static_handoff.json") if (run_dir / "static_handoff.json").exists() else None,
            manifest_evidence_path=str(run_dir / "manifest_evidence.json") if (run_dir / "manifest_evidence.json").exists() else None,
            dep_path=str(run_dir / "dep.json") if (run_dir / "dep.json").exists() else None,
        )
    return out


def _report_candidates_for_hash(
    *,
    base_apk_sha256: str | None,
    reports_latest_dir: Path,
    reports_archive_dir: Path,
) -> tuple[str | None, int]:
    if not base_apk_sha256:
        return None, 0
    latest_path = reports_latest_dir / f"{base_apk_sha256}.json"
    if latest_path.exists():
        archive_count = len(list(reports_archive_dir.glob(f"*/{base_apk_sha256}.json")))
        return str(latest_path), archive_count
    archive_matches = sorted(reports_archive_dir.glob(f"*/{base_apk_sha256}.json"))
    if len(archive_matches) == 1:
        return str(archive_matches[0]), 1
    return None, len(archive_matches)


def _match_baseline_for_plan(plan_path: Path, baseline_dir: Path) -> str | None:
    name = plan_path.name
    if "-sr" not in name:
        return None
    prefix, _, suffix = name.rpartition("-sr")
    if "-" not in suffix:
        return None
    _, _, stamp_ext = suffix.partition("-")
    candidate = baseline_dir / f"{prefix}-{stamp_ext}"
    return str(candidate) if candidate.exists() else None


def _scan_dynamic_evidence_packs(
    evidence_root: Path,
) -> dict[str, DynamicEvidencePack]:
    out: dict[str, DynamicEvidencePack] = {}
    if not evidence_root.exists():
        return out
    from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_preflight import (
        compute_ml_preflight,
        load_run_inputs,
    )
    from scytaledroid.DynamicAnalysis.tools.evidence.state_summary import (
        _freeze_stamped,
        _rdi_ready,
        _threshold_present,
        _windowing_recorded,
    )

    for run_dir in sorted([path for path in evidence_root.iterdir() if path.is_dir()], key=lambda p: p.name):
        manifest = _read_json(run_dir / "run_manifest.json")
        if not isinstance(manifest, dict):
            continue
        run_id = _norm_text(manifest.get("dynamic_run_id") or run_dir.name)
        if not run_id:
            continue
        target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
        plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json") or {}
        summary = _read_json(run_dir / "analysis" / "summary.json")
        pcap_report = _read_json(run_dir / "analysis" / "pcap_report.json")
        ml_summary = _read_json(run_dir / "analysis" / "ml" / "v1" / "summary.json")
        model_manifest = _read_json(run_dir / "analysis" / "ml" / "v1" / "model_manifest.json")
        inputs = load_run_inputs(run_dir)
        preflight = compute_ml_preflight(inputs) if inputs is not None else None

        pcap_paths = tuple(
            sorted(
                str(path)
                for path in [run_dir / "artifacts" / "pcapdroid_capture" / item.name for item in (run_dir / "artifacts" / "pcapdroid_capture").glob("*.pcap")]
            )
        ) if (run_dir / "artifacts" / "pcapdroid_capture").exists() else tuple()
        logcat_paths = tuple(
            sorted(
                str(path)
                for path in [run_dir / "artifacts" / "system_log_capture" / item.name for item in (run_dir / "artifacts" / "system_log_capture").glob("*.txt")]
            )
        ) if (run_dir / "artifacts" / "system_log_capture").exists() else tuple()

        missing_fields: list[str] = []
        if not (run_dir / "run_manifest.json").exists():
            missing_fields.append("run_manifest.json")
        if not (run_dir / "inputs" / "static_dynamic_plan.json").exists():
            missing_fields.append("inputs/static_dynamic_plan.json")
        if not pcap_paths:
            missing_fields.append("pcap")
        if not logcat_paths:
            missing_fields.append("logcat")
        if not (run_dir / "analysis" / "pcap_features.json").exists():
            missing_fields.append("analysis/pcap_features.json")
        if not (run_dir / "analysis" / "static_dynamic_overlap.json").exists():
            missing_fields.append("analysis/static_dynamic_overlap.json")

        out[run_id] = DynamicEvidencePack(
            dynamic_run_id=run_id,
            package_name=_norm_text_or_none(plan.get("package_name") or target.get("package_name")),
            static_run_id=_safe_int(plan.get("static_run_id") or target.get("static_run_id")),
            base_apk_sha256=_norm_sha256(
                ((plan.get("run_identity") or {}) if isinstance(plan.get("run_identity"), Mapping) else {}).get("base_apk_sha256")
                or plan.get("base_apk_sha256")
                or target.get("base_apk_sha256")
                or ((target.get("run_identity") or {}) if isinstance(target.get("run_identity"), Mapping) else {}).get("base_apk_sha256")
            ),
            evidence_pack_path=str(run_dir),
            run_manifest_path=str(run_dir / "run_manifest.json") if (run_dir / "run_manifest.json").exists() else None,
            static_dynamic_plan_path=str(run_dir / "inputs" / "static_dynamic_plan.json") if (run_dir / "inputs" / "static_dynamic_plan.json").exists() else None,
            pcap_paths=pcap_paths,
            logcat_paths=logcat_paths,
            pcap_features_present=(run_dir / "analysis" / "pcap_features.json").exists(),
            static_dynamic_overlap_present=(run_dir / "analysis" / "static_dynamic_overlap.json").exists(),
            summary_present=isinstance(summary, dict),
            pcap_report_present=isinstance(pcap_report, dict),
            window_params_present=_windowing_recorded(manifest, ml_summary),
            threshold_present=_threshold_present(run_dir, ml_summary),
            rdi_derivable=_rdi_ready(run_dir, ml_summary),
            freeze_stamped=_freeze_stamped(model_manifest, ml_summary),
            run_mode=(preflight.mode if preflight is not None else None),
            valid_dataset_run=(manifest.get("dataset") or {}).get("valid_dataset_run") if isinstance(manifest.get("dataset"), dict) else None,
            paper_eligible=(manifest.get("dataset") or {}).get("paper_eligible") if isinstance(manifest.get("dataset"), dict) else None,
            manifest_status=_norm_text_or_none(manifest.get("status")),
            missing_fields=tuple(missing_fields),
        )
    return out


def _resolve_category_context(
    package_name: str,
    inventory_by_package: Mapping[str, Mapping[str, Any]],
    resolve_category_with_provenance: Any | None,
) -> tuple[str | None, str | None, str | None]:
    inventory_row = dict(inventory_by_package.get(package_name.lower()) or {})
    display_name = _norm_text_or_none(inventory_row.get("display_name") or inventory_row.get("app_label"))
    if resolve_category_with_provenance is None:
        return _norm_text_or_none(inventory_row.get("category")), _norm_text_or_none(inventory_row.get("category_source")), None
    metadata = dict(inventory_row)
    metadata.setdefault("display_name", display_name)
    try:
        resolution = resolve_category_with_provenance(package_name.lower(), metadata)
    except Exception:  # noqa: BLE001
        resolution = None
    if resolution is None:
        return _norm_text_or_none(inventory_row.get("category")), _norm_text_or_none(inventory_row.get("category_source")), None
    return resolution.category, resolution.source, resolution.confidence


def _plan_missing_required_fields(row: Mapping[str, Any]) -> list[str]:
    missing: list[str] = []
    if not _norm_text(row.get("package_name")):
        missing.append("package_name")
    if _safe_int(row.get("static_run_id")) is None:
        missing.append("static_run_id")
    if not _norm_sha256(row.get("base_apk_sha256")):
        missing.append("base_apk_sha256")
    if not _norm_sha256(row.get("artifact_set_hash")):
        missing.append("artifact_set_hash")
    if not _norm_sha256(row.get("static_handoff_hash")):
        missing.append("static_handoff_hash")
    return missing


def _plan_status(missing_fields: Sequence[str]) -> str:
    return "complete" if not missing_fields else "partial"


def _linkage_status(
    *,
    static_run_id: int | None,
    baseline_present: bool,
    base_apk_sha256: str | None,
    store_present: bool,
    report_match_count: int,
    identity_complete: bool,
) -> str:
    if static_run_id is None:
        return "missing_static_run"
    if not baseline_present:
        return "missing_baseline"
    if not base_apk_sha256:
        return "missing_apk_hash"
    if not store_present:
        return "missing_store_artifact"
    if report_match_count > 1:
        return "ambiguous_multiple_reports"
    if identity_complete:
        return "complete"
    return "partial"


def _identity_linked(
    *,
    static_identity_complete: bool,
    static_run_manifest_present: bool,
    handoff_view_present: bool,
    handoff_path_present: bool,
) -> bool:
    return bool(
        static_identity_complete
        and (static_run_manifest_present or handoff_view_present or handoff_path_present)
    )


def _classify_readiness_level(
    *,
    static_plan_present: bool,
    identity_linked: bool,
    apk_store_ready: bool,
    dynamic_capture_ready: bool,
    dynamic_evidence_present: bool,
    analysis_ready: bool,
    freeze_ready: bool,
) -> str:
    if freeze_ready:
        return "freeze_ready"
    if analysis_ready:
        return "analysis_ready"
    if dynamic_evidence_present:
        return "dynamic_evidence_present"
    if dynamic_capture_ready:
        return "dynamic_capture_ready"
    if apk_store_ready:
        return "apk_store_ready"
    if identity_linked:
        return "identity_linked"
    if static_plan_present:
        return "static_plan_ready"
    return "blocked"


def _flatten_blockers(blockers: Sequence[str]) -> str:
    return "; ".join(str(item) for item in blockers if str(item).strip())


def _unique_packages(rows: Sequence[Mapping[str, Any]], *, field: str = "package_name") -> set[str]:
    packages: set[str] = set()
    for row in rows:
        package_name = _norm_text(row.get(field)).lower()
        if package_name:
            packages.add(package_name)
    return packages


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        from scytaledroid.Config import app_config
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    try:
        from scytaledroid.StaticAnalysis.modules.categories import resolve_category_with_provenance
    except Exception:  # noqa: BLE001
        resolve_category_with_provenance = None

    data_dir = Path(app_config.DATA_DIR)
    output_root = Path(app_config.OUTPUT_DIR)
    dynamic_plan_dir = data_dir / "static_analysis" / "dynamic_plan"
    baseline_dir = data_dir / "static_analysis" / "baseline"
    reports_latest_dir = data_dir / "static_analysis" / "reports" / "latest"
    reports_archive_dir = data_dir / "static_analysis" / "reports" / "archive"
    static_evidence_root = _REPO_ROOT / "evidence" / "static_runs"
    dynamic_evidence_root = output_root / "evidence" / "dynamic"
    audit_output_dir = (
        Path(args.output_dir)
        if args.output_dir
        else output_root / "audit" / "dynamic_readiness" / datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    )
    audit_output_dir.mkdir(parents=True, exist_ok=True)
    _log(bool(args.verbose), f"[dynamic-readiness] output_dir={audit_output_dir}")

    inventory_by_package = _load_latest_inventory_metadata(data_dir)
    static_runs_db, handoff_view_ids, dynamic_sessions_db, db_notes, db_name = _init_optional_db()
    freeze_ids, freeze_notes = _load_freeze_manifest(data_dir)
    latest_paper_audit = _load_latest_paper_readiness(output_root)
    static_run_evidence = _load_static_run_evidence_index(static_evidence_root)
    evidence_packs = _scan_dynamic_evidence_packs(dynamic_evidence_root)
    _log(
        bool(args.verbose),
        f"[dynamic-readiness] plans_dir_exists={int(dynamic_plan_dir.exists())} static_evidence_runs={len(static_run_evidence)} dynamic_evidence_packs={len(evidence_packs)}",
    )

    plan_rows: list[dict[str, Any]] = []
    linkage_rows: list[dict[str, Any]] = []
    apk_rows: list[dict[str, Any]] = []
    evidence_rows: list[dict[str, Any]] = []
    readiness_rows: list[dict[str, Any]] = []
    demo_rows: list[dict[str, Any]] = []
    blocking_rows: list[dict[str, Any]] = []

    # This audit overlaps with report_dynamic_static_alignment.py and
    # report_dynamic_static_pairing_eligibility.py at the identity/hash layer.
    # It intentionally stays standalone for now so its CSV/summary contract can
    # stabilize before any shared helper extraction changes multiple reports.
    plan_paths = sorted(dynamic_plan_dir.glob("*.json")) if dynamic_plan_dir.exists() else []
    baseline_paths = sorted(baseline_dir.glob("*.json")) if baseline_dir.exists() else []
    evidence_by_static_run_id: dict[int, list[DynamicEvidencePack]] = defaultdict(list)
    evidence_by_pkg_hash: dict[tuple[str, str], list[DynamicEvidencePack]] = defaultdict(list)
    for pack in evidence_packs.values():
        if pack.static_run_id is not None:
            evidence_by_static_run_id[int(pack.static_run_id)].append(pack)
        if pack.package_name and pack.base_apk_sha256:
            evidence_by_pkg_hash[(pack.package_name.lower(), pack.base_apk_sha256)].append(pack)
        evidence_rows.append(
            {
                "dynamic_run_id": pack.dynamic_run_id,
                "package_name": pack.package_name,
                "evidence_pack_path": pack.evidence_pack_path,
                "run_manifest_path": pack.run_manifest_path,
                "static_dynamic_plan_path": pack.static_dynamic_plan_path,
                "pcap_paths": "; ".join(pack.pcap_paths),
                "logcat_paths": "; ".join(pack.logcat_paths),
                "pcap_features_present": int(pack.pcap_features_present),
                "static_dynamic_overlap_present": int(pack.static_dynamic_overlap_present),
                "other_analysis_outputs": "; ".join(
                    item
                    for item, present in (
                        ("analysis/summary.json", pack.summary_present),
                        ("analysis/pcap_report.json", pack.pcap_report_present),
                    )
                    if present
                ),
                "static_run_id": pack.static_run_id,
                "base_apk_sha256": pack.base_apk_sha256,
                "dynamic_plan_hash": _sha256_file(Path(pack.static_dynamic_plan_path)) if pack.static_dynamic_plan_path else None,
                "freeze_status": "stamped" if pack.freeze_stamped else ("paper_eligible" if pack.paper_eligible else None),
                "missing_fields": "; ".join(pack.missing_fields),
            }
        )

    package_hashes: dict[str, set[str]] = defaultdict(set)
    dynamic_plan_hash_refs: set[str] = set()

    for plan_path in plan_paths:
        plan = _read_json(plan_path)
        if not isinstance(plan, dict):
            continue
        run_identity = plan.get("run_identity") if isinstance(plan.get("run_identity"), Mapping) else {}
        package_name = _norm_text(plan.get("package_name")).lower()
        static_run_id = _safe_int(plan.get("static_run_id") or run_identity.get("static_run_id"))
        base_apk_sha256 = _norm_sha256(run_identity.get("base_apk_sha256") or plan.get("base_apk_sha256") or (plan.get("hashes") or {}).get("sha256"))
        artifact_set_hash = _norm_sha256(run_identity.get("artifact_set_hash"))
        signer_set_hash = _norm_sha256(run_identity.get("signer_set_hash"))
        static_handoff_hash = _norm_sha256(run_identity.get("static_handoff_hash"))
        session_stamp = None
        static_run_manifest = static_run_evidence.get(static_run_id) if static_run_id is not None else None
        db_row = static_runs_db.get(static_run_id) if static_run_id is not None else None
        if db_row is not None:
            session_stamp = db_row.session_stamp
        display_name = None
        category, category_source, category_confidence = _resolve_category_context(
            package_name,
            inventory_by_package,
            resolve_category_with_provenance,
        )
        inventory_row = inventory_by_package.get(package_name) or {}
        display_name = _norm_text_or_none(
            inventory_row.get("display_name")
            or inventory_row.get("app_label")
            or (static_run_manifest.display_name if static_run_manifest is not None else None)
        )

        baseline_path = (
            static_run_manifest.baseline_path
            if static_run_manifest is not None and static_run_manifest.baseline_path
            else _match_baseline_for_plan(plan_path, baseline_dir)
        )
        report_path, report_match_count = _report_candidates_for_hash(
            base_apk_sha256=(
                base_apk_sha256
                or (static_run_manifest.base_apk_sha256 if static_run_manifest is not None else None)
                or (db_row.base_apk_sha256 if db_row is not None else None)
            ),
            reports_latest_dir=reports_latest_dir,
            reports_archive_dir=reports_archive_dir,
        )
        if static_run_manifest is not None and static_run_manifest.static_report_path:
            report_path = static_run_manifest.static_report_path
            report_match_count = max(report_match_count, 1)

        missing_fields = _plan_missing_required_fields(
            {
                "package_name": package_name,
                "static_run_id": static_run_id,
                "base_apk_sha256": base_apk_sha256,
                "artifact_set_hash": artifact_set_hash,
                "static_handoff_hash": static_handoff_hash,
            }
        )

        plan_rows.append(
            {
                "package_name": package_name,
                "dynamic_plan_path": str(plan_path),
                "display_name": display_name,
                "category": category,
                "category_source": category_source,
                "category_confidence": category_confidence,
                "static_run_id": static_run_id,
                "session_stamp": session_stamp,
                "base_apk_sha256": base_apk_sha256,
                "artifact_set_hash": artifact_set_hash,
                "signer_set_hash": signer_set_hash,
                "static_handoff_hash": static_handoff_hash,
                "plan_schema_version": _norm_text_or_none(plan.get("plan_schema_version")),
                "schema_version": _norm_text_or_none(plan.get("schema_version")),
                "plan_created_at": _norm_text_or_none(plan.get("generated_at")),
                "missing_required_fields": "; ".join(missing_fields),
                "plan_status": _plan_status(missing_fields),
            }
        )

        effective_base_hash = (
            base_apk_sha256
            or (static_run_manifest.base_apk_sha256 if static_run_manifest is not None else None)
            or (db_row.base_apk_sha256 if db_row is not None else None)
        )
        store_exists = False
        if effective_base_hash:
            expected_store_path = _expected_store_path(data_dir, effective_base_hash)
            store_exists = expected_store_path.exists()
            package_hashes[package_name].add(effective_base_hash)
            dynamic_plan_hash_refs.add(effective_base_hash)
            apk_rows.append(
                {
                    "package_name": package_name,
                    "sha256": effective_base_hash,
                    "expected_store_path": str(expected_store_path),
                    "exists_in_store": int(store_exists),
                    "source_artifact": str(plan_path),
                    "source_type": "dynamic_plan",
                    "file_size_bytes": expected_store_path.stat().st_size if expected_store_path.exists() else None,
                    "gap_reason": None if expected_store_path.exists() else "missing_store_artifact",
                }
            )
        if static_run_manifest is not None and static_run_manifest.static_handoff_path:
            handoff_payload = _read_json(Path(static_run_manifest.static_handoff_path)) or {}
            handoff_identity = handoff_payload.get("identity") if isinstance(handoff_payload.get("identity"), Mapping) else {}
            handoff_base = _norm_sha256(handoff_identity.get("base_apk_sha256"))
            if handoff_base:
                expected_store_path = _expected_store_path(data_dir, handoff_base)
                apk_rows.append(
                    {
                        "package_name": package_name,
                        "sha256": handoff_base,
                        "expected_store_path": str(expected_store_path),
                        "exists_in_store": int(expected_store_path.exists()),
                        "source_artifact": static_run_manifest.static_handoff_path,
                        "source_type": "static_handoff",
                        "file_size_bytes": expected_store_path.stat().st_size if expected_store_path.exists() else None,
                        "gap_reason": None if expected_store_path.exists() else "missing_store_artifact",
                    }
                )
        if baseline_path:
            baseline_payload = _read_json(Path(baseline_path)) or {}
            baseline_app = baseline_payload.get("app") if isinstance(baseline_payload.get("app"), Mapping) else {}
            baseline_base = _norm_sha256(baseline_app.get("base_apk_sha256"))
            if baseline_base:
                expected_store_path = _expected_store_path(data_dir, baseline_base)
                apk_rows.append(
                    {
                        "package_name": package_name,
                        "sha256": baseline_base,
                        "expected_store_path": str(expected_store_path),
                        "exists_in_store": int(expected_store_path.exists()),
                        "source_artifact": baseline_path,
                        "source_type": "baseline",
                        "file_size_bytes": expected_store_path.stat().st_size if expected_store_path.exists() else None,
                        "gap_reason": None if expected_store_path.exists() else "missing_store_artifact",
                    }
                )

        static_identity_complete = bool(
            static_run_id is not None
            and effective_base_hash
            and artifact_set_hash
            and static_handoff_hash
        )
        handoff_view_present = bool(static_run_id is not None and static_run_id in handoff_view_ids)
        static_run_manifest_present = bool(static_run_manifest is not None and static_run_manifest.run_manifest_path)
        handoff_path_present = bool(static_run_manifest is not None and static_run_manifest.static_handoff_path)
        linked = _identity_linked(
            static_identity_complete=static_identity_complete,
            static_run_manifest_present=static_run_manifest_present,
            handoff_view_present=handoff_view_present,
            handoff_path_present=handoff_path_present,
        )
        linkage_status = _linkage_status(
            static_run_id=static_run_id,
            baseline_present=bool(baseline_path),
            base_apk_sha256=effective_base_hash,
            store_present=store_exists,
            report_match_count=report_match_count,
            identity_complete=linked,
        )
        linkage_gaps: list[str] = []
        if static_run_id is None:
            linkage_gaps.append("missing_static_run")
        if not baseline_path:
            linkage_gaps.append("missing_baseline")
        if not effective_base_hash:
            linkage_gaps.append("missing_apk_hash")
        if effective_base_hash and not store_exists:
            linkage_gaps.append("missing_store_artifact")
        if report_match_count > 1:
            linkage_gaps.append("ambiguous_multiple_reports")
        if not linked:
            linkage_gaps.append("identity_link_incomplete")

        linkage_rows.append(
            {
                "package_name": package_name,
                "dynamic_plan_path": str(plan_path),
                "baseline_path": baseline_path,
                "static_report_path": report_path,
                "static_session": session_stamp,
                "static_run_id": static_run_id,
                "base_apk_sha256": effective_base_hash,
                "artifact_set_hash": artifact_set_hash,
                "signer_set_hash": signer_set_hash,
                "static_handoff_hash": static_handoff_hash,
                "v_static_handoff_v1_present": int(handoff_view_present),
                "linkage_status": linkage_status,
                "linkage_gaps": _flatten_blockers(linkage_gaps),
            }
        )

        matched_packs = []
        if static_run_id is not None:
            matched_packs.extend(evidence_by_static_run_id.get(static_run_id, []))
        if not matched_packs and package_name and effective_base_hash:
            matched_packs.extend(evidence_by_pkg_hash.get((package_name, effective_base_hash), []))
        matched_run_ids = sorted({pack.dynamic_run_id for pack in matched_packs})
        dynamic_evidence_pack_present = bool(matched_packs)
        run_manifest_present = any(pack.run_manifest_path for pack in matched_packs)
        static_dynamic_plan_input_present = any(pack.static_dynamic_plan_path for pack in matched_packs)
        pcap_present = any(pack.pcap_paths for pack in matched_packs)
        logcat_present = any(pack.logcat_paths for pack in matched_packs)
        pcap_features_present = any(pack.pcap_features_present for pack in matched_packs)
        static_dynamic_overlap_present = any(pack.static_dynamic_overlap_present for pack in matched_packs)
        idle_baseline_present = any(pack.run_mode == "baseline" for pack in matched_packs)
        interaction_capture_present = any(pack.run_mode == "interactive" for pack in matched_packs)
        window_params_present = any(pack.window_params_present for pack in matched_packs)
        threshold_present = any(pack.threshold_present for pack in matched_packs)
        rdi_derivable = any(pack.rdi_derivable for pack in matched_packs)
        freeze_ready = bool(freeze_ids.intersection(matched_run_ids)) or any(pack.freeze_stamped for pack in matched_packs)

        dynamic_capture_ready = bool(dynamic_evidence_pack_present and run_manifest_present and (pcap_present or logcat_present))
        dynamic_evidence_present = bool(
            dynamic_capture_ready and static_dynamic_plan_input_present and pcap_present and logcat_present
        )
        analysis_ready = bool(
            dynamic_evidence_present and pcap_features_present and static_dynamic_overlap_present
        )
        readiness_level = _classify_readiness_level(
            static_plan_present=True,
            identity_linked=linked,
            apk_store_ready=bool(linked and store_exists),
            dynamic_capture_ready=dynamic_capture_ready,
            dynamic_evidence_present=dynamic_evidence_present,
            analysis_ready=analysis_ready,
            freeze_ready=freeze_ready,
        )
        blockers: list[str] = []
        if not static_identity_complete:
            blockers.append("static_identity_incomplete")
        if not linked:
            blockers.append("identity_link_missing")
        if not store_exists:
            blockers.append("apk_store_unresolved")
        if not dynamic_evidence_pack_present:
            blockers.append("dynamic_evidence_pack_missing")
        if dynamic_evidence_pack_present and not run_manifest_present:
            blockers.append("run_manifest_missing")
        if dynamic_evidence_pack_present and not static_dynamic_plan_input_present:
            blockers.append("static_dynamic_plan_input_missing")
        if dynamic_evidence_pack_present and not pcap_present:
            blockers.append("pcap_missing")
        if dynamic_evidence_pack_present and not logcat_present:
            blockers.append("logcat_missing")
        if dynamic_evidence_pack_present and not pcap_features_present:
            blockers.append("pcap_features_missing")
        if dynamic_evidence_pack_present and not static_dynamic_overlap_present:
            blockers.append("static_dynamic_overlap_missing")
        if dynamic_evidence_pack_present and not idle_baseline_present:
            blockers.append("idle_baseline_missing")
        if dynamic_evidence_pack_present and not interaction_capture_present:
            blockers.append("interaction_capture_missing")
        if dynamic_evidence_pack_present and not window_params_present:
            blockers.append("window_params_missing")
        if dynamic_evidence_pack_present and not threshold_present:
            blockers.append("baseline_threshold_missing")
        if dynamic_evidence_pack_present and not rdi_derivable:
            blockers.append("rdi_not_derivable")
        if analysis_ready and not freeze_ready:
            blockers.append("freeze_not_stamped")

        readiness_row = {
            "package_name": package_name,
            "dynamic_plan_path": str(plan_path),
            "display_name": display_name,
            "category": category,
            "category_source": category_source,
            "static_plan_present": 1,
            "static_identity_complete": int(static_identity_complete),
            "static_run_id_present": int(static_run_id is not None),
            "base_apk_sha256_present": int(bool(effective_base_hash)),
            "static_handoff_hash_present": int(bool(static_handoff_hash)),
            "apk_store_resolved": int(store_exists),
            "baseline_artifact_present": int(bool(baseline_path)),
            "dynamic_evidence_pack_present": int(dynamic_evidence_pack_present),
            "run_manifest_present": int(run_manifest_present),
            "static_dynamic_plan_input_present": int(static_dynamic_plan_input_present),
            "pcap_present": int(pcap_present),
            "logcat_present": int(logcat_present),
            "pcap_features_present": int(pcap_features_present),
            "static_dynamic_overlap_present": int(static_dynamic_overlap_present),
            "idle_baseline_present": int(idle_baseline_present),
            "interaction_capture_present": int(interaction_capture_present),
            "window_params_present": int(window_params_present),
            "threshold_present": int(threshold_present),
            "rdi_derivable": int(rdi_derivable),
            "freeze_ready": int(freeze_ready),
            "readiness_level": readiness_level,
            "blockers": _flatten_blockers(blockers),
            "matched_dynamic_run_ids": "; ".join(matched_run_ids),
        }
        readiness_rows.append(readiness_row)

        for blocker in blockers:
            blocking_rows.append(
                {
                    "package_name": package_name,
                    "dynamic_plan_path": str(plan_path),
                    "static_run_id": static_run_id,
                    "readiness_level": readiness_level,
                    "blocker_code": blocker,
                    "base_apk_sha256": effective_base_hash,
                }
            )

        if readiness_level in {"analysis_ready", "freeze_ready"}:
            demo_rows.append(
                {
                    "package_name": package_name,
                    "display_name": display_name,
                    "category": category,
                    "readiness_level": readiness_level,
                    "static_run_id": static_run_id,
                    "base_apk_sha256": effective_base_hash,
                    "dynamic_plan_path": str(plan_path),
                    "matched_dynamic_run_ids": "; ".join(matched_run_ids),
                    "blockers": _flatten_blockers([blocker for blocker in blockers if blocker != "freeze_not_stamped"]),
                }
            )

    # Include dynamic-evidence-only hash references after plan processing.
    for pack in evidence_packs.values():
        if pack.base_apk_sha256:
            expected_store_path = _expected_store_path(data_dir, pack.base_apk_sha256)
            apk_rows.append(
                {
                    "package_name": pack.package_name,
                    "sha256": pack.base_apk_sha256,
                    "expected_store_path": str(expected_store_path),
                    "exists_in_store": int(expected_store_path.exists()),
                    "source_artifact": pack.evidence_pack_path,
                    "source_type": "dynamic_evidence_pack",
                    "file_size_bytes": expected_store_path.stat().st_size if expected_store_path.exists() else None,
                    "gap_reason": None if expected_store_path.exists() else "missing_store_artifact",
                }
            )

    readiness_counts = Counter(str(row.get("readiness_level") or "unknown") for row in readiness_rows)
    linkage_counts = Counter(str(row.get("linkage_status") or "unknown") for row in linkage_rows)
    blocker_counts = Counter(str(row.get("blocker_code") or "unknown") for row in blocking_rows)
    store_missing_count = sum(1 for row in apk_rows if not bool(row.get("exists_in_store")))
    store_total_refs = len(apk_rows)
    store_unreferenced_count = 0
    store_root = data_dir / "store" / "apk" / "sha256"
    if store_root.exists():
        all_store_hashes = {path.stem.lower() for path in store_root.glob("*/*.apk")}
        store_unreferenced_count = len(all_store_hashes - dynamic_plan_hash_refs)

    packages_with_dynamic_plan = _unique_packages(plan_rows)
    packages_with_baseline = {
        package
        for package, row in (
            (_norm_text(item.get("package_name")).lower(), item)
            for item in linkage_rows
        )
        if package and _norm_text(row.get("baseline_path"))
    }
    packages_with_complete_static_linkage = {
        _norm_text(row.get("package_name")).lower()
        for row in linkage_rows
        if _norm_text(row.get("package_name")) and _norm_text(row.get("linkage_status")) == "complete"
    }
    packages_with_resolved_apk_store_identity = {
        _norm_text(row.get("package_name")).lower()
        for row in readiness_rows
        if _norm_text(row.get("package_name")) and bool(row.get("apk_store_resolved"))
    }
    packages_with_dynamic_evidence = {
        _norm_text(row.get("package_name")).lower()
        for row in readiness_rows
        if _norm_text(row.get("package_name")) and bool(row.get("dynamic_evidence_pack_present"))
    }
    packages_analysis_ready = {
        _norm_text(row.get("package_name")).lower()
        for row in readiness_rows
        if _norm_text(row.get("package_name"))
        and _norm_text(row.get("readiness_level")) in {"analysis_ready", "freeze_ready"}
    }
    packages_freeze_ready = {
        _norm_text(row.get("package_name")).lower()
        for row in readiness_rows
        if _norm_text(row.get("package_name")) and _norm_text(row.get("readiness_level")) == "freeze_ready"
    }
    blocked_packages = {
        _norm_text(row.get("package_name")).lower()
        for row in readiness_rows
        if _norm_text(row.get("package_name")) and _norm_text(row.get("blockers"))
    }
    warnings = sorted(
        set(
            note
            for note in (
                *db_notes,
                *freeze_notes,
                "dynamic_evidence_absent" if not evidence_rows else "",
            )
            if note
        )
    )
    assumptions = [
        "artifact files are primary evidence",
        "database rows and views are rebuildable analytical indexes",
        "v_static_handoff_v1 is optional corroboration, not the sole authority",
    ]
    output_files = [
        "summary.json",
        "dynamic_plan_inventory.csv",
        "static_to_dynamic_linkage.csv",
        "apk_store_resolution.csv",
        "dynamic_evidence_pack_inventory.csv",
        "dynamic_readiness_matrix.csv",
        "demo_candidate_apps.csv",
        "blocking_gaps.csv",
    ]

    generated_at = datetime.now(UTC).isoformat()

    summary = {
        "report_type": "dynamic_readiness_audit",
        # Preferred public keys come first; legacy aliases remain below for compatibility.
        "generated_at": generated_at,
        "generated_at_utc": generated_at,
        "repo_root": str(_REPO_ROOT),
        "data_root": str(data_dir),
        "output_dir": str(audit_output_dir),
        "dynamic_plan_count": len(plan_rows),
        "baseline_count": len(baseline_paths),
        "dynamic_evidence_pack_count": len(evidence_rows),
        "packages_with_dynamic_plan": len(packages_with_dynamic_plan),
        "packages_with_baseline": len(packages_with_baseline),
        "packages_with_complete_static_linkage": len(packages_with_complete_static_linkage),
        "packages_with_resolved_apk_store_identity": len(packages_with_resolved_apk_store_identity),
        "packages_with_dynamic_evidence": len(packages_with_dynamic_evidence),
        "packages_analysis_ready": len(packages_analysis_ready),
        "packages_freeze_ready": len(packages_freeze_ready),
        "blocked_package_count": len(blocked_packages),
        "top_blocker_types": [
            {"blocker": blocker, "count": count}
            for blocker, count in blocker_counts.most_common(10)
        ],
        "readiness_level_counts": dict(sorted(readiness_counts.items())),
        "output_files": output_files,
        "warnings": warnings,
        "assumptions": assumptions,
        "no_db_writes": True,
        "experimental_audit": True,
        "source_of_truth_rule": {
            "artifact_files_primary": True,
            "db_rows_optional_index": True,
            "static_handoff_view_optional": True,
        },
        "filesystem_roots": {
            "dynamic_plan_dir": str(dynamic_plan_dir),
            "baseline_dir": str(baseline_dir),
            "reports_latest_dir": str(reports_latest_dir),
            "reports_archive_dir": str(reports_archive_dir),
            "apk_store_root": str(store_root),
            "static_evidence_root": str(static_evidence_root),
            "dynamic_evidence_root": str(dynamic_evidence_root),
        },
        "db": {
            "available": int(bool(static_runs_db or dynamic_sessions_db or db_name)),
            "database_name": db_name,
            "notes": sorted(set(db_notes)),
            "static_runs_rows": len(static_runs_db),
            "dynamic_sessions_rows": len(dynamic_sessions_db),
            "v_static_handoff_v1_rows": len(handoff_view_ids),
        },
        "freeze_manifest": {
            "present": int(bool(freeze_ids)),
            "included_run_ids": len(freeze_ids),
            "notes": freeze_notes,
        },
        "dynamic_plans_total": len(plan_rows),
        "static_run_evidence_total": len(static_run_evidence),
        "dynamic_evidence_packs_total": len(evidence_rows),
        "demo_candidate_count": len(demo_rows),
        "readiness_distribution": dict(sorted(readiness_counts.items())),
        "linkage_status_distribution": dict(sorted(linkage_counts.items())),
        "blocking_gap_distribution": dict(sorted(blocker_counts.items())),
        "apk_store_resolution": {
            "referenced_hash_rows": store_total_refs,
            "missing_store_artifacts": int(store_missing_count),
            "store_apks_unreferenced_by_current_dynamic_plans": int(store_unreferenced_count),
            "packages_with_multiple_referenced_hashes": int(sum(1 for hashes in package_hashes.values() if len(hashes) > 1)),
        },
        "latest_paper_readiness_audit": {
            "present": int(isinstance(latest_paper_audit, dict)),
            "path": None,
            "can_freeze": (latest_paper_audit or {}).get("can_freeze") if isinstance(latest_paper_audit, dict) else None,
            "apps_satisfied": (latest_paper_audit or {}).get("apps_satisfied") if isinstance(latest_paper_audit, dict) else None,
            "reasons": (latest_paper_audit or {}).get("reasons") if isinstance(latest_paper_audit, dict) else None,
        },
        "limitations": warnings,
        "generated_files": output_files,
    }

    latest_audit_candidates = sorted((output_root / "audit" / "dynamic").glob("paper_readiness_audit_*.json"))
    if latest_audit_candidates:
        summary["latest_paper_readiness_audit"]["path"] = str(latest_audit_candidates[-1])

    _write_csv(audit_output_dir / "dynamic_plan_inventory.csv", plan_rows)
    _write_csv(audit_output_dir / "static_to_dynamic_linkage.csv", linkage_rows)
    _write_csv(audit_output_dir / "apk_store_resolution.csv", apk_rows)
    _write_csv(audit_output_dir / "dynamic_evidence_pack_inventory.csv", evidence_rows)
    _write_csv(audit_output_dir / "dynamic_readiness_matrix.csv", readiness_rows)
    _write_csv(audit_output_dir / "demo_candidate_apps.csv", demo_rows)
    _write_csv(audit_output_dir / "blocking_gaps.csv", blocking_rows)
    _write_json(audit_output_dir / "summary.json", summary)

    print(audit_output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
