"""Phase 1 session evidence manifest (best-effort; must not fail static runs).

Writes ``evidence_manifest.json`` next to ``run_map.json`` under
``DATA_DIR/sessions/<session_stamp>/`` after session linkage succeeds — see
``docs/maintenance/evidence_run_manifest_spec.md`` §6 (Phase 1: log-only failures).

Disable entirely with ``SCYTALEDROID_EVIDENCE_MANIFEST=0`` (or ``false`` / ``no``).
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_utils import diagnostics as db_diagnostics
from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunOutcome
from scytaledroid.Utils.LoggingUtils import logging_utils as log
from scytaledroid.Utils.version_utils import get_git_commit


def _env_manifest_enabled() -> bool:
    raw = (os.environ.get("SCYTALEDROID_EVIDENCE_MANIFEST") or "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _file_sha256(path: Path) -> tuple[str | None, str | None]:
    try:
        data = path.read_bytes()
        return hashlib.sha256(data).hexdigest(), None
    except OSError as exc:
        return None, f"{exc.__class__.__name__}: {exc}"


def _safe_db_catalog() -> str | None:
    try:
        name = db_config.DB_CONFIG.get("database")
        return str(name).strip() or None
    except Exception:
        return None


def _environment_fingerprint() -> dict[str, Any]:
    return {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "paper_grade_requested": bool((os.environ.get("SCYTALEDROID_PAPER_GRADE") or "").strip()),
        "no_dotenv": os.environ.get("SCYTALEDROID_NO_DOTENV") == "1",
    }


def _build_id() -> str | None:
    for key in ("SCYTALEDROID_BUILD_ID", "GITHUB_SHA", "CI_COMMIT_SHA"):
        raw = (os.environ.get(key) or "").strip()
        if raw:
            return raw[:256]
    return None


def _fetch_handoff_by_run_id(static_run_ids: list[int]) -> dict[int, dict[str, Any]]:
    if not static_run_ids:
        return {}
    try:
        placeholders = ",".join(["%s"] * len(static_run_ids))
        rows = core_q.run_sql(
            f"""
            SELECT id, static_handoff_json_path, static_handoff_hash
            FROM static_analysis_runs
            WHERE id IN ({placeholders})
            """,
            tuple(static_run_ids),
            fetch="all",
        ) or []
    except Exception:
        return {}
    out: dict[int, dict[str, Any]] = {}
    for row in rows:
        if not row or row[0] is None:
            continue
        rid = int(row[0])
        out[rid] = {
            "json_path": row[1],
            "sha256": row[2],
        }
    return out


def build_session_evidence_manifest_payload(
    *,
    session_stamp: str,
    session_label: str | None,
    run_map: Mapping[str, Any],
    outcome: RunOutcome,
) -> dict[str, Any]:
    """Assemble the JSON payload (for tests and introspection)."""

    stamp = str(session_stamp).strip()
    label = (session_label or "").strip() or stamp
    apps = run_map.get("apps") if isinstance(run_map.get("apps"), list) else []
    static_run_ids: list[int] = []
    for app in apps:
        if not isinstance(app, Mapping):
            continue
        sid = app.get("static_run_id")
        if sid is not None:
            try:
                static_run_ids.append(int(sid))
            except (TypeError, ValueError):
                continue
    static_run_ids = sorted(set(static_run_ids))
    # Spec allows a single id or a session-level list; encode as int when unique.
    if not static_run_ids:
        static_run_id_field: Any = None
    elif len(static_run_ids) == 1:
        static_run_id_field = static_run_ids[0]
    else:
        static_run_id_field = static_run_ids

    session_dir = Path(app_config.DATA_DIR) / "sessions" / stamp
    run_map_path = session_dir / "run_map.json"
    canonical_artifacts: list[dict[str, Any]] = []
    warnings: list[str] = []

    seen_canonical_paths: set[str] = set()
    if run_map_path.is_file():
        digest, err = _file_sha256(run_map_path)
        entry: dict[str, Any] = {
            "path": str(run_map_path),
            "role": "run_map",
            "sha256": digest,
        }
        if err:
            entry["hash_error"] = err
            warnings.append(f"run_map_hash_error:{err}")
        canonical_artifacts.append(entry)
        seen_canonical_paths.add(str(run_map_path))
    else:
        warnings.append("run_map_missing_on_disk_after_finalize")
        canonical_artifacts.append(
            {
                "path": str(run_map_path),
                "role": "run_map",
                "status": "missing",
                "sha256": None,
            }
        )

    handoff_by_run = _fetch_handoff_by_run_id(static_run_ids)
    handoff_runs: list[dict[str, Any]] = []
    detector_reports: list[dict[str, Any]] = []

    by_pkg: dict[str, AppRunResult] = {
        str(getattr(r, "package_name", "") or "").strip(): r for r in (outcome.results or [])
    }

    for app in apps:
        if not isinstance(app, Mapping):
            continue
        pkg = str(app.get("package") or "").strip()
        sid_raw = app.get("static_run_id")
        try:
            sid = int(sid_raw) if sid_raw is not None else None
        except (TypeError, ValueError):
            sid = None
        res = by_pkg.get(pkg)
        base = res.base_artifact_outcome() if res else None
        report_path: Path | None = None
        if base and base.saved_path:
            report_path = Path(str(base.saved_path))
        det: dict[str, Any] = {
            "package_name": pkg,
            "static_run_id": sid,
        }
        if report_path and report_path.is_file():
            d, err = _file_sha256(report_path)
            det["path"] = str(report_path)
            det["sha256"] = d
            if err:
                det["hash_error"] = err
                warnings.append(f"detector_report_hash_error:{pkg}:{err}")
            else:
                rp_s = str(report_path)
                if rp_s not in seen_canonical_paths:
                    seen_canonical_paths.add(rp_s)
                    canonical_artifacts.append(
                        {
                            "path": rp_s,
                            "role": "detector_report",
                            "package_name": pkg,
                            "static_run_id": sid,
                            "sha256": d,
                        }
                    )
        else:
            det["status"] = "missing"
            det["path"] = str(report_path) if report_path else None
            det["sha256"] = None
        detector_reports.append(det)

        hrow = handoff_by_run.get(sid) if sid is not None else None
        h: dict[str, Any] = {"package_name": pkg, "static_run_id": sid}
        if hrow and hrow.get("json_path"):
            hp = Path(str(hrow["json_path"]))
            if hp.is_file():
                hd, herr = _file_sha256(hp)
                h["json_path"] = str(hp)
                h["sha256"] = hd or hrow.get("sha256")
                if herr:
                    h["hash_error"] = herr
                    warnings.append(f"handoff_hash_error:{pkg}:{herr}")
                elif hd:
                    hp_s = str(hp)
                    if hp_s not in seen_canonical_paths:
                        seen_canonical_paths.add(hp_s)
                        canonical_artifacts.append(
                            {
                                "path": hp_s,
                                "role": "handoff_json",
                                "package_name": pkg,
                                "static_run_id": sid,
                                "sha256": hd,
                            }
                        )
            else:
                h["json_path"] = str(hp)
                h["sha256"] = hrow.get("sha256")
                h["status"] = "path_not_found"
        else:
            h["status"] = "missing"
            h["json_path"] = hrow.get("json_path") if hrow else None
            h["sha256"] = hrow.get("sha256") if hrow else None
        handoff_runs.append(h)

        if res and res.dynamic_plan_path:
            pp = Path(str(res.dynamic_plan_path))
            if pp.is_file():
                pd, perr = _file_sha256(pp)
                art: dict[str, Any] = {
                    "path": str(pp),
                    "role": "dynamic_plan_json",
                    "package_name": pkg,
                    "static_run_id": sid,
                    "sha256": pd,
                }
                if perr:
                    art["hash_error"] = perr
                    warnings.append(f"dynamic_plan_hash_error:{pkg}:{perr}")
                pp_s = str(pp)
                if pp_s not in seen_canonical_paths:
                    seen_canonical_paths.add(pp_s)
                    canonical_artifacts.append(art)

    generated = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    payload: dict[str, Any] = {
        "manifest_schema_version": "1",
        "manifest_scope": "session",
        "generated_at_utc": generated,
        "session_stamp": stamp,
        "session_label": label,
        "static_run_id": static_run_id_field,
        "static_run_ids": static_run_ids,
        "db_catalog": _safe_db_catalog(),
        "schema_version": db_diagnostics.get_schema_version() or "<unknown>",
        "git_commit": get_git_commit(),
        "environment_fingerprint": _environment_fingerprint(),
        "canonical_artifacts": canonical_artifacts,
        "handoff": {"runs": handoff_runs},
        "detector_report": {"runs": detector_reports},
        "manifest_location": str(session_dir / "evidence_manifest.json"),
    }
    bid = _build_id()
    if bid:
        payload["build_id"] = bid
    if warnings:
        payload["warnings"] = warnings
    return payload


def write_session_evidence_manifest_phase1(
    *,
    session_stamp: str,
    session_label: str | None,
    run_map: Mapping[str, Any],
    outcome: RunOutcome,
) -> Path | None:
    """Write ``evidence_manifest.json`` for the session; swallow all errors (Phase 1)."""

    if not _env_manifest_enabled():
        return None
    stamp = str(session_stamp or "").strip()
    if not stamp or not run_map:
        return None
    try:
        payload = build_session_evidence_manifest_payload(
            session_stamp=stamp,
            session_label=session_label,
            run_map=run_map,
            outcome=outcome,
        )
        session_dir = Path(app_config.DATA_DIR) / "sessions" / stamp
        session_dir.mkdir(parents=True, exist_ok=True)
        dest = session_dir / "evidence_manifest.json"
        tmp = session_dir / f"evidence_manifest.json.tmp.{os.getpid()}"
        text = json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n"
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(dest)
        return dest
    except OSError as exc:
        log.warning(
            f"SKIP evidence manifest (not writable): {exc}",
            category="static_analysis",
        )
        return None
    except Exception as exc:
        log.warning(
            f"SKIP evidence manifest (build/write failed): {exc.__class__.__name__}: {exc}",
            category="static_analysis",
        )
        return None


__all__ = [
    "build_session_evidence_manifest_payload",
    "write_session_evidence_manifest_phase1",
]
