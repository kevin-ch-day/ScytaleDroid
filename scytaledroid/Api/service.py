"""FastAPI service definition for ScytaleDroid."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows.headless_run import _artifact_group_from_path
from scytaledroid.StaticAnalysis.persistence import list_reports
from scytaledroid.StaticAnalysis.services import static_service
from scytaledroid.StaticAnalysis.session import make_session_stamp, normalize_session_stamp
from scytaledroid.Utils.LoggingUtils import logging_utils as log

try:  # optional API dependency
    from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, Request, UploadFile
    from fastapi.responses import FileResponse, JSONResponse
    from pydantic import BaseModel
except Exception:  # pragma: no cover - API is optional
    BackgroundTasks = Depends = FastAPI = File = HTTPException = Request = UploadFile = None
    FileResponse = JSONResponse = None
    BaseModel = object

try:  # optional database access for status queries
    from scytaledroid.Database.db_core import db_queries as core_q
except Exception:  # pragma: no cover - offline mode
    core_q = None

if TYPE_CHECKING:  # pragma: no cover - typing only
    from fastapi import FastAPI

MAX_LIST_LIMIT = 200
MAX_JOB_HISTORY = 200
DEFAULT_MAX_UPLOAD_MB = 200


@dataclass
class JobRecord:
    job_id: str
    state: str
    created_at: float
    session_stamp: str
    package_name: str
    detail: str | None = None


class ScanRequest(BaseModel):
    apk_path: str
    session_stamp: str | None = None
    profile: str = "full"
    scope_label: str | None = None
    allow_session_reuse: bool = True


_jobs: dict[str, JobRecord] = {}
_jobs_lock = threading.Lock()


def _record_job(job: JobRecord) -> None:
    with _jobs_lock:
        _jobs[job.job_id] = job
        if len(_jobs) > MAX_JOB_HISTORY:
            for stale in sorted(_jobs.values(), key=lambda entry: entry.created_at)[: len(_jobs) - MAX_JOB_HISTORY]:
                _jobs.pop(stale.job_id, None)


def _update_job(
    job_id: str,
    *,
    state: str,
    detail: str | None = None,
    session_stamp: str | None = None,
    package_name: str | None = None,
) -> None:
    with _jobs_lock:
        existing = _jobs.get(job_id)
        if not existing:
            return
        _jobs[job_id] = JobRecord(
            job_id=existing.job_id,
            state=state,
            created_at=existing.created_at,
            session_stamp=session_stamp or existing.session_stamp,
            package_name=package_name or existing.package_name,
            detail=detail,
        )


def _serialize_job(job: JobRecord) -> dict[str, Any]:
    return {
        "job_id": job.job_id,
        "state": job.state,
        "created_at": job.created_at,
        "session_stamp": job.session_stamp,
        "package_name": job.package_name,
        "detail": job.detail,
    }


def _find_report_for_session(session_stamp: str) -> Path | None:
    for stored in list_reports():
        meta = stored.report.metadata
        if str(meta.get("session_stamp", "")).strip() == session_stamp:
            return stored.path
    return None


def _find_report_by_hash(report_hash: str) -> Path | None:
    report_hash = report_hash.strip()
    if not report_hash:
        return None
    for stored in list_reports():
        if stored.path.stem == report_hash:
            return stored.path
    return None


def _run_static_scan(
    job_id: str,
    apk_path: Path,
    session_stamp: str,
    profile: str,
    scope_label: str,
    allow_reuse: bool,
) -> None:
    _update_job(job_id, state="RUNNING")
    group = None
    try:
        group = _artifact_group_from_path(apk_path)
        selection = ScopeSelection(scope="app", label=scope_label, groups=(group,))
        params = RunParameters(
            profile=profile,
            scope="app",
            scope_label=scope_label,
            paper_grade_requested=False,
        )
        params = replace(params, session_stamp=session_stamp, session_label=session_stamp)
        base_dir = artifact_store.analysis_apk_root()
        run_result = static_service.run_scan(
            selection,
            params,
            base_dir,
            allow_session_reuse=allow_reuse,
        )
        resolved_stamp = run_result.session_stamp or session_stamp
        if not run_result.completed:
            _update_job(
                job_id,
                state="FAILED",
                detail=run_result.detail or "Static analysis did not complete.",
                session_stamp=resolved_stamp,
                package_name=group.package_name,
            )
            return
        _update_job(
            job_id,
            state="OK",
            detail=run_result.detail,
            session_stamp=resolved_stamp,
            package_name=group.package_name,
        )
    except BaseException as exc:  # pragma: no cover - async path
        detail = str(exc) or exc.__class__.__name__
        log.error(f"API scan failed: {exc}", category="api")
        _update_job(
            job_id,
            state="FAILED",
            detail=detail,
            session_stamp=session_stamp,
            package_name=getattr(group, "package_name", None),
        )


def _start_scan_worker(
    job_id: str,
    apk_path: Path,
    session_stamp: str,
    profile: str,
    scope_label: str,
    allow_reuse: bool,
) -> threading.Thread:
    worker = threading.Thread(
        target=_run_static_scan,
        args=(
            job_id,
            apk_path,
            session_stamp,
            profile,
            scope_label,
            allow_reuse,
        ),
        daemon=True,
    )
    worker.start()
    return worker


def _hash_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_upload_sidecar(
    apk_path: Path,
    *,
    upload_id: str,
    original_filename: str | None,
    digest: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "upload_id": upload_id,
        "uploaded_filename": original_filename or apk_path.name,
        "sha256": digest,
        "artifact": "base",
        "artifact_kind": "apk",
        "is_split_member": False,
        "source_kind": "api_upload",
        "canonical_store_path": artifact_store.repo_relative_path(apk_path),
    }
    try:
        group = _artifact_group_from_path(apk_path)
        artifact = group.artifacts[0] if group.artifacts else None
        if artifact is not None:
            payload.update(dict(artifact.metadata))
        payload.setdefault("package_name", group.package_name)
        if artifact is not None:
            payload.setdefault("artifact", artifact.artifact_label)
            payload.setdefault("is_split_member", artifact.is_split_member)
    except Exception as exc:
        log.warning(f"Upload metadata extraction failed for {apk_path.name}: {exc}", category="api")
    sidecar_path = apk_path.with_suffix(apk_path.suffix + ".meta.json")
    sidecar_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return payload


def _resolve_api_key() -> str | None:
    api_key = os.getenv("SCYTALEDROID_API_KEY", "").strip()
    return api_key or None


def _require_api_key(request: Any) -> None:
    from fastapi import HTTPException

    api_key = _resolve_api_key()
    if not api_key:
        return
    auth_header = request.headers.get("Authorization", "")
    token = ""
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    if not token:
        token = request.headers.get("X-API-Key", "").strip()
    if token != api_key:
        raise HTTPException(status_code=401, detail="Unauthorized")


def _resolve_max_upload_bytes() -> int:
    raw = os.getenv("SCYTALEDROID_API_MAX_UPLOAD_MB", str(DEFAULT_MAX_UPLOAD_MB)).strip()
    try:
        mb = max(1, int(raw))
    except ValueError:
        mb = DEFAULT_MAX_UPLOAD_MB
    return mb * 1024 * 1024


def _resolve_allowed_apk_bases() -> tuple[Path, ...]:
    return (artifact_store.analysis_apk_root().resolve(),)


def _validate_apk_path(apk_path: Path) -> Path:
    from fastapi import HTTPException

    base_dirs = _resolve_allowed_apk_bases()
    resolved = apk_path.expanduser().resolve()
    if not any(_is_relative_to(resolved, base_dir) for base_dir in base_dirs):
        allowed = ", ".join(str(base_dir) for base_dir in base_dirs)
        raise HTTPException(
            status_code=400,
            detail=f"APK path must be within one of: {allowed}",
        )
    if not resolved.exists():
        raise HTTPException(status_code=404, detail=f"APK not found: {resolved}")
    return resolved


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def _collect_run_status(session_stamp: str) -> dict[str, Any]:
    if core_q is None:
        return {"session_stamp": session_stamp, "status": "db_unavailable"}
    rows = core_q.run_sql(
        """
        SELECT status, COUNT(*) AS n
        FROM static_analysis_runs
        WHERE session_stamp = %s
        GROUP BY status
        """,
        (session_stamp,),
        fetch="all",
    )
    return {
        "session_stamp": session_stamp,
        "counts": {row[0]: int(row[1]) for row in rows or []},
    }


def build_api_app() -> FastAPI:
    if FastAPI is None or File is None or JSONResponse is None:
        raise RuntimeError("FastAPI dependencies are unavailable. Install API extras to use the server.")

    app = FastAPI(title="ScytaleDroid API", version=app_config.APP_VERSION)

    upload_file = File(...)

    def require_api_key(request: Request) -> None:
        _require_api_key(request)

    @app.post("/upload")
    def upload_apk(
        file: UploadFile = upload_file,
        _: None = Depends(require_api_key),
    ) -> dict[str, Any]:
        upload_dir = artifact_store.upload_inbox_root()
        upload_dir.mkdir(parents=True, exist_ok=True)
        suffix = Path(file.filename or "upload.apk").suffix or ".apk"
        upload_id = uuid.uuid4().hex
        filename = f"{upload_id}{suffix}"
        destination = upload_dir / filename
        max_bytes = _resolve_max_upload_bytes()
        written = 0

        with destination.open("wb") as handle:
            while True:
                chunk = file.file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    handle.close()
                    destination.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"Upload exceeds max size ({max_bytes // (1024 * 1024)} MB).",
                    )
                handle.write(chunk)

        digest = _hash_file(destination)
        canonical_path = artifact_store.materialize_apk(
            destination,
            sha256_digest=digest,
            suffix=suffix,
            move=True,
        )
        metadata = _write_upload_sidecar(
            canonical_path,
            upload_id=upload_id,
            original_filename=file.filename,
            digest=digest,
        )
        receipt_payload = {
            **metadata,
            "upload_id": upload_id,
            "canonical_store_path": artifact_store.repo_relative_path(canonical_path),
            "size_bytes": canonical_path.stat().st_size,
        }
        receipt_path = artifact_store.write_upload_receipt(
            upload_id=upload_id,
            payload=receipt_payload,
        )
        return {
            "upload_id": upload_id,
            "path": str(canonical_path),
            "sha256": digest,
            "size_bytes": canonical_path.stat().st_size,
            "package_name": metadata.get("package_name"),
            "version_code": metadata.get("version_code"),
            "version_name": metadata.get("version_name"),
            "receipt_path": artifact_store.repo_relative_path(receipt_path),
        }

    @app.post("/scan")
    def scan_apk(
        payload: ScanRequest,
        _: None = Depends(require_api_key),
    ) -> JSONResponse:
        apk_path = _validate_apk_path(Path(payload.apk_path))

        session_stamp = payload.session_stamp or make_session_stamp()
        normalized = normalize_session_stamp(session_stamp)
        if normalized != session_stamp:
            session_stamp = normalized

        try:
            group = _artifact_group_from_path(apk_path)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        scope_label = payload.scope_label or group.package_name
        job_id = uuid.uuid4().hex
        record = JobRecord(
            job_id=job_id,
            state="QUEUED",
            created_at=time.time(),
            session_stamp=session_stamp,
            package_name=group.package_name,
        )
        _record_job(record)

        _start_scan_worker(
            job_id,
            apk_path,
            session_stamp,
            payload.profile,
            scope_label,
            payload.allow_session_reuse,
        )

        return JSONResponse(
            {
                "job_id": job_id,
                "session_stamp": session_stamp,
                "package_name": group.package_name,
                "state": "QUEUED",
            }
        )

    @app.get("/job/{job_id}")
    def job_status(job_id: str, _: None = Depends(require_api_key)) -> dict[str, Any]:
        with _jobs_lock:
            job = _jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        return _serialize_job(job)

    @app.get("/jobs")
    def jobs_list(limit: int = 25, _: None = Depends(require_api_key)) -> dict[str, Any]:
        limit = max(1, min(limit, MAX_LIST_LIMIT))
        with _jobs_lock:
            jobs = list(_jobs.values())
        jobs = sorted(jobs, key=lambda entry: entry.created_at, reverse=True)[:limit]
        return {"jobs": [_serialize_job(job) for job in jobs]}

    @app.get("/runs")
    def runs_list(
        limit: int = 25,
        q: str | None = None,
        profile: str | None = None,
        _: None = Depends(require_api_key),
    ) -> dict[str, Any]:
        if core_q is None:
            return {"runs": []}
        limit = max(1, min(limit, MAX_LIST_LIMIT))
        where = []
        params: list[Any] = []
        if q:
            where.append("(a.package_name LIKE %s OR a.display_name LIKE %s)")
            like = f"%{q}%"
            params.extend([like, like])
        if profile:
            where.append("a.profile_key = %s")
            params.append(profile)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        params.append(limit)
        rows = core_q.run_sql(
            f"""
            SELECT sar.session_stamp,
                   sar.status,
                   a.package_name,
                   a.display_name,
                   av.version_code,
                   av.version_name,
                   sar.ended_at_utc
            FROM static_analysis_runs sar
            JOIN app_versions av ON av.id = sar.app_version_id
            JOIN apps a ON a.id = av.app_id
            {clause}
            ORDER BY sar.id DESC
            LIMIT %s
            """,
            tuple(params),
            fetch="all",
        )
        runs = [
            {
                "session_stamp": row[0],
                "status": row[1],
                "package_name": row[2],
                "display_name": row[3],
                "version_code": row[4],
                "version_name": row[5],
                "ended_at_utc": row[6].isoformat() if row[6] else None,
            }
            for row in (rows or [])
        ]
        return {"runs": runs}

    @app.get("/apps")
    def apps_list(
        limit: int = 25,
        q: str | None = None,
        profile: str | None = None,
        _: None = Depends(require_api_key),
    ) -> dict[str, Any]:
        if core_q is None:
            return {"apps": []}
        limit = max(1, min(limit, MAX_LIST_LIMIT))
        where = []
        params: list[Any] = []
        if q:
            where.append("(a.package_name LIKE %s OR a.display_name LIKE %s)")
            like = f"%{q}%"
            params.extend([like, like])
        if profile:
            where.append("a.profile_key = %s")
            params.append(profile)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        params.append(limit)
        rows = core_q.run_sql(
            f"""
            SELECT av.id AS app_version_id,
                   a.package_name,
                   a.display_name,
                   av.version_code,
                   av.version_name,
                   r.status,
                   r.ended_at_utc,
                   r.sha256,
                   r.session_stamp
            FROM app_versions av
            JOIN apps a ON a.id = av.app_id
            LEFT JOIN (
              SELECT r1.*
              FROM static_analysis_runs r1
              JOIN (
                SELECT app_version_id, MAX(id) AS max_id
                FROM static_analysis_runs
                GROUP BY app_version_id
              ) x ON x.app_version_id = r1.app_version_id AND x.max_id = r1.id
            ) r ON r.app_version_id = av.id
            {clause}
            ORDER BY r.ended_at_utc DESC
            LIMIT %s
            """,
            tuple(params),
            fetch="all",
        )
        apps = [
            {
                "app_version_id": row[0],
                "package_name": row[1],
                "display_name": row[2],
                "version_code": row[3],
                "version_name": row[4],
                "latest_status": row[5],
                "latest_ended_at": row[6].isoformat() if row[6] else None,
                "sha256": row[7],
                "session_stamp": row[8],
            }
            for row in (rows or [])
        ]
        return {"apps": apps}

    @app.get("/profiles")
    def profile_list(_: None = Depends(require_api_key)) -> dict[str, Any]:
        if core_q is None:
            return {"profiles": []}
        rows = core_q.run_sql(
            """
            SELECT DISTINCT profile_key
            FROM apps
            WHERE profile_key IS NOT NULL AND profile_key <> ''
            ORDER BY profile_key
            """,
            fetch="all",
        )
        profiles = [row[0] for row in (rows or []) if row and row[0]]
        return {"profiles": profiles}

    @app.get("/apps/recent")
    def apps_recent(limit: int = 25, _: None = Depends(require_api_key)) -> dict[str, Any]:
        if core_q is None:
            return {"apps": []}
        limit = max(1, min(limit, MAX_LIST_LIMIT))
        rows = core_q.run_sql(
            """
            SELECT av.id AS app_version_id,
                   a.package_name,
                   a.display_name,
                   av.version_code,
                   av.version_name,
                   r.status,
                   r.ended_at_utc,
                   r.sha256,
                   r.session_stamp
            FROM static_analysis_runs r
            JOIN (
              SELECT app_version_id, MAX(id) AS max_id
              FROM static_analysis_runs
              WHERE status='COMPLETED'
              GROUP BY app_version_id
            ) x ON x.app_version_id = r.app_version_id AND x.max_id = r.id
            JOIN app_versions av ON av.id = r.app_version_id
            JOIN apps a ON a.id = av.app_id
            ORDER BY r.ended_at_utc DESC
            LIMIT %s
            """,
            (limit,),
            fetch="all",
        )
        apps = [
            {
                "app_version_id": row[0],
                "package_name": row[1],
                "display_name": row[2],
                "version_code": row[3],
                "version_name": row[4],
                "latest_status": row[5],
                "latest_ended_at": row[6].isoformat() if row[6] else None,
                "sha256": row[7],
                "session_stamp": row[8],
            }
            for row in (rows or [])
        ]
        return {"apps": apps}

    @app.get("/app_version/{app_version_id}/latest_run")
    def latest_run_for_version(
        app_version_id: int,
        _: None = Depends(require_api_key),
    ) -> dict[str, Any]:
        if core_q is None:
            return {"status": "db_unavailable"}
        row = core_q.run_sql(
            """
            SELECT r.session_stamp, r.status, r.ended_at_utc, r.sha256
            FROM static_analysis_runs r
            WHERE r.app_version_id = %s AND r.status='COMPLETED'
            ORDER BY r.id DESC
            LIMIT 1
            """,
            (app_version_id,),
            fetch="one",
        )
        if not row:
            return {"status": "not_found"}
        report_path = _find_report_for_session(row[0]) if row[0] else None
        report_hash = report_path.stem if report_path else None
        if not report_hash and row[3]:
            report_hash = str(row[3])
        return {
            "status": "ok",
            "session_stamp": row[0],
            "ended_at_utc": row[2].isoformat() if row[2] else None,
            "sha256": row[3],
            "report_hash": report_hash,
        }

    @app.get("/report/{report_hash}.json")
    def report_by_hash(report_hash: str, _: None = Depends(require_api_key)) -> FileResponse:
        report_path = _find_report_by_hash(report_hash)
        if report_path is None:
            raise HTTPException(status_code=404, detail="Report not found")
        return FileResponse(report_path, media_type="application/json")

    @app.get("/health/summary")
    def health_summary(_: None = Depends(require_api_key)) -> dict[str, Any]:
        if core_q is None:
            return {"status": "db_unavailable"}
        rows = core_q.run_sql(
            """
            SELECT status, COUNT(*) AS n
            FROM static_analysis_runs
            WHERE ended_at_utc >= (UTC_TIMESTAMP() - INTERVAL 1 DAY)
            GROUP BY status
            """,
            fetch="all",
        )
        running_total = core_q.run_sql(
            """
            SELECT COUNT(*) FROM static_analysis_runs
            WHERE status='RUNNING' AND ended_at_utc IS NULL
            """,
            fetch="one",
        )
        return {
            "status": "ok",
            "last_24h": {row[0]: int(row[1]) for row in (rows or [])},
            "running_total": int(running_total[0]) if running_total else 0,
        }

    @app.post("/maintenance/finalize_stale")
    def finalize_stale(minutes: int = 60, _: None = Depends(require_api_key)) -> dict[str, Any]:
        if core_q is None:
            return {"status": "db_unavailable"}
        threshold = max(1, int(minutes))
        query = """
        UPDATE static_analysis_runs
        SET status='FAILED',
            ended_at_utc=UTC_TIMESTAMP(),
            abort_reason='stale_finalize'
        WHERE status='RUNNING'
          AND ended_at_utc IS NULL
          AND COALESCE(
                STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s.%f'),
                STR_TO_DATE(REPLACE(REPLACE(run_started_utc,'T',' '),'Z',''), '%Y-%m-%d %H:%i:%s')
              ) < (UTC_TIMESTAMP() - INTERVAL %s MINUTE)
        """
        updated = core_q.run_sql_rowcount(query, (threshold,), query_name="api.finalize_stale")
        return {"status": "ok", "updated": updated, "threshold_minutes": threshold}

    @app.get("/run/{session_stamp}/status")
    def run_status(session_stamp: str, _: None = Depends(require_api_key)) -> dict[str, Any]:
        return _collect_run_status(session_stamp)

    @app.get("/run/{session_stamp}/report.json")
    def report_json(session_stamp: str, _: None = Depends(require_api_key)) -> FileResponse:
        report_path = _find_report_for_session(session_stamp)
        if report_path is None:
            raise HTTPException(status_code=404, detail="Report not found")
        return FileResponse(report_path, media_type="application/json")

    @app.get("/run/{session_stamp}/evidence.zip")
    def report_evidence(
        session_stamp: str,
        background_tasks: BackgroundTasks,
        _: None = Depends(require_api_key),
    ) -> FileResponse:
        report_path = _find_report_for_session(session_stamp)
        if report_path is None:
            raise HTTPException(status_code=404, detail="Report not found")

        manifest = {
            "session_stamp": session_stamp,
            "report_path": str(report_path),
        }
        import zipfile

        with tempfile.NamedTemporaryFile(prefix="scytaledroid-evidence-", suffix=".zip", delete=False) as temp_file:
            temp_path = Path(temp_file.name)
        try:
            with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.write(report_path, arcname=report_path.name)
                archive.writestr("manifest.json", json.dumps(manifest, indent=2))
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise

        def _cleanup_temp(path: Path) -> None:
            path.unlink(missing_ok=True)

        background_tasks.add_task(_cleanup_temp, temp_path)
        headers = {"Content-Disposition": f"attachment; filename={session_stamp}_evidence.zip"}
        return FileResponse(temp_path, media_type="application/zip", headers=headers)

    return app


__all__ = ["build_api_app"]
