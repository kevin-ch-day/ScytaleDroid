"""FastAPI service definition for ScytaleDroid."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import io
import json
from pathlib import Path
import threading
import time
import uuid
from typing import Any, Optional

from scytaledroid.Config import app_config
from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows.headless_run import (
    _artifact_group_from_path,
    _check_session_uniqueness,
)
from scytaledroid.StaticAnalysis.persistence import list_reports
from scytaledroid.StaticAnalysis.services import static_service
from scytaledroid.StaticAnalysis.session import make_session_stamp, normalize_session_stamp
from scytaledroid.Utils.LoggingUtils import logging_utils as log

try:  # optional database access for status queries
    from scytaledroid.Database.db_core import db_queries as core_q
except Exception:  # pragma: no cover - offline mode
    core_q = None

WEB_DIR = Path(__file__).resolve().parent / "web"


@dataclass
class JobRecord:
    job_id: str
    state: str
    created_at: float
    session_stamp: str
    package_name: str
    detail: Optional[str] = None


_jobs: dict[str, JobRecord] = {}
_jobs_lock = threading.Lock()


def _record_job(job: JobRecord) -> None:
    with _jobs_lock:
        _jobs[job.job_id] = job


def _update_job(job_id: str, *, state: str, detail: Optional[str] = None) -> None:
    with _jobs_lock:
        existing = _jobs.get(job_id)
        if not existing:
            return
        _jobs[job_id] = JobRecord(
            job_id=existing.job_id,
            state=state,
            created_at=existing.created_at,
            session_stamp=existing.session_stamp,
            package_name=existing.package_name,
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


def _find_report_for_session(session_stamp: str) -> Optional[Path]:
    for stored in list_reports():
        meta = stored.report.metadata
        if str(meta.get("session_stamp", "")).strip() == session_stamp:
            return stored.path
    return None


def _find_report_by_hash(report_hash: str) -> Optional[Path]:
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
    try:
        group = _artifact_group_from_path(apk_path)
        selection = ScopeSelection(scope="app", label=scope_label, groups=(group,))
        params = RunParameters(profile=profile, scope="app", scope_label=scope_label)
        params = params.__class__(**{**params.__dict__, "session_stamp": session_stamp})

        _check_session_uniqueness(session_stamp, group.package_name, allow_reuse)
        base_dir = Path(app_config.DATA_DIR) / "device_apks"
        static_service.run_scan(selection, params, base_dir)
        _update_job(job_id, state="OK")
    except Exception as exc:  # pragma: no cover - async path
        log.error(f"API scan failed: {exc}", category="api")
        _update_job(job_id, state="FAILED", detail=str(exc))


def _hash_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def build_api_app() -> "FastAPI":
    from fastapi import FastAPI, File, HTTPException, UploadFile
    from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel

    app = FastAPI(title="ScytaleDroid API", version=app_config.APP_VERSION)
    app.mount("/assets", StaticFiles(directory=WEB_DIR / "assets"), name="assets")

    class ScanRequest(BaseModel):
        apk_path: str
        session_stamp: Optional[str] = None
        profile: str = "full"
        scope_label: Optional[str] = None
        allow_session_reuse: bool = True

    @app.post("/upload")
    def upload_apk(file: UploadFile = File(...)) -> dict[str, Any]:
        upload_dir = Path(app_config.DATA_DIR) / "device_apks" / "repo_uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)
        suffix = Path(file.filename or "upload.apk").suffix or ".apk"
        upload_id = uuid.uuid4().hex
        filename = f"{upload_id}{suffix}"
        destination = upload_dir / filename

        with destination.open("wb") as handle:
            while True:
                chunk = file.file.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)

        digest = _hash_file(destination)
        return {
            "upload_id": upload_id,
            "path": str(destination),
            "sha256": digest,
            "size_bytes": destination.stat().st_size,
        }

    @app.get("/")
    def root_status() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html", media_type="text/html")

    @app.get("/ui/upload")
    def ui_upload() -> FileResponse:
        return FileResponse(WEB_DIR / "upload.html", media_type="text/html")

    @app.get("/ui/jobs")
    def ui_jobs() -> FileResponse:
        return FileResponse(WEB_DIR / "jobs.html", media_type="text/html")

    @app.get("/ui/run")
    def ui_run() -> FileResponse:
        return FileResponse(WEB_DIR / "run.html", media_type="text/html")

    @app.get("/ui/runs")
    def ui_runs() -> FileResponse:
        return FileResponse(WEB_DIR / "runs.html", media_type="text/html")

    @app.get("/ui/apps")
    def ui_apps() -> FileResponse:
        return FileResponse(WEB_DIR / "apps.html", media_type="text/html")

    @app.get("/ui/report")
    def ui_report() -> FileResponse:
        return FileResponse(WEB_DIR / "report.html", media_type="text/html")

    @app.get("/ui/ops")
    def ui_ops() -> FileResponse:
        return FileResponse(WEB_DIR / "ops.html", media_type="text/html")

    @app.post("/scan")
    def scan_apk(payload: ScanRequest) -> JSONResponse:
        apk_path = Path(payload.apk_path).expanduser().resolve()
        if not apk_path.exists():
            raise HTTPException(status_code=404, detail=f"APK not found: {apk_path}")

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

        worker = threading.Thread(
            target=_run_static_scan,
            args=(
                job_id,
                apk_path,
                session_stamp,
                payload.profile,
                scope_label,
                payload.allow_session_reuse,
            ),
            daemon=True,
        )
        worker.start()

        return JSONResponse(
            {
                "job_id": job_id,
                "session_stamp": session_stamp,
                "package_name": group.package_name,
                "state": "QUEUED",
            }
        )

    @app.get("/job/{job_id}")
    def job_status(job_id: str) -> dict[str, Any]:
        with _jobs_lock:
            job = _jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        return _serialize_job(job)

    @app.get("/jobs")
    def jobs_list(limit: int = 25) -> dict[str, Any]:
        with _jobs_lock:
            jobs = list(_jobs.values())
        jobs = sorted(jobs, key=lambda entry: entry.created_at, reverse=True)[:limit]
        return {"jobs": [_serialize_job(job) for job in jobs]}

    @app.get("/runs")
    def runs_list(limit: int = 25) -> dict[str, Any]:
        if core_q is None:
            return {"runs": []}
        rows = core_q.run_sql(
            """
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
            ORDER BY sar.id DESC
            LIMIT %s
            """,
            (limit,),
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
    def apps_list(limit: int = 25) -> dict[str, Any]:
        if core_q is None:
            return {"apps": []}
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

    @app.get("/apps/recent")
    def apps_recent(limit: int = 25) -> dict[str, Any]:
        if core_q is None:
            return {"apps": []}
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
    def latest_run_for_version(app_version_id: int) -> dict[str, Any]:
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
        return {
            "status": "ok",
            "session_stamp": row[0],
            "ended_at_utc": row[2].isoformat() if row[2] else None,
            "sha256": row[3],
            "report_hash": report_hash,
        }

    @app.get("/report/{report_hash}.json")
    def report_by_hash(report_hash: str) -> FileResponse:
        report_path = _find_report_by_hash(report_hash)
        if report_path is None:
            raise HTTPException(status_code=404, detail="Report not found")
        return FileResponse(report_path, media_type="application/json")

    @app.get("/health/summary")
    def health_summary() -> dict[str, Any]:
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
    def finalize_stale(minutes: int = 60) -> dict[str, Any]:
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
        result = core_q.run_sql(query, (threshold,))
        updated = result if isinstance(result, int) else 0
        return {"status": "ok", "updated": updated, "threshold_minutes": threshold}

    @app.get("/run/{session_stamp}/status")
    def run_status(session_stamp: str) -> dict[str, Any]:
        return _collect_run_status(session_stamp)

    @app.get("/run/{session_stamp}/report.json")
    def report_json(session_stamp: str) -> FileResponse:
        report_path = _find_report_for_session(session_stamp)
        if report_path is None:
            raise HTTPException(status_code=404, detail="Report not found")
        return FileResponse(report_path, media_type="application/json")

    @app.get("/run/{session_stamp}/evidence.zip")
    def report_evidence(session_stamp: str) -> StreamingResponse:
        report_path = _find_report_for_session(session_stamp)
        if report_path is None:
            raise HTTPException(status_code=404, detail="Report not found")

        buffer = io.BytesIO()
        payload = report_path.read_bytes()
        manifest = {
            "session_stamp": session_stamp,
            "report_path": str(report_path),
        }
        import zipfile

        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(report_path.name, payload)
            archive.writestr("manifest.json", json.dumps(manifest, indent=2))

        buffer.seek(0)
        headers = {"Content-Disposition": f"attachment; filename={session_stamp}_evidence.zip"}
        return StreamingResponse(buffer, media_type="application/zip", headers=headers)

    return app


__all__ = ["build_api_app"]
