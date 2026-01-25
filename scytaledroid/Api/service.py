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
        base_dir = Path(app_config.DATA_DIR) / "apks"
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
    from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, StreamingResponse
    from pydantic import BaseModel

    app = FastAPI(title="ScytaleDroid API", version=app_config.APP_VERSION)

    class ScanRequest(BaseModel):
        apk_path: str
        session_stamp: Optional[str] = None
        profile: str = "full"
        scope_label: Optional[str] = None
        allow_session_reuse: bool = True

    @app.post("/upload")
    def upload_apk(file: UploadFile = File(...)) -> dict[str, Any]:
        upload_dir = Path(app_config.DATA_DIR) / "apks" / "repo_uploads"
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
    def root_status() -> HTMLResponse:
        html = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>ScytaleDroid API</title>
    <style>
      body {{
        font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
        background: #f6f3ee;
        color: #1f1d1a;
        margin: 0;
        padding: 32px;
      }}
      .card {{
        background: #ffffff;
        border: 1px solid #e4ddd3;
        border-radius: 16px;
        max-width: 760px;
        padding: 24px;
        box-shadow: 0 12px 30px rgba(46, 39, 30, 0.08);
      }}
      h1 {{
        margin: 0 0 8px;
        font-size: 24px;
      }}
      p {{
        margin: 6px 0 14px;
      }}
      code {{
        background: #f3ede3;
        padding: 2px 6px;
        border-radius: 6px;
      }}
      ul {{
        padding-left: 18px;
      }}
    </style>
  </head>
  <body>
    <div class="card">
      <h1>ScytaleDroid API</h1>
      <p>Status: <strong>ok</strong></p>
      <p>Version: <code>{app_config.APP_VERSION}</code></p>
      <p>Endpoints</p>
      <ul>
        <li><code>POST /upload</code> — upload an APK</li>
        <li><code>POST /scan</code> — start a static scan</li>
        <li><code>GET /job/{{job_id}}</code> — job status</li>
        <li><code>GET /run/{{session_stamp}}/status</code></li>
        <li><code>GET /run/{{session_stamp}}/report.json</code></li>
        <li><code>GET /run/{{session_stamp}}/evidence.zip</code></li>
      </ul>
    </div>
  </body>
</html>
"""
        return HTMLResponse(content=html)

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
