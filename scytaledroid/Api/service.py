"""FastAPI service definition for ScytaleDroid."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass, replace
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
from typing import TYPE_CHECKING, Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_queries.sql_typed_reads import resolved_static_run_started_at_utc
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
API_KEY_PLACEHOLDER = "change-me"
API_AUTH_DISABLED_ENV = "SCYTALEDROID_API_AUTH_DISABLED"
API_ENV_ENV = "SCYTALEDROID_ENV"
API_AUTH_BYPASS_ENVS = {"test", "development"}
APK_UPLOAD_SUFFIX = ".apk"
APK_MANIFEST_NAME = "AndroidManifest.xml"
UPLOAD_REJECT_EXTENSION = "invalid_extension"
UPLOAD_REJECT_NOT_ZIP = "invalid_apk_zip"
UPLOAD_REJECT_MANIFEST_MISSING = "android_manifest_missing"
UPLOAD_REJECT_CORRUPT_ZIP = "corrupt_apk_zip"
UPLOAD_REJECT_OVERSIZE = "upload_too_large"
UPLOAD_REJECT_METADATA = "metadata_extraction_failed"


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


class ApiAuthConfigError(RuntimeError):
    """Raised when API authentication configuration is unsafe."""


class UploadValidationError(ValueError):
    """Stable API upload rejection with a machine-readable reason code."""

    def __init__(self, reason_code: str, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status_code = status_code


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


def _normalise_upload_filename(filename: str | None) -> str:
    """Return the client basename only; never trust client directory components."""

    raw = str(filename or "upload.apk").replace("\\", "/")
    name = Path(raw).name.strip()
    return name or "upload.apk"


def _validate_upload_filename(filename: str | None) -> str:
    basename = _normalise_upload_filename(filename)
    if Path(basename).suffix.lower() != APK_UPLOAD_SUFFIX:
        raise UploadValidationError(
            UPLOAD_REJECT_EXTENSION,
            "Only single APK uploads with a .apk filename are accepted.",
        )
    return basename


def _validate_apk_container(path: Path) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            try:
                bad_member = archive.testzip()
            except RuntimeError as exc:
                raise UploadValidationError(
                    UPLOAD_REJECT_CORRUPT_ZIP,
                    "APK ZIP structure is corrupt.",
                ) from exc
            if bad_member is not None:
                raise UploadValidationError(
                    UPLOAD_REJECT_CORRUPT_ZIP,
                    "APK ZIP structure is corrupt.",
                )
            names = {name.lstrip("/") for name in archive.namelist()}
    except zipfile.BadZipFile as exc:
        raise UploadValidationError(
            UPLOAD_REJECT_NOT_ZIP,
            "Uploaded file is not a ZIP-compatible APK container.",
        ) from exc
    if APK_MANIFEST_NAME not in names:
        raise UploadValidationError(
            UPLOAD_REJECT_MANIFEST_MISSING,
            "Uploaded APK is missing AndroidManifest.xml.",
        )


def _extract_upload_metadata(apk_path: Path) -> tuple[dict[str, Any], str]:
    try:
        group = _artifact_group_from_path(apk_path)
        artifact = group.artifacts[0] if group.artifacts else None
    except Exception as exc:
        raise UploadValidationError(
            UPLOAD_REJECT_METADATA,
            "APK metadata extraction failed.",
        ) from exc

    metadata: dict[str, Any] = {}
    if artifact is not None:
        metadata.update(dict(artifact.metadata))
    metadata.setdefault("package_name", group.package_name)
    if artifact is not None:
        metadata.setdefault("artifact", artifact.artifact_label)
        metadata.setdefault("is_split_member", artifact.is_split_member)
    return metadata, group.package_name


def _write_upload_sidecar(
    apk_path: Path,
    *,
    upload_id: str,
    original_filename: str | None,
    digest: str,
    extracted_metadata: dict[str, Any],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "upload_id": upload_id,
        "uploaded_filename": _normalise_upload_filename(original_filename),
        "sha256": digest,
        "artifact": "base",
        "artifact_kind": "apk",
        "is_split_member": False,
        "source_kind": "api_upload",
        "canonical_store_path": artifact_store.repo_relative_path(apk_path),
    }
    payload.update(extracted_metadata)
    sidecar_path = apk_path.with_suffix(apk_path.suffix + ".meta.json")
    sidecar_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return payload


def _env_flag(name: str, default: str = "0") -> bool:
    value = os.getenv(name, default).strip().lower()
    return value in {"1", "true", "yes", "on"}


def _resolve_api_key() -> str | None:
    api_key = os.getenv("SCYTALEDROID_API_KEY", "").strip()
    return api_key or None


def _is_placeholder_api_key(api_key: str | None) -> bool:
    return str(api_key or "").strip().lower() == API_KEY_PLACEHOLDER


def _is_loopback_host(host: str | None) -> bool:
    raw = str(host or os.getenv("SCYTALEDROID_API_HOST", "127.0.0.1")).strip().lower()
    if raw in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ip_address(raw).is_loopback
    except ValueError:
        return False


def _api_env_allows_auth_bypass() -> bool:
    env = os.getenv(API_ENV_ENV, "").strip().lower()
    if env in API_AUTH_BYPASS_ENVS:
        return True
    runtime_preset = os.getenv("SCYTALEDROID_RUNTIME_PRESET", "").strip().lower()
    sys_test = os.getenv("SCYTALEDROID_SYS_TEST", "").strip().lower()
    return runtime_preset == "validation" or sys_test in {"1", "true", "yes", "on"}


def _api_auth_disabled() -> bool:
    return _env_flag(API_AUTH_DISABLED_ENV)


def validate_api_auth_config(*, bind_host: str | None = None) -> bool:
    """Validate API authentication policy and return True when auth is disabled intentionally."""

    if _api_auth_disabled():
        if not _api_env_allows_auth_bypass():
            raise ApiAuthConfigError(
                "SCYTALEDROID_API_AUTH_DISABLED=1 requires SCYTALEDROID_ENV=test or "
                "SCYTALEDROID_ENV=development."
            )
        if not _is_loopback_host(bind_host):
            raise ApiAuthConfigError(
                "Unauthenticated API mode is only allowed on loopback bind hosts."
            )
        return True

    api_key = _resolve_api_key()
    if not api_key:
        raise ApiAuthConfigError(
            "SCYTALEDROID_API_KEY is required; refusing to create JSON API without authentication."
        )
    if _is_placeholder_api_key(api_key):
        raise ApiAuthConfigError(
            "SCYTALEDROID_API_KEY uses the documented placeholder value; generate a unique secret."
        )
    return False


def _require_api_key(request: Any, *, auth_disabled: bool = False) -> None:
    from fastapi import HTTPException

    if auth_disabled:
        return
    api_key = _resolve_api_key()
    if not api_key:
        raise HTTPException(status_code=503, detail="API authentication is not configured")
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


def build_api_app(*, bind_host: str | None = None) -> FastAPI:
    if FastAPI is None or File is None or JSONResponse is None:
        raise RuntimeError("FastAPI dependencies are unavailable. Install API extras to use the server.")
    auth_disabled = validate_api_auth_config(bind_host=bind_host)

    app = FastAPI(title="ScytaleDroid API", version=app_config.APP_VERSION)

    upload_file = File(...)

    def require_api_key(request: Request) -> None:
        _require_api_key(request, auth_disabled=auth_disabled)

    @app.post("/upload")
    def upload_apk(
        file: UploadFile = upload_file,
        _: None = Depends(require_api_key),
    ) -> dict[str, Any]:
        upload_dir = artifact_store.upload_inbox_root()
        upload_dir.mkdir(parents=True, exist_ok=True)
        upload_id = uuid.uuid4().hex
        filename = f"{upload_id}.upload{APK_UPLOAD_SUFFIX}"
        destination = upload_dir / filename
        max_bytes = _resolve_max_upload_bytes()
        written = 0

        try:
            original_filename = _validate_upload_filename(file.filename)
            with destination.open("wb") as handle:
                while True:
                    chunk = file.file.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > max_bytes:
                        raise UploadValidationError(
                            UPLOAD_REJECT_OVERSIZE,
                            f"Upload exceeds max size ({max_bytes // (1024 * 1024)} MB).",
                            status_code=413,
                        )
                    handle.write(chunk)

            _validate_apk_container(destination)
            extracted_metadata, _package_name = _extract_upload_metadata(destination)
            digest = _hash_file(destination)
            canonical_path = artifact_store.materialize_apk(
                destination,
                sha256_digest=digest,
                suffix=APK_UPLOAD_SUFFIX,
                move=True,
            )
            metadata = _write_upload_sidecar(
                canonical_path,
                upload_id=upload_id,
                original_filename=original_filename,
                digest=digest,
                extracted_metadata=extracted_metadata,
            )
        except UploadValidationError as exc:
            destination.unlink(missing_ok=True)
            raise HTTPException(
                status_code=exc.status_code,
                detail={"reason_code": exc.reason_code, "message": str(exc)},
            ) from exc
        except Exception:
            destination.unlink(missing_ok=True)
            raise
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

    app.state.scytaledroid_auth_disabled = auth_disabled

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
        started_at_expr = resolved_static_run_started_at_utc("static_analysis_runs")
        query = f"""
        UPDATE static_analysis_runs
        SET status='FAILED',
            ended_at_utc=UTC_TIMESTAMP(),
            abort_reason='stale_finalize'
        WHERE status='RUNNING'
          AND ended_at_utc IS NULL
          AND {started_at_expr} < (UTC_TIMESTAMP() - INTERVAL %s MINUTE)
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
