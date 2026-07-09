from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Api import service as api_service
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, RepositoryArtifact
from scytaledroid.StaticAnalysis.services.static_service import RunResult
from tests.api.helpers import require_fastapi_testclient


def _make_group(apk_path: Path, package_name: str) -> ArtifactGroup:
    artifact = RepositoryArtifact(
        path=apk_path,
        display_path=apk_path.name,
        metadata={
            "package_name": package_name,
            "version_code": "1",
            "version_name": "1.0",
        },
    )
    return ArtifactGroup(
        group_key=f"{package_name}:1.0",
        package_name=package_name,
        version_display="1.0",
        session_stamp=None,
        capture_id="api-test",
        artifacts=(artifact,),
    )


def _make_run_result(
    *,
    completed: bool,
    session_stamp: str,
    detail: str | None,
) -> RunResult:
    return RunResult(
        outcome=None,
        completed=completed,
        session_stamp=session_stamp,
        session_label=session_stamp,
        detail=detail,
        pipeline_version="2.0.0-alpha",
        catalog_versions=None,
        config_hash=None,
        study_tag=None,
        run_started_utc=datetime.now(UTC),
    )


def test_scan_job_marks_failed_when_run_does_not_complete(monkeypatch, tmp_path: Path) -> None:
    testclient = require_fastapi_testclient()
    monkeypatch.setattr(api_service.app_config, "DATA_DIR", str(tmp_path))
    with api_service._jobs_lock:
        api_service._jobs.clear()

    apk_path = tmp_path / "store" / "apk" / "sha256" / "aa" / "failure.apk"
    apk_path.parent.mkdir(parents=True, exist_ok=True)
    apk_path.write_bytes(b"apk")

    monkeypatch.setattr(api_service, "_artifact_group_from_path", lambda _path: _make_group(apk_path, "com.example.failed"))

    seen: dict[str, object] = {}

    def _fake_run_scan(selection, params, base_dir, *, allow_session_reuse=True, **_kwargs):
        seen["allow_session_reuse"] = allow_session_reuse
        seen["session_stamp"] = params.session_stamp
        seen["paper_grade_requested"] = params.paper_grade_requested
        return _make_run_result(
            completed=False,
            session_stamp="resolved-failed-session",
            detail="Persistence gate failed.",
        )

    monkeypatch.setattr(api_service.static_service, "run_scan", _fake_run_scan)
    monkeypatch.setattr(
        api_service,
        "_start_scan_worker",
        lambda *args, **kwargs: api_service._run_static_scan(*args, **kwargs),
    )

    client = testclient.TestClient(api_service.build_api_app())
    response = client.post(
        "/scan",
        json={
            "apk_path": str(apk_path),
            "session_stamp": "requested-session",
            "profile": "full",
            "allow_session_reuse": False,
        },
    )

    assert response.status_code == 200
    job_id = response.json()["job_id"]
    status = client.get(f"/job/{job_id}").json()
    assert seen["allow_session_reuse"] is False
    assert seen["session_stamp"] == "requested-session"
    assert seen["paper_grade_requested"] is False
    assert status["state"] == "FAILED"
    assert status["detail"] == "Persistence gate failed."
    assert status["session_stamp"] == "resolved-failed-session"
    assert status["package_name"] == "com.example.failed"


def test_scan_job_marks_ok_when_execution_completes_without_run_outcome(monkeypatch, tmp_path: Path) -> None:
    testclient = require_fastapi_testclient()
    monkeypatch.setattr(api_service.app_config, "DATA_DIR", str(tmp_path))
    with api_service._jobs_lock:
        api_service._jobs.clear()

    apk_path = tmp_path / "store" / "apk" / "sha256" / "bb" / "permissions.apk"
    apk_path.parent.mkdir(parents=True, exist_ok=True)
    apk_path.write_bytes(b"apk")

    monkeypatch.setattr(
        api_service,
        "_artifact_group_from_path",
        lambda _path: _make_group(apk_path, "com.example.permissions"),
    )
    monkeypatch.setattr(
        api_service.static_service,
        "run_scan",
        lambda *_args, **_kwargs: _make_run_result(
            completed=True,
            session_stamp="resolved-ok-session",
            detail=None,
        ),
    )
    monkeypatch.setattr(
        api_service,
        "_start_scan_worker",
        lambda *args, **kwargs: api_service._run_static_scan(*args, **kwargs),
    )

    client = testclient.TestClient(api_service.build_api_app())
    response = client.post(
        "/scan",
        json={
            "apk_path": str(apk_path),
            "session_stamp": "requested-session",
            "profile": "permissions",
        },
    )

    assert response.status_code == 200
    job_id = response.json()["job_id"]
    status = client.get(f"/job/{job_id}").json()
    assert status["state"] == "OK"
    assert status["detail"] is None
    assert status["session_stamp"] == "resolved-ok-session"
    assert status["package_name"] == "com.example.permissions"


def test_finalize_stale_prefers_typed_started_at_expression(monkeypatch) -> None:
    testclient = require_fastapi_testclient()
    monkeypatch.delenv("SCYTALEDROID_API_KEY", raising=False)

    captured: dict[str, object] = {}

    def _fake_rowcount(sql, params=(), **_kwargs):
        captured["sql"] = sql
        captured["params"] = params
        return 4

    monkeypatch.setattr(api_service.core_q, "run_sql_rowcount", _fake_rowcount)

    client = testclient.TestClient(api_service.build_api_app())
    response = client.post("/maintenance/finalize_stale?minutes=90")

    assert response.status_code == 200
    assert response.json()["updated"] == 4
    assert captured["params"] == (90,)
    sql = str(captured["sql"])
    assert "run_started_at_utc" in sql
    assert "UTC_TIMESTAMP() - INTERVAL %s MINUTE" in sql


def test_upload_writes_sidecar_with_package_identity(monkeypatch, tmp_path: Path) -> None:
    testclient = require_fastapi_testclient()
    monkeypatch.setattr(api_service.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    artifact = RepositoryArtifact(
        path=tmp_path / "placeholder.apk",
        display_path="placeholder.apk",
        metadata={
            "package_name": "com.example.upload",
            "version_code": "77",
            "version_name": "7.7.0",
            "app_label": "Example Upload",
        },
    )
    group = ArtifactGroup(
        group_key="com.example.upload:7.7.0",
        package_name="com.example.upload",
        version_display="7.7.0",
        session_stamp=None,
        capture_id="legacy-upload",
        artifacts=(artifact,),
    )
    monkeypatch.setattr(api_service, "_artifact_group_from_path", lambda _path: group)

    client = testclient.TestClient(api_service.build_api_app())
    response = client.post(
        "/upload",
        files={"file": ("example.apk", b"fake apk bytes", "application/vnd.android.package-archive")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["package_name"] == "com.example.upload"
    stored_path = Path(payload["path"])
    assert stored_path == tmp_path / "store" / "apk" / "sha256" / payload["sha256"][:2] / f"{payload['sha256']}.apk"
    sidecar = stored_path.with_suffix(".apk.meta.json")
    metadata = json.loads(sidecar.read_text(encoding="utf-8"))
    assert metadata["package_name"] == "com.example.upload"
    assert metadata["version_code"] == "77"
    assert metadata["canonical_store_path"] == stored_path.relative_to(tmp_path).as_posix()
    receipt = tmp_path / payload["receipt_path"]
    assert receipt.exists()
