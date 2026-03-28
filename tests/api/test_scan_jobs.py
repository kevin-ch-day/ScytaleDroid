from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from scytaledroid.Api import service as api_service
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, RepositoryArtifact
from scytaledroid.StaticAnalysis.services.static_service import RunResult


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
    testclient = pytest.importorskip("fastapi.testclient")
    monkeypatch.setattr(api_service.app_config, "DATA_DIR", str(tmp_path))
    with api_service._jobs_lock:
        api_service._jobs.clear()

    apk_path = tmp_path / "device_apks" / "repo_uploads" / "failure.apk"
    apk_path.parent.mkdir(parents=True, exist_ok=True)
    apk_path.write_bytes(b"apk")

    monkeypatch.setattr(api_service, "_artifact_group_from_path", lambda _path: _make_group(apk_path, "com.example.failed"))

    seen: dict[str, object] = {}

    def _fake_run_scan(selection, params, base_dir, *, allow_session_reuse=True, **_kwargs):
        seen["allow_session_reuse"] = allow_session_reuse
        seen["session_stamp"] = params.session_stamp
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
    assert status["state"] == "FAILED"
    assert status["detail"] == "Persistence gate failed."
    assert status["session_stamp"] == "resolved-failed-session"
    assert status["package_name"] == "com.example.failed"


def test_scan_job_marks_ok_when_execution_completes_without_run_outcome(monkeypatch, tmp_path: Path) -> None:
    testclient = pytest.importorskip("fastapi.testclient")
    monkeypatch.setattr(api_service.app_config, "DATA_DIR", str(tmp_path))
    with api_service._jobs_lock:
        api_service._jobs.clear()

    apk_path = tmp_path / "device_apks" / "repo_uploads" / "permissions.apk"
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
