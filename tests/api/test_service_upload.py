from __future__ import annotations

import json
from pathlib import Path

import pytest

from scytaledroid.Api import service as api_service
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, RepositoryArtifact


def test_upload_writes_sidecar_with_package_identity(monkeypatch, tmp_path):
    testclient = pytest.importorskip("fastapi.testclient")
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
