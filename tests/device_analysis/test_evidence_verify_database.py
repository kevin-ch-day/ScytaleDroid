"""Harvest evidence DB alignment (manifest SHA-256 vs android_apk_repository)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scytaledroid.Config import app_config


@pytest.fixture(autouse=True)
def _isolate_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))


def test_db_verify_warns_when_sha256_absent_from_repo(monkeypatch: pytest.MonkeyPatch) -> None:
    from scytaledroid.Database.db_func.harvest import apk_repository as repo
    from scytaledroid.DeviceAnalysis.evidence_verify.database import verify_harvest_db_alignment

    monkeypatch.setattr(repo, "get_apk_by_sha256", lambda _sha256: None)

    data = Path.cwd() / "data"
    harvest_base = data / "device_apks"
    pkg_dir = harvest_base / "S" / "runs" / "r1" / "com.example.db" / "App_1"
    pkg_dir.mkdir(parents=True)
    digest = "a" * 64
    doc = {
        "schema": "harvest_package_manifest_v1",
        "package": {"package_name": "com.example.db"},
        "execution": {
            "observed_artifacts": [
                {
                    "pull_outcome": "written",
                    "sha256": digest,
                    "local_artifact_path": "S/runs/r1/com.example.db/App_1/x.apk",
                }
            ]
        },
    }
    manifest_path = pkg_dir / "harvest_package_manifest.json"
    manifest_path.write_text(json.dumps(doc), encoding="utf-8")

    issues, exit_code = verify_harvest_db_alignment(harvest_root=harvest_base, data_root=data)
    assert exit_code == 0
    assert len(issues) == 1
    assert issues[0].code == "db_missing_apk_sha256"
    assert issues[0].severity == "warning"


def test_db_verify_warns_on_package_name_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    from scytaledroid.Database.db_func.harvest import apk_repository as repo
    from scytaledroid.DeviceAnalysis.evidence_verify.database import verify_harvest_db_alignment

    monkeypatch.setattr(
        repo,
        "get_apk_by_sha256",
        lambda sha256: {"package_name": "com.other.app", "sha256": sha256},
    )

    data = Path.cwd() / "data"
    harvest_base = data / "device_apks"
    pkg_dir = harvest_base / "S" / "runs" / "r1" / "com.manifest.pkg" / "App_1"
    pkg_dir.mkdir(parents=True)
    digest = "b" * 64
    doc = {
        "package": {"package_name": "com.manifest.pkg"},
        "execution": {
            "observed_artifacts": [{"pull_outcome": "written", "sha256": digest}],
        },
    }
    (pkg_dir / "harvest_package_manifest.json").write_text(json.dumps(doc), encoding="utf-8")

    issues, _code = verify_harvest_db_alignment(harvest_root=harvest_base, data_root=data)
    assert any(i.code == "db_package_name_mismatch" for i in issues)


def _minimal_manifest_pkg(harvest_base: Path, digest: str) -> None:
    pkg_dir = harvest_base / "S" / "runs" / "r1" / "com.example.db" / "App_1"
    pkg_dir.mkdir(parents=True)
    doc = {
        "package": {"package_name": "com.example.db"},
        "execution": {
            "observed_artifacts": [{"pull_outcome": "written", "sha256": digest}],
        },
    }
    (pkg_dir / "harvest_package_manifest.json").write_text(json.dumps(doc), encoding="utf-8")


def test_db_verify_returns_error_on_database_engine_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from scytaledroid.Database.db_core import DatabaseError
    from scytaledroid.Database.db_func.harvest import apk_repository as repo
    from scytaledroid.DeviceAnalysis.evidence_verify.database import verify_harvest_db_alignment

    def _fail(_digest: str) -> None:
        raise DatabaseError("connection refused")

    monkeypatch.setattr(repo, "get_apk_by_sha256", _fail)

    data = Path.cwd() / "data"
    harvest_base = data / "device_apks"
    _minimal_manifest_pkg(harvest_base, "d" * 64)

    issues, exit_code = verify_harvest_db_alignment(harvest_root=harvest_base, data_root=data)
    assert exit_code == 1
    assert len(issues) == 1
    assert issues[0].severity == "error"
    assert issues[0].code == "db_query_failed"


def test_db_verify_maps_disabled_database_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    from scytaledroid.Database.db_func.harvest import apk_repository as repo
    from scytaledroid.DeviceAnalysis.evidence_verify.database import verify_harvest_db_alignment

    def _fail(_digest: str) -> None:
        raise RuntimeError("Database is disabled. Configure SCYTALEDROID_DB_URL (mysql/mariadb).")

    monkeypatch.setattr(repo, "get_apk_by_sha256", _fail)

    data = Path.cwd() / "data"
    harvest_base = data / "device_apks"
    _minimal_manifest_pkg(harvest_base, "e" * 64)

    issues, exit_code = verify_harvest_db_alignment(harvest_root=harvest_base, data_root=data)
    assert exit_code == 1
    assert issues[0].code == "db_disabled_or_unconfigured"
