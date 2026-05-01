from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DeviceAnalysis.harvest import replay


class _FakeRepo:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []
        self.next_apk_id = 500

    def ensure_storage_root(self, *args, **kwargs):
        self.calls.append(("ensure_storage_root", args, kwargs))
        return 41

    def ensure_app_definition(self, *args, **kwargs):
        self.calls.append(("ensure_app_definition", args, kwargs))
        return 17

    def ensure_split_group(self, *args, **kwargs):
        self.calls.append(("ensure_split_group", args, kwargs))
        return 93

    class ApkRecord:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    def upsert_apk_record(self, record, **kwargs):
        self.calls.append(("upsert_apk_record", (record.kwargs,), kwargs))
        self.next_apk_id += 1
        return self.next_apk_id

    def upsert_artifact_path(self, *args, **kwargs):
        self.calls.append(("upsert_artifact_path", args, kwargs))

    def upsert_source_path(self, *args, **kwargs):
        self.calls.append(("upsert_source_path", args, kwargs))


def _write_manifest(
    root: Path,
    *,
    persistence_status: str = "mirror_failed",
    local_artifact_path: str,
) -> Path:
    manifest_path = root / "SERIAL123" / "20260328" / "com.example.app" / "harvest_package_manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "harvest_package_manifest_v1",
        "execution_state": "completed",
        "package": {
            "package_name": "com.example.app",
            "app_label": "Example",
            "version_name": "1.0",
            "version_code": "100",
            "device_serial": "SERIAL123",
            "session_label": "20260328",
        },
        "inventory": {
            "installer": "com.android.vending",
            "category": "user",
            "profile_key": "RDA",
            "profile_name": "Research Dataset Alpha",
        },
        "planning": {
            "expected_artifacts": [
                {
                    "artifact_index": 1,
                    "artifact_total": 1,
                    "split_label": "base",
                    "file_name": "base.apk",
                    "is_base": True,
                    "planned_source_path": "/data/app/com.example.app/base.apk",
                }
            ]
        },
        "execution": {
            "observed_artifacts": [
                {
                    "split_label": "base",
                    "file_name": "base.apk",
                    "is_base": True,
                    "local_artifact_path": local_artifact_path,
                    "observed_source_path": "/data/app/com.example.app/base.apk",
                    "sha256": "a" * 64,
                    "file_size": 4,
                    "pulled_at": "2026-03-28T10:00:00Z",
                    "pull_outcome": "written",
                    "mirror_failure_reasons": ["artifact_path_failed"],
                }
            ],
            "mirror_failure_reasons": ["artifact_path_failed"],
        },
        "status": {
            "capture_status": "clean",
            "persistence_status": persistence_status,
            "research_status": "pending_audit",
        },
        "comparison": {
            "matches_planned_artifacts": True,
            "observed_hashes_complete": True,
        },
    }
    manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return manifest_path


def test_replay_package_manifest_repairs_mirror_failed_package(tmp_path: Path, monkeypatch) -> None:
    artifact_path = tmp_path / "device_apks" / "SERIAL123" / "20260328" / "com.example.app" / "base.apk"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_bytes(b"apk\n")
    manifest_path = _write_manifest(
        tmp_path / "device_apks",
        local_artifact_path="SERIAL123/20260328/com.example.app/base.apk",
    )
    fake_repo = _FakeRepo()

    monkeypatch.setattr(replay.common, "resolve_storage_root", lambda: ("test-host", str(tmp_path / "device_apks")))

    outcome = replay.replay_package_manifest(manifest_path, repo_module=fake_repo)

    assert outcome.succeeded is True
    assert outcome.status == "replayed"
    assert outcome.replayed_artifacts == 1
    assert outcome.failed_artifacts == 0
    assert outcome.updated_manifest is True
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert payload["status"]["persistence_status"] == "mirrored"
    assert payload["repairs"][-1]["status"] == "replayed"
    assert any(call[0] == "ensure_app_definition" for call in fake_repo.calls)
    assert any(call[0] == "upsert_apk_record" for call in fake_repo.calls)
    assert any(call[0] == "upsert_artifact_path" for call in fake_repo.calls)
    assert any(call[0] == "upsert_source_path" for call in fake_repo.calls)


def test_replay_package_manifest_skips_non_mirror_failed_package(tmp_path: Path, monkeypatch) -> None:
    artifact_path = tmp_path / "device_apks" / "SERIAL123" / "20260328" / "com.example.app" / "base.apk"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_bytes(b"apk\n")
    manifest_path = _write_manifest(
        tmp_path / "device_apks",
        persistence_status="mirrored",
        local_artifact_path="SERIAL123/20260328/com.example.app/base.apk",
    )
    fake_repo = _FakeRepo()

    monkeypatch.setattr(replay.common, "resolve_storage_root", lambda: ("test-host", str(tmp_path / "device_apks")))

    outcome = replay.replay_package_manifest(manifest_path, repo_module=fake_repo)

    assert outcome.status == "skipped"
    assert outcome.failure_reasons == ["persistence_status_not_mirror_failed"]
    assert fake_repo.calls == []


def test_replay_package_manifest_fails_when_artifact_is_missing(tmp_path: Path, monkeypatch) -> None:
    manifest_path = _write_manifest(
        tmp_path / "device_apks",
        local_artifact_path="SERIAL123/20260328/com.example.app/base.apk",
    )
    fake_repo = _FakeRepo()

    monkeypatch.setattr(replay.common, "resolve_storage_root", lambda: ("test-host", str(tmp_path / "device_apks")))

    outcome = replay.replay_package_manifest(manifest_path, repo_module=fake_repo)

    assert outcome.status == "failed"
    assert outcome.failed_artifacts == 1
    assert "artifact_file_missing" in outcome.failure_reasons
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert payload["status"]["persistence_status"] == "mirror_failed"
    assert payload["repairs"][-1]["status"] == "failed"
