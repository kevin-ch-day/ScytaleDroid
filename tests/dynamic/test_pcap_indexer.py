from __future__ import annotations

from pathlib import Path

import pytest
from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.core.manifest import ArtifactRecord, RunManifest
from scytaledroid.DynamicAnalysis.pcap.indexer import PcapIndexConfig, index_pcap_by_app


def _dataset_manifest(*, relative_path: str, package_name: str, size_bytes: int) -> RunManifest:
    return RunManifest(
        run_manifest_version=1,
        dynamic_run_id="run-1",
        created_at="2026-06-15T00:00:00Z",
        operator={"tier": "dataset"},
        target={"package_name": package_name},
        artifacts=[
            ArtifactRecord(
                relative_path=relative_path,
                type="pcapdroid_capture",
                produced_by="pcapdroid_capture",
                size_bytes=size_bytes,
            )
        ],
    )


def test_index_pcap_rejects_relative_path_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    secret = tmp_path / "secret.pcap"
    secret.write_bytes(b"P" * 2048)
    manifest = _dataset_manifest(
        relative_path="../secret.pcap",
        package_name="com.example.app",
        size_bytes=2048,
    )
    assert index_pcap_by_app(manifest, run_dir, config=PcapIndexConfig(min_bytes=1)) is None
    by_app = tmp_path / "data" / "archive" / "pcap" / "by_app"
    assert not by_app.exists() or not any(by_app.rglob("*.pcap"))


def test_index_pcap_keeps_package_dir_inside_by_app(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))
    run_dir = tmp_path / "run"
    capture_dir = run_dir / "artifacts"
    capture_dir.mkdir(parents=True)
    pcap = capture_dir / "app.pcap"
    pcap.write_bytes(b"P" * 2048)
    manifest = _dataset_manifest(
        relative_path="artifacts/app.pcap",
        package_name="../etc/passwd",
        size_bytes=2048,
    )
    result = index_pcap_by_app(manifest, run_dir, config=PcapIndexConfig(min_bytes=1))
    assert result is not None
    by_app = (tmp_path / "data" / "archive" / "pcap" / "by_app").resolve()
    assert result.resolve().is_relative_to(by_app)
    assert ".." not in result.parts


def test_index_pcap_preserves_dotted_package_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))
    run_dir = tmp_path / "run"
    capture_dir = run_dir / "artifacts"
    capture_dir.mkdir(parents=True)
    pcap = capture_dir / "app.pcap"
    pcap.write_bytes(b"P" * 2048)
    manifest = _dataset_manifest(
        relative_path="artifacts/app.pcap",
        package_name="com.example.app",
        size_bytes=2048,
    )
    result = index_pcap_by_app(manifest, run_dir, config=PcapIndexConfig(min_bytes=1))
    assert result is not None
    assert result.parent.name == "com.example.app"
