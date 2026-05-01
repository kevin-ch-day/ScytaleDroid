from __future__ import annotations

import os
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.services import artifact_store


def test_materialize_apk_moves_into_canonical_store(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")

    source = tmp_path / "data" / "inbox" / "uploads" / "upload.apk"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"apk-bytes")
    digest = "a" * 64

    stored = artifact_store.materialize_apk(
        source,
        sha256_digest=digest,
        move=True,
    )

    expected = tmp_path / "data" / "store" / "apk" / "sha256" / "aa" / f"{digest}.apk"
    assert stored == expected
    assert stored.exists()
    assert not source.exists()


def test_materialize_apk_reuses_existing_store_copy(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")

    digest = "b" * 64
    stored = artifact_store.canonical_apk_path(digest)
    stored.parent.mkdir(parents=True, exist_ok=True)
    stored.write_bytes(b"first-copy")

    source = tmp_path / "second.apk"
    source.write_bytes(b"second-copy")

    resolved = artifact_store.materialize_apk(source, sha256_digest=digest, move=True)

    assert resolved == stored.resolve()
    assert stored.read_bytes() == b"first-copy"
    assert not source.exists()


def test_write_receipts_use_stable_paths(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", "data")

    harvest_path = artifact_store.write_harvest_receipt(
        session_label="20260328-rda-full",
        package_name="com.example.app",
        payload={"schema": "test"},
    )
    upload_path = artifact_store.write_upload_receipt(
        upload_id="upload-1",
        payload={"schema": "upload"},
    )

    assert harvest_path == (
        tmp_path / "data" / "receipts" / "harvest" / "20260328-rda-full" / "com.example.app.json"
    )
    assert upload_path == tmp_path / "data" / "receipts" / "upload" / "upload-1.json"
    assert harvest_path.exists()
    assert upload_path.exists()
