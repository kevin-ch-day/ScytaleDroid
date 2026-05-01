"""iter_manifest_written_hashes coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scytaledroid.Config import app_config


@pytest.fixture(autouse=True)
def _isolate_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path / "data"))


def test_iter_skips_invalid_hex_and_dedupes() -> None:
    from scytaledroid.DeviceAnalysis.evidence_verify.filesystem import iter_manifest_written_hashes

    data = Path.cwd() / "data"
    harvest_base = data / "device_apks"
    d = harvest_base / "Z" / "m"
    d.mkdir(parents=True)
    digest_ok = "c" * 64
    doc = {
        "package": {"package_name": "a.b"},
        "execution": {
            "observed_artifacts": [
                {"pull_outcome": "written", "sha256": "not-64-hex"},
                {"pull_outcome": "written", "sha256": digest_ok},
                {"pull_outcome": "written", "sha256": digest_ok},
                {"pull_outcome": "skipped", "sha256": digest_ok},
            ]
        },
    }
    (d / "harvest_package_manifest.json").write_text(json.dumps(doc), encoding="utf-8")

    rows = iter_manifest_written_hashes(harvest_root=harvest_base, data_root=data)
    assert len(rows) == 1
    assert rows[0][2] == digest_ok
