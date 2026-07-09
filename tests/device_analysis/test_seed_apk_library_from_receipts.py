from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from scripts.device_analysis import seed_apk_library_from_receipts as seed
from scytaledroid.Config import app_config
from scytaledroid.DeviceAnalysis.services import apk_library_service, artifact_store
from tests.device_analysis._harvest_runner_support import isolate_storage_contract


pytestmark = [pytest.mark.unit]


@pytest.fixture(autouse=True)
def _isolate_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    isolate_storage_contract(tmp_path, monkeypatch)


def _stored_apk(digest: str, content: bytes = b"apk") -> str:
    path = artifact_store.canonical_apk_path(digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return artifact_store.repo_relative_path(path)


def _write_receipt(session: str = "run-1", digest: str = "a" * 64) -> Path:
    canonical = _stored_apk(digest)
    receipt = Path(app_config.DATA_DIR) / "receipts" / "harvest" / session / "com.example.app.json"
    receipt.parent.mkdir(parents=True)
    receipt.write_text(
        json.dumps(
            {
                "package": {
                    "app_label": "Example",
                    "package_name": "com.example.app",
                    "version_code": "1",
                    "version_name": "1.0",
                    "device_serial": "SER",
                    "session_label": session,
                },
                "inventory": {
                    "apk_paths": ["/data/app/com.example.app/base.apk"],
                    "primary_path": "/data/app/com.example.app/base.apk",
                    "split_count": 1,
                },
                "planning": {
                    "expected_artifacts": [
                        {
                            "file_name": "com_example_app_1__base.apk",
                            "is_base": True,
                            "planned_source_path": "/data/app/com.example.app/base.apk",
                            "split_label": "base",
                        }
                    ],
                    "total_paths": 1,
                },
                "execution": {
                    "observed_artifacts": [
                        {
                            "file_name": "com_example_app_1__base.apk",
                            "split_label": "base",
                            "is_base": True,
                            "sha256": digest,
                            "file_size": 3,
                            "canonical_store_path": canonical,
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    return receipt


def test_seed_dry_run_marks_existing_receipt_already_indexed(tmp_path: Path) -> None:
    receipt = _write_receipt()
    assert apk_library_service.register_legacy_receipt(receipt) is not None
    output_dir = tmp_path / "seed-report"

    result = seed.main(["--receipts-root", str(receipt.parents[1]), "--output-dir", str(output_dir)])

    assert result == 0
    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    rows = list(csv.DictReader((output_dir / "apk_library_seed_receipts.csv").open(newline="", encoding="utf-8")))
    assert summary["seedable_receipts"] == 1
    assert summary["already_indexed_receipts"] == 1
    assert summary["applied_receipts"] == 0
    assert rows[0]["reason"] == "already_indexed"


def test_seed_dry_run_include_existing_reports_seedable(tmp_path: Path) -> None:
    receipt = _write_receipt()
    assert apk_library_service.register_legacy_receipt(receipt) is not None
    output_dir = tmp_path / "seed-report"

    result = seed.main(
        [
            "--receipts-root",
            str(receipt.parents[1]),
            "--output-dir",
            str(output_dir),
            "--include-existing",
        ]
    )

    assert result == 0
    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    rows = list(csv.DictReader((output_dir / "apk_library_seed_receipts.csv").open(newline="", encoding="utf-8")))
    assert summary["already_indexed_receipts"] == 0
    assert rows[0]["reason"] == "seedable"


def test_seed_dry_run_blocks_planned_hash_content_collision(tmp_path: Path) -> None:
    indexed_receipt = _write_receipt(session="run-1", digest="a" * 64)
    colliding_receipt = _write_receipt(session="run-2", digest="b" * 64)
    assert apk_library_service.register_legacy_receipt(indexed_receipt) is not None
    output_dir = tmp_path / "seed-report"

    result = seed.main(["--receipts-root", str(indexed_receipt.parents[1]), "--output-dir", str(output_dir)])

    assert result == 0
    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    rows = list(csv.DictReader((output_dir / "apk_library_seed_receipts.csv").open(newline="", encoding="utf-8")))
    by_session = {row["session"]: row for row in rows}
    assert summary["planned_split_set_hash_collisions"] == 1
    assert by_session["run-1"]["reason"] == "already_indexed"
    assert by_session["run-2"]["reason"] == "planned_split_set_hash_collision"
    assert by_session["run-2"]["planned_hash_collision"] == "True"
    assert by_session["run-2"]["existing_manifest_path"]
    assert by_session["run-2"]["existing_content_split_set_hash"]
    assert colliding_receipt.exists()


def test_seed_apply_can_index_planned_hash_content_variant(tmp_path: Path) -> None:
    indexed_receipt = _write_receipt(session="run-1", digest="a" * 64)
    _write_receipt(session="run-2", digest="b" * 64)
    assert apk_library_service.register_legacy_receipt(indexed_receipt) is not None
    output_dir = tmp_path / "seed-report"

    result = seed.main(
        [
            "--receipts-root",
            str(indexed_receipt.parents[1]),
            "--output-dir",
            str(output_dir),
            "--include-content-variants",
            "--apply",
        ]
    )

    assert result == 0
    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    rows = list(csv.DictReader((output_dir / "apk_library_seed_receipts.csv").open(newline="", encoding="utf-8")))
    by_session = {row["session"]: row for row in rows}
    assert summary["applied_receipts"] == 1
    assert summary["planned_split_set_hash_collisions"] == 0
    assert by_session["run-2"]["reason"] == "content_variant_seedable"
    assert by_session["run-2"]["applied"] == "True"
    assert "/content_variants/" in by_session["run-2"]["library_manifest_path"]
