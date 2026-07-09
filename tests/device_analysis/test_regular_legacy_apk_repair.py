from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from scripts.device_analysis import repair_regular_legacy_apks as repair
from scytaledroid.DeviceAnalysis.services import apk_library_service, artifact_store
from tests.device_analysis._harvest_runner_support import isolate_storage_contract


pytestmark = [pytest.mark.unit]


@pytest.fixture(autouse=True)
def _isolate_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    isolate_storage_contract(tmp_path, monkeypatch)


def test_regular_legacy_apk_repair_canonicalizes_and_indexes_without_deleting_legacy_file() -> None:
    data_root = artifact_store.data_root()
    apk_bytes = b"legacy apk bytes"
    digest = sha256(apk_bytes).hexdigest()
    legacy_dir = data_root / "device_apks" / "SER1" / "runs" / "run-1" / "com.example" / "Example_v1"
    legacy_dir.mkdir(parents=True)
    legacy_apk = legacy_dir / "com_example_1__base.apk"
    legacy_apk.write_bytes(apk_bytes)
    (legacy_dir / "harvest_package_manifest.json").write_text(
        json.dumps(
            {
                "package": {
                    "package_name": "com.example",
                    "version_code": "1",
                    "version_name": "1.0",
                    "device_serial": "SER1",
                    "session_label": "run-1",
                },
                "inventory": {
                    "apk_paths": ["/data/app/com.example/base.apk"],
                    "primary_path": "/data/app/com.example/base.apk",
                    "split_count": 1,
                },
                "planning": {
                    "expected_artifacts": [
                        {
                            "file_name": legacy_apk.name,
                            "is_base": True,
                            "planned_source_path": "/data/app/com.example/base.apk",
                            "split_label": "base",
                        }
                    ],
                    "total_paths": 1,
                },
                "execution": {"observed_artifacts": []},
            }
        ),
        encoding="utf-8",
    )

    rows = repair.build_rows(
        data_root=data_root,
        serial="SER1",
        artifact_store=artifact_store,
        apk_library_service=apk_library_service,
    )

    assert len(rows) == 1
    assert rows[0]["action"] == "copy_to_canonical_and_index"
    assert rows[0]["safe_to_canonicalize"] is True

    repair.apply_rows(rows, artifact_store=artifact_store, apk_library_service=apk_library_service)

    canonical = artifact_store.canonical_apk_path(digest)
    assert canonical.exists()
    assert canonical.read_bytes() == apk_bytes
    assert legacy_apk.exists()
    assert rows[0]["applied"] is True
    assert rows[0]["library_manifest_path"]
    assert Path(rows[0]["library_manifest_path"]).exists()
