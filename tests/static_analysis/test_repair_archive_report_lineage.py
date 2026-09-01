from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load_module():
    path = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "static_analysis"
        / "repair_archive_report_lineage.py"
    )
    spec = importlib.util.spec_from_file_location("repair_archive_report_lineage", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_report(path: Path, metadata: dict[str, object]) -> None:
    path.write_text(
        json.dumps({"metadata": metadata, "findings": [{"id": "unchanged"}]}, indent=2),
        encoding="utf-8",
    )


def test_lineage_repair_uses_unanimous_siblings_and_preserves_payload(tmp_path: Path) -> None:
    module = _load_module()
    base_sha = "a" * 64
    split_sha = "b" * 64
    shared = {
        "package_name": "com.example.app",
        "session_stamp": "session-1",
        "execution_id": "exec-1",
        "base_apk_sha256": base_sha,
        "artifact_set_hash": "c" * 64,
        "artifact_manifest_sha256": "d" * 64,
        "identity_valid": True,
    }
    base_path = tmp_path / f"{base_sha}.json"
    split_path = tmp_path / f"{split_sha}.json"
    _write_report(
        base_path,
        {
            "package_name": "com.example.app",
            "session_stamp": "session-1",
            "sha256": base_sha,
            "is_split_member": False,
        },
    )
    _write_report(
        split_path,
        {**shared, "sha256": split_sha, "is_split_member": True},
    )

    repairs = module.plan_repairs(tmp_path, session="session-1")
    assert len(repairs) == 1
    assert repairs[0]["additions"] == {
        key: shared[key] for key in module.LINEAGE_FIELDS
    }

    rows = module.apply_repairs(repairs, backup_dir=tmp_path / "backups")
    repaired = json.loads(base_path.read_text(encoding="utf-8"))
    assert repaired["findings"] == [{"id": "unchanged"}]
    assert all(repaired["metadata"][key] == shared[key] for key in module.LINEAGE_FIELDS)
    assert rows[0]["non_metadata_payload_sha256_before"] == rows[0]["non_metadata_payload_sha256_after"]
    assert (tmp_path / "backups" / base_path.name).is_file()


def test_latest_mirror_repair_requires_matching_analytical_payload(tmp_path: Path) -> None:
    module = _load_module()
    archive_dir = tmp_path / "archive"
    latest_dir = tmp_path / "latest"
    archive_dir.mkdir()
    latest_dir.mkdir()
    digest = "a" * 64
    complete = {
        "package_name": "com.example.app",
        "session_stamp": "session-1",
        "sha256": digest,
        "is_split_member": False,
        "execution_id": "exec-1",
        "base_apk_sha256": digest,
        "artifact_set_hash": "b" * 64,
        "artifact_manifest_sha256": "c" * 64,
        "identity_valid": True,
    }
    _write_report(archive_dir / f"{digest}.json", complete)
    _write_report(
        latest_dir / f"{digest}.json",
        {
            key: value
            for key, value in complete.items()
            if key not in module.LINEAGE_FIELDS
        },
    )

    repairs = module.plan_latest_mirror_repairs(archive_dir, latest_dir)

    assert len(repairs) == 1
    assert repairs[0]["additions"] == {
        key: complete[key] for key in module.LINEAGE_FIELDS
    }
