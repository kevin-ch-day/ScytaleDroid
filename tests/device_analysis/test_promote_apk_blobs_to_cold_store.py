from __future__ import annotations

import csv
import json
from hashlib import sha256
from pathlib import Path

from scripts.device_analysis import promote_apk_blobs_to_cold_store as promote


def _write_hot(tmp_path: Path, payload: bytes = b"apk") -> tuple[Path, Path, str]:
    data_root = tmp_path / "data"
    digest = sha256(payload).hexdigest()
    local = data_root / "store" / "apk" / "sha256" / digest[:2] / f"{digest}.apk"
    local.parent.mkdir(parents=True)
    local.write_bytes(payload)
    return data_root, local, digest


def _input(*, sha: str, local: Path, cold: Path, promotion_class: str = promote.ELIGIBLE_CLASS) -> promote.PromotionInput:
    return promote.PromotionInput(
        sha256=sha,
        size_bytes=local.stat().st_size if local.exists() and not local.is_symlink() else 0,
        package_name="com.example.app",
        version_code="1",
        version_name="1.0",
        local_path=local.as_posix(),
        cold_path=cold.as_posix(),
        promotion_class=promotion_class,
    )


def _cold_path(cold_root: Path, sha: str) -> Path:
    return cold_root / "data" / "store" / "apk" / "sha256" / sha[:2] / f"{sha}.apk"


def test_dry_run_does_not_mutate(tmp_path: Path) -> None:
    data_root, local, digest = _write_hot(tmp_path)
    mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    cold_root = mount / "scytaledroid_artifacts" / "apk_store" / "cold"
    cold = _cold_path(cold_root, digest)

    actions, blocked, _verification = promote.plan_or_apply(
        [_input(sha=digest, local=local, cold=cold)],
        data_root=data_root,
        cold_root=cold_root,
        mount_root=mount,
        apply=False,
        is_mount=lambda path: Path(path) == mount,
    )

    assert not blocked
    assert actions[0].status == "planned"
    assert local.is_file()
    assert not local.is_symlink()
    assert not cold.exists()


def test_verified_dry_run_hashes_local_blob_without_mutating(tmp_path: Path) -> None:
    data_root, local, digest = _write_hot(tmp_path, b"payload")
    mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    cold_root = mount / "scytaledroid_artifacts" / "apk_store" / "cold"
    cold = _cold_path(cold_root, digest)

    actions, blocked, _verification = promote.plan_or_apply(
        [_input(sha=digest, local=local, cold=cold)],
        data_root=data_root,
        cold_root=cold_root,
        mount_root=mount,
        apply=False,
        verify_hashes=True,
        is_mount=lambda path: Path(path) == mount,
    )

    assert not blocked
    assert actions[0].status == "planned"
    assert actions[0].hash_verified_before is True
    assert actions[0].hash_verified_after is False
    assert local.is_file()
    assert not cold.exists()


def test_verified_dry_run_blocks_local_hash_mismatch(tmp_path: Path) -> None:
    data_root, local, digest = _write_hot(tmp_path, b"payload")
    local.write_bytes(b"changed")
    mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    cold_root = mount / "scytaledroid_artifacts" / "apk_store" / "cold"
    cold = _cold_path(cold_root, digest)

    actions, blocked, _verification = promote.plan_or_apply(
        [_input(sha=digest, local=local, cold=cold)],
        data_root=data_root,
        cold_root=cold_root,
        mount_root=mount,
        apply=False,
        verify_hashes=True,
        is_mount=lambda path: Path(path) == mount,
    )

    assert not actions
    assert blocked[0].reason == "local_hash_mismatch"
    assert local.is_file()
    assert not local.is_symlink()


def test_apply_one_blob_copies_to_cold_and_replaces_local_with_symlink(tmp_path: Path) -> None:
    data_root, local, digest = _write_hot(tmp_path, b"payload")
    mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    cold_root = mount / "scytaledroid_artifacts" / "apk_store" / "cold"
    cold = _cold_path(cold_root, digest)

    actions, blocked, _verification = promote.plan_or_apply(
        [_input(sha=digest, local=local, cold=cold)],
        data_root=data_root,
        cold_root=cold_root,
        mount_root=mount,
        apply=True,
        is_mount=lambda path: Path(path) == mount,
    )

    assert not blocked
    assert actions[0].status == "applied"
    assert actions[0].symlink_created is True
    assert actions[0].hash_verified_before is True
    assert actions[0].hash_verified_after is True
    assert actions[0].bytes_reclaimed == len(b"payload")
    assert cold.read_bytes() == b"payload"
    assert local.is_symlink()
    assert local.read_bytes() == b"payload"


def test_existing_cold_blob_with_matching_hash_is_reused(tmp_path: Path) -> None:
    data_root, local, digest = _write_hot(tmp_path, b"payload")
    mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    cold_root = mount / "scytaledroid_artifacts" / "apk_store" / "cold"
    cold = _cold_path(cold_root, digest)
    cold.parent.mkdir(parents=True)
    cold.write_bytes(b"payload")

    actions, blocked, _verification = promote.plan_or_apply(
        [_input(sha=digest, local=local, cold=cold)],
        data_root=data_root,
        cold_root=cold_root,
        mount_root=mount,
        apply=True,
        is_mount=lambda path: Path(path) == mount,
    )

    assert not blocked
    assert actions[0].status == "applied"
    assert cold.read_bytes() == b"payload"
    assert local.is_symlink()


def test_existing_cold_blob_with_mismatched_hash_blocks(tmp_path: Path) -> None:
    data_root, local, digest = _write_hot(tmp_path, b"payload")
    mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    cold_root = mount / "scytaledroid_artifacts" / "apk_store" / "cold"
    cold = _cold_path(cold_root, digest)
    cold.parent.mkdir(parents=True)
    cold.write_bytes(b"different")

    actions, blocked, _verification = promote.plan_or_apply(
        [_input(sha=digest, local=local, cold=cold)],
        data_root=data_root,
        cold_root=cold_root,
        mount_root=mount,
        apply=True,
        is_mount=lambda path: Path(path) == mount,
    )

    assert not actions
    assert blocked[0].reason == "existing_cold_blob_hash_mismatch"
    assert local.is_file()
    assert not local.is_symlink()


def test_mercury_unmounted_blocks(tmp_path: Path) -> None:
    data_root, local, digest = _write_hot(tmp_path)
    mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    cold_root = mount / "scytaledroid_artifacts" / "apk_store" / "cold"

    _actions, blocked, _verification = promote.plan_or_apply(
        [_input(sha=digest, local=local, cold=_cold_path(cold_root, digest))],
        data_root=data_root,
        cold_root=cold_root,
        mount_root=mount,
        apply=True,
        is_mount=lambda _path: False,
    )

    assert blocked[0].reason == "mercury_mount_not_mounted"
    assert local.is_file()


def test_protected_class_blocks(tmp_path: Path) -> None:
    data_root, local, digest = _write_hot(tmp_path)
    mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    cold_root = mount / "scytaledroid_artifacts" / "apk_store" / "cold"

    _actions, blocked, _verification = promote.plan_or_apply(
        [
            _input(
                sha=digest,
                local=local,
                cold=_cold_path(cold_root, digest),
                promotion_class="KEEP_HOT_CURRENT_RESEARCH_DATASET_BETA",
            )
        ],
        data_root=data_root,
        cold_root=cold_root,
        mount_root=mount,
        apply=True,
        is_mount=lambda path: Path(path) == mount,
    )

    assert blocked[0].reason == "promotion_class_not_eligible:KEEP_HOT_CURRENT_RESEARCH_DATASET_BETA"
    assert local.is_file()


def test_symlink_creation_failure_restores_local_file(tmp_path: Path) -> None:
    data_root, local, digest = _write_hot(tmp_path, b"payload")
    mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    cold_root = mount / "scytaledroid_artifacts" / "apk_store" / "cold"
    cold = _cold_path(cold_root, digest)

    def fail_symlink(_path: Path, _target: Path) -> None:
        raise OSError("synthetic symlink failure")

    _actions, blocked, _verification = promote.plan_or_apply(
        [_input(sha=digest, local=local, cold=cold)],
        data_root=data_root,
        cold_root=cold_root,
        mount_root=mount,
        apply=True,
        is_mount=lambda path: Path(path) == mount,
        symlink_to=fail_symlink,
    )

    assert blocked[0].status == "error"
    assert "synthetic symlink failure" in blocked[0].reason
    assert local.is_file()
    assert not local.is_symlink()
    assert local.read_bytes() == b"payload"


def test_already_cold_symlink_is_skipped(tmp_path: Path) -> None:
    data_root, local, digest = _write_hot(tmp_path, b"payload")
    mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    cold_root = mount / "scytaledroid_artifacts" / "apk_store" / "cold"
    cold = _cold_path(cold_root, digest)
    cold.parent.mkdir(parents=True)
    cold.write_bytes(b"payload")
    local.unlink()
    local.symlink_to(cold)

    actions, blocked, _verification = promote.plan_or_apply(
        [_input(sha=digest, local=local, cold=cold)],
        data_root=data_root,
        cold_root=cold_root,
        mount_root=mount,
        apply=True,
        is_mount=lambda path: Path(path) == mount,
    )

    assert not blocked
    assert actions[0].action == "already_cold"
    assert actions[0].status == "skipped"


def test_receipt_is_written(tmp_path: Path) -> None:
    data_root, local, digest = _write_hot(tmp_path)
    mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    cold_root = mount / "scytaledroid_artifacts" / "apk_store" / "cold"
    action = promote._base_action(
        _input(sha=digest, local=local, cold=_cold_path(cold_root, digest)),
        local=local,
        cold=_cold_path(cold_root, digest),
        action="dry_run",
    )
    action = promote._replace(action, status="planned", reason="dry_run_copy_verify_symlink")

    paths = promote.write_receipts(
        receipt_dir=tmp_path / "receipts",
        stamp="STAMP",
        apply=False,
        verify=True,
        from_audit=tmp_path / "candidates.csv",
        actions=[action],
        blocked=[],
        verification=[action],
    )

    summary = json.loads(Path(paths["summary_json"]).read_text(encoding="utf-8"))
    assert summary["mode"] == "dry_run"
    assert summary["verify_local_hashes"] is True
    assert summary["planned"] == 1
    assert summary["planned_bytes"] == action.size_bytes
    with Path(paths["actions_csv"]).open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["sha256"] == digest
