from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from scytaledroid.DeviceAnalysis.services import artifact_store
from scytaledroid.StaticAnalysis.cli.core.models import ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows import exact_target, headless_run
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, RepositoryArtifact
from scytaledroid.Utils.install_set_identity import compute_artifact_set_hash


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _apk(tmp_path: Path, name: str, data: bytes) -> tuple[Path, str]:
    path = tmp_path / name
    path.write_bytes(data)
    return path, _sha(data)


def _row(*, apk_id: int = 11, package: str = "com.example.app", sha: str, path: Path | None):
    return {
        "apk_id": apk_id,
        "package_name": package,
        "file_name": path.name if path else "missing.apk",
        "version_name": "1.0",
        "version_code": "1",
        "sha256": sha,
        "is_split_member": 0,
        "split_group_id": 77,
        "local_rel_path": str(path) if path else str(Path("/definitely/missing.apk")),
        "data_root": "",
    }


def _patch_db(monkeypatch, row):
    monkeypatch.setattr(
        exact_target,
        "core_q",
        SimpleNamespace(run_sql=lambda *_a, **_k: [row]),
    )


def _patch_exact_db(monkeypatch, base_row, split_rows=()):
    def _run_sql(sql, *_args, **_kwargs):  # noqa: ANN001
        if "lookup_same_capture_splits" in str(_kwargs.get("query_name") or ""):
            return list(split_rows)
        return [base_row] if base_row is not None else []

    monkeypatch.setattr(exact_target, "core_q", SimpleNamespace(run_sql=_run_sql))


def _artifact(path: Path, *, apk_id: int, package: str, sha: str, split: bool, group_id: int = 77):
    return RepositoryArtifact(
        path=path,
        display_path=path.name,
        metadata={
            "apk_id": apk_id,
            "package_name": package,
            "version_name": "1.0",
            "version_code": "1",
            "sha256": sha,
            "is_split_member": split,
            "split_group_id": group_id,
            "receipt_path": "data/receipts/harvest/test/com.example.app.json",
            "session_stamp": "capture-1",
        },
    )


def _group(
    base: RepositoryArtifact,
    *splits: RepositoryArtifact,
    capture_id: str = "capture-1",
    group_key: str | None = None,
) -> ArtifactGroup:
    return ArtifactGroup(
        group_key=group_key or f"split-com.example.app-77-{capture_id}-1",
        package_name=base.package_name,
        version_display=base.version_display,
        session_stamp=capture_id,
        capture_id=capture_id,
        artifacts=(base, *splits),
        grouping_reason="split_group_capture_id",
        grouping_confidence="high",
        harvest_manifest_path="data/receipts/harvest/test/com.example.app.json",
    )


def test_hash_mismatch_aborts(monkeypatch, tmp_path):
    path, good_sha = _apk(tmp_path, "base.apk", b"actual")
    bad_sha = _sha(b"expected")
    _patch_db(monkeypatch, _row(sha=bad_sha, path=path))
    monkeypatch.setattr(exact_target, "group_artifacts", lambda: [])

    with pytest.raises(exact_target.ExactTargetResolutionError, match="Hash mismatch"):
        exact_target.resolve_exact_static_target(
            apk_id=11,
            base_apk_sha256=bad_sha,
            include_splits="base-only",
        )
    assert good_sha != bad_sha


def test_missing_local_artifact_aborts(monkeypatch, tmp_path):
    expected = _sha(b"base")
    _patch_db(monkeypatch, _row(sha=expected, path=tmp_path / "missing.apk"))
    monkeypatch.setattr(exact_target, "group_artifacts", lambda: [])

    with pytest.raises(exact_target.ExactTargetResolutionError, match="Local artifact path"):
        exact_target.resolve_exact_static_target(apk_id=11, include_splits="base-only")


def test_exact_target_canonical_cold_blob_fails_clearly_when_mercury_unmounted(
    monkeypatch,
    tmp_path,
):
    sha = "c" * 64
    external_mount = tmp_path / "mnt" / "MERCURY_DATA_V2"
    cold_apk = external_mount / "cold" / "data" / "store" / "apk" / "sha256" / "cc" / f"{sha}.apk"
    cold_apk.parent.mkdir(parents=True, exist_ok=True)
    cold_apk.write_text("apk", encoding="utf-8")
    canonical_link = tmp_path / "data" / "store" / "apk" / "sha256" / "cc" / f"{sha}.apk"
    canonical_link.parent.mkdir(parents=True, exist_ok=True)
    canonical_link.symlink_to(cold_apk)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(artifact_store, "EXTERNAL_APK_STORE_MOUNT_ROOTS", (external_mount,))
    monkeypatch.setattr(artifact_store.os.path, "ismount", lambda _path: False)

    with pytest.raises(artifact_store.ColdApkBlobUnavailable, match="Mercury drive is not mounted"):
        exact_target._resolve_local_path(_row(sha=sha, path=None))


def test_base_only_requires_explicit_mode(monkeypatch, tmp_path):
    path, expected = _apk(tmp_path, "base.apk", b"base")
    _patch_db(monkeypatch, _row(sha=expected, path=path))
    monkeypatch.setattr(exact_target, "group_artifacts", lambda: [])

    with pytest.raises(exact_target.ExactTargetResolutionError, match="base-only"):
        exact_target.resolve_exact_static_target(apk_id=11, include_splits="auto")

    target = exact_target.resolve_exact_static_target(apk_id=11, include_splits="base-only")
    assert target.split_mode == "base-only"
    assert "Exact base-only" in target.selection.label


def test_newest_capture_fallback_is_not_used(monkeypatch, tmp_path):
    path, expected = _apk(tmp_path, "requested.apk", b"requested")
    other_path, other_sha = _apk(tmp_path, "newest.apk", b"newest")
    _patch_db(monkeypatch, _row(sha=expected, path=path))
    newest_group = _group(
        _artifact(other_path, apk_id=99, package="com.example.app", sha=other_sha, split=False)
    )
    monkeypatch.setattr(exact_target, "group_artifacts", lambda: [newest_group])

    with pytest.raises(exact_target.ExactTargetResolutionError, match="Receipt-backed split set unavailable"):
        exact_target.resolve_exact_static_target(apk_id=11, include_splits="auto")


def test_worklist_row_resolves_by_apk_id_and_base_hash(monkeypatch, tmp_path):
    path, expected = _apk(tmp_path, "base.apk", b"base")
    _patch_db(monkeypatch, _row(apk_id=44, sha=expected, path=path))
    monkeypatch.setattr(exact_target, "group_artifacts", lambda: [])

    target = exact_target.resolve_exact_static_target(
        apk_id=44,
        base_apk_sha256=expected,
        package_name="com.example.app",
        include_splits="base-only",
    )

    assert target.apk_id == "44"
    assert target.expected_base_sha256 == expected
    assert target.actual_base_sha256 == expected
    assert target.base_path == path.resolve()


def test_hash_only_resolution_rejects_ambiguous_repository_rows(monkeypatch, tmp_path):
    path, expected = _apk(tmp_path, "base.apk", b"base")
    row1 = _row(apk_id=44, sha=expected, path=path)
    row2 = _row(apk_id=45, sha=expected, path=path)
    monkeypatch.setattr(
        exact_target,
        "core_q",
        SimpleNamespace(run_sql=lambda *_a, **_k: [row1, row2]),
    )
    monkeypatch.setattr(exact_target, "group_artifacts", lambda: [])

    with pytest.raises(exact_target.ExactTargetResolutionError, match="provide apk_id"):
        exact_target.resolve_exact_static_target(
            base_apk_sha256=expected,
            include_splits="base-only",
        )


def test_split_reconstruction_path_selected_for_receipt_backed_group(monkeypatch, tmp_path):
    base_path, base_sha = _apk(tmp_path, "base.apk", b"base")
    split_path, split_sha = _apk(tmp_path, "split.apk", b"split")
    _patch_db(monkeypatch, _row(apk_id=55, sha=base_sha, path=base_path))
    base = _artifact(base_path, apk_id=55, package="com.example.app", sha=base_sha, split=False)
    split = _artifact(split_path, apk_id=56, package="com.example.app", sha=split_sha, split=True)
    monkeypatch.setattr(exact_target, "group_artifacts", lambda: [_group(base, split)])

    target = exact_target.resolve_exact_static_target(
        apk_id=55,
        base_apk_sha256=base_sha,
        include_splits="auto",
    )

    assert target.split_mode == "receipt-backed-group"
    assert target.receipt_backed is True
    assert target.split_count == 1
    assert len(target.selection.groups[0].artifacts) == 2


def test_receipt_backed_sibling_sets_are_ambiguous(monkeypatch, tmp_path):
    base_path, base_sha = _apk(tmp_path, "base.apk", b"base")
    one_path, one_sha = _apk(tmp_path, "one.apk", b"one")
    two_path, two_sha = _apk(tmp_path, "two.apk", b"two")
    _patch_db(monkeypatch, _row(apk_id=55, sha=base_sha, path=base_path))
    base = _artifact(base_path, apk_id=55, package="com.example.app", sha=base_sha, split=False)
    one = _artifact(one_path, apk_id=56, package="com.example.app", sha=one_sha, split=True)
    two = _artifact(two_path, apk_id=57, package="com.example.app", sha=two_sha, split=True)
    monkeypatch.setattr(exact_target, "group_artifacts", lambda: [_group(base, one), _group(base, two)])

    with pytest.raises(exact_target.ExactTargetResolutionError, match="multiple receipt-backed install sets"):
        exact_target.resolve_exact_static_target(apk_id=55, base_apk_sha256=base_sha, include_splits="auto")


def test_identical_receipt_duplicates_select_newest_capture(monkeypatch, tmp_path):
    base_path, base_sha = _apk(tmp_path, "base.apk", b"base")
    split_path, split_sha = _apk(tmp_path, "split.apk", b"split")
    _patch_db(monkeypatch, _row(apk_id=55, sha=base_sha, path=base_path))
    base = _artifact(base_path, apk_id=55, package="com.example.app", sha=base_sha, split=False)
    split = _artifact(split_path, apk_id=56, package="com.example.app", sha=split_sha, split=True)
    older = _group(base, split, capture_id="capture-20260612")
    newer = _group(base, split, capture_id="capture-20260613")
    monkeypatch.setattr(exact_target, "group_artifacts", lambda: [older, newer])

    target = exact_target.resolve_exact_static_target(
        apk_id=55,
        base_apk_sha256=base_sha,
        include_splits="auto",
    )

    assert target.capture_id == "capture-20260613"
    assert target.artifact_set_hash_version == "v1"
    assert target.artifact_set_hash
    assert target.split_count == 1


def test_apk_set_id_selects_matching_sibling_set(monkeypatch, tmp_path):
    base_path, base_sha = _apk(tmp_path, "base.apk", b"base")
    one_path, one_sha = _apk(tmp_path, "one.apk", b"one")
    two_path, two_sha = _apk(tmp_path, "two.apk", b"two")
    base_row = _row(apk_id=55, sha=base_sha, path=base_path)
    chosen_hash = compute_artifact_set_hash(
        [
            {"role": "base", "split_name": "base", "sha256": base_sha},
            {"role": "split", "split_name": "one", "sha256": one_sha},
        ],
        version="v1",
    )

    def _run_sql(*_a, **kwargs):
        if kwargs.get("query_name") == "static.exact_target.lookup_apk_set":
            return {
                "apk_set_id": 843,
                "package_name": "com.example.app",
                "base_apk_sha256": base_sha,
                "artifact_set_hash": chosen_hash,
                "artifact_set_hash_version": "v1",
            }
        return [base_row]

    monkeypatch.setattr(exact_target, "core_q", SimpleNamespace(run_sql=_run_sql))
    base = _artifact(base_path, apk_id=55, package="com.example.app", sha=base_sha, split=False)
    one = _artifact(one_path, apk_id=56, package="com.example.app", sha=one_sha, split=True)
    two = _artifact(two_path, apk_id=57, package="com.example.app", sha=two_sha, split=True)
    monkeypatch.setattr(
        exact_target,
        "group_artifacts",
        lambda: [_group(base, one, capture_id="set-one"), _group(base, two, capture_id="set-two")],
    )

    target = exact_target.resolve_exact_static_target(
        apk_id=55,
        base_apk_sha256=base_sha,
        include_splits="auto",
        apk_set_id=843,
    )

    assert target.apk_set_id == "843"
    assert target.artifact_set_hash == chosen_hash
    assert target.capture_id == "set-one"
    assert target.split_count == 1


def test_apk_set_id_selects_matching_v2_set_without_v1_digest_compare(monkeypatch, tmp_path):
    base_path, base_sha = _apk(tmp_path, "base.apk", b"base")
    split_path, split_sha = _apk(tmp_path, "one.apk", b"one")
    base_row = _row(apk_id=55, sha=base_sha, path=base_path)
    members = [
        {"role": "base", "split_name": "base", "sha256": base_sha},
        {"role": "split", "split_name": "one", "sha256": split_sha},
    ]
    v2_hash = compute_artifact_set_hash(members, version="v2")

    def _run_sql(*_a, **kwargs):
        if kwargs.get("query_name") == "static.exact_target.lookup_apk_set":
            return {
                "apk_set_id": 6485,
                "package_name": "com.example.app",
                "base_apk_sha256": base_sha,
                "artifact_set_hash": v2_hash,
                "artifact_set_hash_version": "v2",
            }
        return [base_row]

    monkeypatch.setattr(exact_target, "core_q", SimpleNamespace(run_sql=_run_sql))
    base = _artifact(base_path, apk_id=55, package="com.example.app", sha=base_sha, split=False)
    split = _artifact(split_path, apk_id=56, package="com.example.app", sha=split_sha, split=True)
    monkeypatch.setattr(exact_target, "group_artifacts", lambda: [_group(base, split)])

    target = exact_target.resolve_exact_static_target(
        apk_id=55,
        base_apk_sha256=base_sha,
        include_splits="auto",
        apk_set_id=6485,
    )

    assert target.apk_set_id == "6485"
    assert target.artifact_set_hash_version == "v2"
    assert target.artifact_set_hash == v2_hash


def test_apk_set_id_uses_stored_members_without_harvest_walk(monkeypatch, tmp_path):
    base_path, base_sha = _apk(tmp_path, "base.apk", b"base")
    split_path, split_sha = _apk(tmp_path, "one.apk", b"one")
    base_row = _row(apk_id=55, sha=base_sha, path=base_path)
    members = [
        {"role": "base", "split_name": "base", "sha256": base_sha},
        {"role": "split", "split_name": "one", "sha256": split_sha},
    ]
    chosen_hash = compute_artifact_set_hash(members, version="v1")

    def _run_sql(*_a, **kwargs):
        name = kwargs.get("query_name")
        if name == "static.exact_target.lookup_apk_set":
            return {
                "apk_set_id": 843,
                "package_name": "com.example.app",
                "base_apk_sha256": base_sha,
                "artifact_set_hash": chosen_hash,
                "artifact_set_hash_version": "v1",
            }
        if name == "static.exact_target.lookup_apk_set_members":
            return [
                {
                    "apk_id": 55,
                    "role": "base",
                    "split_name": "base",
                    "sha256": base_sha,
                    "local_rel_path": str(base_path),
                    "package_name": "com.example.app",
                    "version_name": "1.0",
                    "version_code": "1",
                },
                {
                    "apk_id": 56,
                    "role": "split",
                    "split_name": "one",
                    "sha256": split_sha,
                    "local_rel_path": str(split_path),
                    "package_name": "com.example.app",
                    "version_name": "1.0",
                    "version_code": "1",
                },
            ]
        return [base_row]

    monkeypatch.setattr(exact_target, "core_q", SimpleNamespace(run_sql=_run_sql))
    monkeypatch.setattr(
        exact_target,
        "group_artifacts",
        lambda: (_ for _ in ()).throw(AssertionError("harvest tree walk should be skipped")),
    )

    target = exact_target.resolve_exact_static_target(
        apk_id=55,
        base_apk_sha256=base_sha,
        include_splits="auto",
        apk_set_id=843,
    )

    assert target.apk_set_id == "843"
    assert target.artifact_set_hash == chosen_hash
    assert target.artifact_set_hash_version == "v1"
    assert target.split_count == 1
    assert target.receipt_backed is True
    assert target.selection.groups[0].grouping_reason == "stored_install_set"


def test_stored_members_missing_bytes_fall_back_to_receipts(monkeypatch, tmp_path):
    base_path, base_sha = _apk(tmp_path, "base.apk", b"base")
    split_path, split_sha = _apk(tmp_path, "one.apk", b"one")
    base_row = _row(apk_id=55, sha=base_sha, path=base_path)
    members = [
        {"role": "base", "split_name": "base", "sha256": base_sha},
        {"role": "split", "split_name": "one", "sha256": split_sha},
    ]
    chosen_hash = compute_artifact_set_hash(members, version="v1")

    def _run_sql(*_a, **kwargs):
        name = kwargs.get("query_name")
        if name == "static.exact_target.lookup_apk_set":
            return {
                "apk_set_id": 843,
                "package_name": "com.example.app",
                "base_apk_sha256": base_sha,
                "artifact_set_hash": chosen_hash,
                "artifact_set_hash_version": "v1",
            }
        if name == "static.exact_target.lookup_apk_set_members":
            return [
                {
                    "apk_id": 55,
                    "role": "base",
                    "split_name": "base",
                    "sha256": base_sha,
                    "local_rel_path": str(tmp_path / "missing-base.apk"),
                    "package_name": "com.example.app",
                },
                {
                    "apk_id": 56,
                    "role": "split",
                    "split_name": "one",
                    "sha256": split_sha,
                    "local_rel_path": str(tmp_path / "missing-split.apk"),
                    "package_name": "com.example.app",
                },
            ]
        return [base_row]

    monkeypatch.setattr(exact_target, "core_q", SimpleNamespace(run_sql=_run_sql))
    base = _artifact(base_path, apk_id=55, package="com.example.app", sha=base_sha, split=False)
    split = _artifact(split_path, apk_id=56, package="com.example.app", sha=split_sha, split=True)
    monkeypatch.setattr(exact_target, "group_artifacts", lambda: [_group(base, split)])

    target = exact_target.resolve_exact_static_target(
        apk_id=55,
        base_apk_sha256=base_sha,
        include_splits="auto",
        apk_set_id=843,
    )

    assert target.apk_set_id == "843"
    assert target.artifact_set_hash == chosen_hash
    assert target.capture_id == "capture-1"


def test_requested_set_hash_mismatch_fails_closed(monkeypatch, tmp_path):
    base_path, base_sha = _apk(tmp_path, "base.apk", b"base")
    split_path, split_sha = _apk(tmp_path, "split.apk", b"split")
    _patch_db(monkeypatch, _row(apk_id=55, sha=base_sha, path=base_path))
    base = _artifact(base_path, apk_id=55, package="com.example.app", sha=base_sha, split=False)
    split = _artifact(split_path, apk_id=56, package="com.example.app", sha=split_sha, split=True)
    monkeypatch.setattr(exact_target, "group_artifacts", lambda: [_group(base, split)])

    with pytest.raises(exact_target.ExactTargetResolutionError, match="did not match"):
        exact_target.resolve_exact_static_target(
            apk_id=55,
            base_apk_sha256=base_sha,
            include_splits="auto",
            artifact_set_hash="c" * 64,
        )


def test_readiness_missing_base_bytes_recommends_restore_artifacts(monkeypatch, tmp_path):
    expected = _sha(b"base")
    split_sha_1 = _sha(b"split-1")
    split_sha_2 = _sha(b"split-2")
    base_row = _row(apk_id=2578, package="com.whatsapp", sha=expected, path=tmp_path / "missing-base.apk")
    base_row["source_path"] = "/data/app/~~abc/com.whatsapp-xyz/base.apk"
    split_row_1 = _row(apk_id=2579, package="com.whatsapp", sha=split_sha_1, path=tmp_path / "missing-split-1.apk")
    split_row_1.update({"is_split_member": 1, "source_path": "/data/app/~~abc/com.whatsapp-xyz/split_config.arm64_v8a.apk"})
    split_row_2 = _row(apk_id=2580, package="com.whatsapp", sha=split_sha_2, path=tmp_path / "missing-split-2.apk")
    split_row_2.update({"is_split_member": 1, "source_path": "/data/app/~~abc/com.whatsapp-xyz/split_config.xxhdpi.apk"})
    _patch_exact_db(monkeypatch, base_row, [split_row_1, split_row_2])
    monkeypatch.setattr(exact_target, "group_artifacts", lambda: [])
    monkeypatch.setattr(
        exact_target.artifact_store,
        "canonical_apk_path",
        lambda sha, **_kwargs: tmp_path / "sha-store" / f"{sha}.apk",
    )

    readiness = exact_target.assess_exact_target_readiness(
        apk_id=2578,
        base_apk_sha256=expected,
        package_name="com.whatsapp",
        dynamic_runs=10,
    )

    assert readiness.repository_row_exists is True
    assert readiness.db_split_members_count == 2
    assert readiness.base_file_available is False
    assert readiness.base_file_hash_verified is False
    assert readiness.recorded_local_file_available is False
    assert readiness.canonical_store_file_available is False
    assert readiness.split_files_expected == 2
    assert readiness.split_files_available == 0
    assert readiness.recommended_action == "restore_artifacts"


def test_readiness_base_only_available_requires_explicit_mode(monkeypatch, tmp_path):
    path, expected = _apk(tmp_path, "base.apk", b"base")
    _patch_exact_db(monkeypatch, _row(apk_id=11, sha=expected, path=path), [])
    monkeypatch.setattr(exact_target, "group_artifacts", lambda: [])

    readiness = exact_target.assess_exact_target_readiness(
        apk_id=11,
        base_apk_sha256=expected,
        package_name="com.example.app",
    )

    assert readiness.base_file_available is True
    assert readiness.base_file_hash_verified is True
    assert readiness.split_files_expected == 0
    assert readiness.recommended_action == "base_only_available_explicit"


def test_readiness_receipt_backed_group_is_exact_static_available(monkeypatch, tmp_path):
    base_path, base_sha = _apk(tmp_path, "base.apk", b"base")
    split_path, split_sha = _apk(tmp_path, "split.apk", b"split")
    base_row = _row(apk_id=55, sha=base_sha, path=base_path)
    base_row["source_path"] = "/data/app/~~abc/com.example.app/base.apk"
    split_row = _row(apk_id=56, sha=split_sha, path=split_path)
    split_row.update({"is_split_member": 1, "source_path": "/data/app/~~abc/com.example.app/split.apk"})
    _patch_exact_db(monkeypatch, base_row, [split_row])
    base = _artifact(base_path, apk_id=55, package="com.example.app", sha=base_sha, split=False)
    split = _artifact(split_path, apk_id=56, package="com.example.app", sha=split_sha, split=True)
    monkeypatch.setattr(exact_target, "group_artifacts", lambda: [_group(base, split)])

    readiness = exact_target.assess_exact_target_readiness(
        apk_id=55,
        base_apk_sha256=base_sha,
        package_name="com.example.app",
    )

    assert readiness.receipt_backed_group_available is True
    assert readiness.split_files_expected == 1
    assert readiness.split_files_available == 1
    assert readiness.recommended_action == "exact_static_available"


def test_headless_exact_mode_uses_exact_resolver(monkeypatch, tmp_path):
    base_path, base_sha = _apk(tmp_path, "base.apk", b"base")
    base = _artifact(base_path, apk_id=55, package="com.example.app", sha=base_sha, split=False)
    group = _group(base)
    target = SimpleNamespace(
        package_name="com.example.app",
        apk_id="55",
        expected_base_sha256=base_sha,
        actual_base_sha256=base_sha,
        split_mode="receipt-backed-group",
        split_count=0,
        artifacts=(SimpleNamespace(),),
        apk_set_id="843",
        artifact_set_hash="b" * 64,
        artifact_set_hash_version="v1",
        capture_id="capture-1",
        selection=ScopeSelection(
            "app",
            "Exact dynamic base hash + harvested split set | com.example.app",
            (group,),
        ),
    )
    captured: dict[str, object] = {}

    def _resolve(**kwargs):
        captured["resolve"] = kwargs
        return target

    monkeypatch.setattr(headless_run.schema_gate, "static_schema_gate", lambda: (True, "ok", None))
    monkeypatch.setattr(headless_run, "resolve_exact_static_target", _resolve)
    monkeypatch.setattr(headless_run, "write_exact_target_receipt", lambda *_a, **_k: tmp_path / "receipt.json")
    monkeypatch.setattr(headless_run, "_check_session_uniqueness", lambda *_a, **_k: None)
    monkeypatch.setattr(headless_run, "execute_run_spec", lambda spec: captured.setdefault("spec", spec))
    monkeypatch.setattr(headless_run, "count_linkable_dynamic_sessions_for_hash", lambda _sha: 0)

    rc = headless_run.main(
        [
            "--apk-id",
            "55",
            "--base-apk-sha256",
            base_sha,
            "--include-splits",
            "require",
            "--apk-set-id",
            "843",
            "--artifact-set-hash",
            "b" * 64,
            "--profile",
            "lightweight",
            "--session",
            "exact-test",
        ]
    )

    assert rc == 0
    assert captured["resolve"]["apk_id"] == "55"
    assert captured["resolve"]["base_apk_sha256"] == base_sha
    assert captured["resolve"]["include_splits"] == "require"
    assert captured["resolve"]["apk_set_id"] == "843"
    assert captured["resolve"]["artifact_set_hash"] == "b" * 64
    spec = captured["spec"]
    assert spec.selection.groups == (group,)
    assert spec.params.profile == "lightweight"


def test_count_linkable_dynamic_sessions_for_hash_uses_typed_static_run_expression(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_run_sql(sql, params=(), **_kwargs):
        captured["sql"] = sql
        captured["params"] = params
        return {"c": 7}

    monkeypatch.setattr(exact_target, "core_q", SimpleNamespace(run_sql=_fake_run_sql))

    count = exact_target.count_linkable_dynamic_sessions_for_hash("a" * 64)

    assert count == 7
    assert captured["params"] == ("a" * 64,)
    sql = str(captured["sql"])
    assert "ds.static_run_id_u" in sql
    assert "CAST(ds.static_run_id AS UNSIGNED)" in sql
