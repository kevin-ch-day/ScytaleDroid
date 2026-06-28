from __future__ import annotations

import json
import os
from hashlib import sha256
from pathlib import Path

from scytaledroid.DeviceAnalysis.services import storage_pressure
from scytaledroid.Database.db_scripts import package_lineage_read_model as lineage


def _write_apk(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return sha256(payload).hexdigest()


def _write_sidecar(
    path: Path,
    *,
    package_name: str,
    version_code: str,
    sha: str,
    canonical_rel: str,
    local_rel: str,
    session_label: str = "run1",
    device_serial: str = "SER1",
) -> None:
    payload = {
        "package_name": package_name,
        "version_code": version_code,
        "sha256": sha,
        "canonical_store_path": canonical_rel,
        "local_path": local_rel,
        "session_stamp": session_label,
        "device_serial": device_serial,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_manifest(path: Path, *, package_name: str, version_code: str, session_label: str = "run1") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "harvest_package_manifest_v1",
        "package": {
            "package_name": package_name,
            "version_code": version_code,
            "session_label": session_label,
            "device_serial": "SER1",
        },
        "execution": {
            "observed_artifacts": [],
        },
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_manifest_with_observed(
    path: Path,
    *,
    package_name: str,
    version_code: str,
    observed_artifacts: list[dict[str, object]],
    session_label: str = "run1",
    device_serial: str = "SER1",
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "harvest_package_manifest_v1",
        "package": {
            "package_name": package_name,
            "version_code": version_code,
            "session_label": session_label,
            "device_serial": device_serial,
        },
        "execution": {
            "observed_artifacts": observed_artifacts,
        },
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _observed_entry(*, local_rel: str, canonical_rel: str, sha: str, file_name: str = "base.apk") -> dict[str, object]:
    return {
        "split_label": "base",
        "file_name": file_name,
        "is_base": True,
        "local_artifact_path": local_rel,
        "canonical_store_path": canonical_rel,
        "sha256": sha,
        "file_size": 1,
        "pull_outcome": "written",
    }


def _write_symlink(session_path: Path, target_path: Path) -> None:
    session_path.parent.mkdir(parents=True, exist_ok=True)
    rel_target = os.path.relpath(target_path, start=session_path.parent)
    session_path.symlink_to(rel_target)


def _db_row(*, package_name: str, sha: str, data_root: str, local_rel_path: str, version_code: str = "1") -> dict:
    return {
        "apk_id": 1,
        "package_name": package_name,
        "version_code": version_code,
        "version_name": "1.0",
        "sha256": sha,
        "is_split_member": 0,
        "local_rel_path": local_rel_path,
        "storage_root_id": 1,
        "data_root": data_root,
    }


def _base_row(*, package_name: str, sha: str, data_root: str, local_rel_path: str, version_code: str = "1") -> dict:
    return {
        "apk_id": 1,
        "package_name": package_name,
        "display_name": package_name,
        "version_code": version_code,
        "version_name": "1.0",
        "base_apk_sha256": sha,
        "storage_root_id": 1,
        "local_rel_path": local_rel_path,
        "data_root": data_root,
    }


def _install_set_table_summary(*, total: int, complete: int) -> dict:
    return {
        "install_sets_total": total,
        "install_sets_complete": complete,
        "install_sets_incomplete": max(total - complete, 0),
    }


def test_verified_regular_session_apk_becomes_eligible(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "data"
    package = "com.example.app"
    rel = "SER1/runs/run1/com.example.app/App_v1/com_example_app_1__base.apk"
    apk_path = root / "device_apks" / rel
    sha = _write_apk(apk_path, b"apk-bytes")
    canonical_rel = f"data/store/apk/sha256/{sha[:2]}/{sha}.apk"
    canonical_path = tmp_path / canonical_rel
    _write_apk(canonical_path, b"apk-bytes")
    _write_sidecar(
        apk_path.with_suffix(".apk.meta.json"),
        package_name=package,
        version_code="1",
        sha=sha,
        canonical_rel=canonical_rel,
        local_rel=rel,
    )
    _write_manifest(apk_path.parent / "harvest_package_manifest.json", package_name=package, version_code="1")

    monkeypatch.setattr(storage_pressure, "_load_db_artifact_rows", lambda _core_q: [
        _db_row(package_name=package, sha=sha, data_root=(root / "device_apks").as_posix(), local_rel_path=rel)
    ])
    monkeypatch.setattr(storage_pressure, "_load_storage_roots", lambda _core_q: [
        {"root_id": 1, "host_name": "test", "data_root": (root / "device_apks").as_posix()}
    ])
    monkeypatch.setattr(storage_pressure, "_load_install_set_summary_by_hash", lambda _core_q, _lineage: {
        sha: {
            "apk_set_id": 10,
            "member_count": 1,
            "split_count": 0,
            "completeness_state": "complete",
        }
    })
    monkeypatch.setattr(
        storage_pressure,
        "_load_install_set_table_summary",
        lambda _core_q, _lineage: _install_set_table_summary(total=1, complete=1),
    )
    monkeypatch.setattr(lineage, "fetch_base_rows", lambda _core_q, package_name=None: [
        _base_row(package_name=package, sha=sha, data_root=(root / "device_apks").as_posix(), local_rel_path=rel)
    ])

    audit = storage_pressure.build_storage_pressure_audit(core_q=object(), data_root=root, verify_candidates=True)

    assert audit["summary"]["eligible_verified_files"] == 1
    assert audit["summary"]["eligible_verified_reclaimable_bytes"] == len(b"apk-bytes")
    rows = audit["session_pressure"]["rows"]
    assert rows[0]["classification"] == "eligible_verified"
    assert rows[0]["hash_verified"] is True
    assert rows[0]["install_set_present"] is True
    assert audit["summary"]["install_sets_total"] == 1
    assert audit["summary"]["install_sets_complete"] == 1
    assert audit["summary"]["base_hashes_with_install_sets"] == 1


def test_missing_canonical_payload_blocks_candidate(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "data"
    package = "com.example.blocked"
    rel = "SER1/runs/run1/com.example.blocked/App_v1/com_example_blocked_1__base.apk"
    apk_path = root / "device_apks" / rel
    sha = _write_apk(apk_path, b"blocked")
    canonical_rel = f"data/store/apk/sha256/{sha[:2]}/{sha}.apk"
    _write_sidecar(
        apk_path.with_suffix(".apk.meta.json"),
        package_name=package,
        version_code="1",
        sha=sha,
        canonical_rel=canonical_rel,
        local_rel=rel,
    )
    _write_manifest(apk_path.parent / "harvest_package_manifest.json", package_name=package, version_code="1")

    monkeypatch.setattr(storage_pressure, "_load_db_artifact_rows", lambda _core_q: [
        _db_row(package_name=package, sha=sha, data_root=(root / "device_apks").as_posix(), local_rel_path=rel)
    ])
    monkeypatch.setattr(storage_pressure, "_load_storage_roots", lambda _core_q: [
        {"root_id": 1, "host_name": "test", "data_root": (root / "device_apks").as_posix()}
    ])
    monkeypatch.setattr(storage_pressure, "_load_install_set_summary_by_hash", lambda _core_q, _lineage: {})
    monkeypatch.setattr(
        storage_pressure,
        "_load_install_set_table_summary",
        lambda _core_q, _lineage: _install_set_table_summary(total=0, complete=0),
    )
    monkeypatch.setattr(lineage, "fetch_base_rows", lambda _core_q, package_name=None: [
        _base_row(package_name=package, sha=sha, data_root=(root / "device_apks").as_posix(), local_rel_path=rel)
    ])

    audit = storage_pressure.build_storage_pressure_audit(core_q=object(), data_root=root, verify_candidates=False)

    assert audit["summary"]["eligible_unverified_files"] == 0
    rows = audit["session_pressure"]["rows"]
    assert rows[0]["classification"] == "blocked_canonical_missing"
    assert audit["session_pressure"]["summary"]["blocked_canonical_missing"] == 1


def test_existing_symlink_counts_as_already_thin(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "data"
    package = "com.example.symlink"
    rel = "SER1/runs/run1/com.example.symlink/App_v1/com_example_symlink_1__base.apk"
    canonical_payload = b"thin"
    sha = sha256(canonical_payload).hexdigest()
    canonical_rel = f"data/store/apk/sha256/{sha[:2]}/{sha}.apk"
    canonical_path = tmp_path / canonical_rel
    _write_apk(canonical_path, canonical_payload)
    apk_path = root / "device_apks" / rel
    apk_path.parent.mkdir(parents=True, exist_ok=True)
    apk_path.symlink_to(Path("../../../../../../") / canonical_rel)
    _write_sidecar(
        apk_path.with_suffix(".apk.meta.json"),
        package_name=package,
        version_code="1",
        sha=sha,
        canonical_rel=canonical_rel,
        local_rel=rel,
    )
    _write_manifest(apk_path.parent / "harvest_package_manifest.json", package_name=package, version_code="1")

    monkeypatch.setattr(storage_pressure, "_load_db_artifact_rows", lambda _core_q: [
        _db_row(package_name=package, sha=sha, data_root=(root / "device_apks").as_posix(), local_rel_path=rel)
    ])
    monkeypatch.setattr(storage_pressure, "_load_storage_roots", lambda _core_q: [
        {"root_id": 1, "host_name": "test", "data_root": (root / "device_apks").as_posix()}
    ])
    monkeypatch.setattr(storage_pressure, "_load_install_set_summary_by_hash", lambda _core_q, _lineage: {})
    monkeypatch.setattr(
        storage_pressure,
        "_load_install_set_table_summary",
        lambda _core_q, _lineage: _install_set_table_summary(total=0, complete=0),
    )
    monkeypatch.setattr(lineage, "fetch_base_rows", lambda _core_q, package_name=None: [
        _base_row(package_name=package, sha=sha, data_root=(root / "device_apks").as_posix(), local_rel_path=rel)
    ])

    audit = storage_pressure.build_storage_pressure_audit(core_q=object(), data_root=root, verify_candidates=True)

    assert audit["summary"]["session_symlink_apk_files"] == 1
    assert audit["summary"]["session_regular_apk_files"] == 0
    row = audit["session_pressure"]["rows"][0]
    assert row["classification"] == "already_thin_symlink"
    assert row["reclaimable_bytes"] == 0


def test_historical_identity_and_stale_current_rows_stay_separate(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "data"
    current_root = (root / "device_apks").as_posix()
    old_root = "/missing/old/device_apks"
    current_sha = sha256(b"current").hexdigest()
    old_sha = sha256(b"old").hexdigest()
    canonical_rel = f"data/store/apk/sha256/{current_sha[:2]}/{current_sha}.apk"
    _write_apk(tmp_path / canonical_rel, b"current")

    monkeypatch.setattr(storage_pressure, "_load_db_artifact_rows", lambda _core_q: [
        _db_row(
            package_name="com.example.current",
            sha=current_sha,
            data_root=current_root,
            local_rel_path="SER1/runs/run1/com.example.current/App_v1/base.apk",
        ),
        _db_row(
            package_name="com.example.old",
            sha=old_sha,
            data_root=old_root,
            local_rel_path="SER1/runs/run0/com.example.old/App_v1/base.apk",
        ),
    ])
    monkeypatch.setattr(storage_pressure, "_load_storage_roots", lambda _core_q: [
        {"root_id": 1, "host_name": "test", "data_root": current_root},
        {"root_id": 2, "host_name": "test", "data_root": old_root},
    ])
    monkeypatch.setattr(storage_pressure, "_load_install_set_summary_by_hash", lambda _core_q, _lineage: {})
    monkeypatch.setattr(
        storage_pressure,
        "_load_install_set_table_summary",
        lambda _core_q, _lineage: _install_set_table_summary(total=0, complete=0),
    )
    monkeypatch.setattr(lineage, "fetch_base_rows", lambda _core_q, package_name=None: [
        _base_row(
            package_name="com.example.current",
            sha=current_sha,
            data_root=current_root,
            local_rel_path="SER1/runs/run1/com.example.current/App_v1/base.apk",
        ),
        _base_row(
            package_name="com.example.old",
            sha=old_sha,
            data_root=old_root,
            local_rel_path="SER1/runs/run0/com.example.old/App_v1/base.apk",
        ),
    ])

    audit = storage_pressure.build_storage_pressure_audit(core_q=object(), data_root=root, verify_candidates=False)

    assert audit["summary"]["session_regular_apk_files"] == 0
    assert audit["summary"]["current_root_stale_canonical_present_rows"] == 1
    assert audit["summary"]["old_root_historical_rows"] == 1
    assert audit["db_lineage"]["summary"]["recorded_path_stale_canonical_present"] == 1
    assert audit["db_lineage"]["summary"]["historical_identity_only"] == 1


def test_blocked_sidecar_report_identifies_safe_reconstruction_candidate(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "data"
    package = "org.example.safe"
    rel = "SER1/runs/run1/org.example.safe/Safe_v7_7.0/org_example_safe_7__base.apk"
    apk_path = root / "device_apks" / rel
    sha = _write_apk(apk_path, b"safe-sidecar-gap")
    canonical_rel = f"data/store/apk/sha256/{sha[:2]}/{sha}.apk"
    _write_apk(tmp_path / canonical_rel, b"safe-sidecar-gap")
    _write_manifest(apk_path.parent / "harvest_package_manifest.json", package_name=package, version_code="7")

    monkeypatch.setattr(storage_pressure, "_load_db_artifact_rows", lambda _core_q: [
        _db_row(package_name=package, sha=sha, data_root=(root / "device_apks").as_posix(), local_rel_path="db/other/path.apk", version_code="7")
    ])
    monkeypatch.setattr(storage_pressure, "_load_storage_roots", lambda _core_q: [
        {"root_id": 1, "host_name": "test", "data_root": (root / "device_apks").as_posix()}
    ])
    monkeypatch.setattr(storage_pressure, "_load_install_set_summary_by_hash", lambda _core_q, _lineage: {
        sha: {
            "apk_set_id": 7,
            "member_count": 1,
            "split_count": 0,
            "completeness_state": "complete",
        }
    })
    monkeypatch.setattr(
        storage_pressure,
        "_load_install_set_table_summary",
        lambda _core_q, _lineage: _install_set_table_summary(total=1, complete=1),
    )
    monkeypatch.setattr(lineage, "fetch_base_rows", lambda _core_q, package_name=None: [])

    audit = storage_pressure.build_storage_pressure_audit(core_q=object(), data_root=root, verify_candidates=False)
    report = storage_pressure.build_blocked_sidecar_report(core_q=object(), data_root=root, audit=audit)

    assert audit["thin_session_rollout_gate"]["blocked_missing_sidecar_files"] == 1
    row = report["rows"][0]
    assert row["package_name"] == package
    assert row["package_name_source"] == "manifest"
    assert row["manifest_present"] is True
    assert row["canonical_exists"] is True
    assert row["db_identity_known"] is True
    assert row["safe_sidecar_reconstruction_possible"] is True
    assert row["recommended_action"] == "rebuild_sidecar_from_manifest_and_hash"
    assert report["summary"]["safe_reconstruction_candidates"] == 1


def test_blocked_sidecar_report_flags_orphan_session_file(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "data"
    rel = "SER1/runs/run1/com.example.orphan.apk"
    apk_path = root / "device_apks" / rel
    _write_apk(apk_path, b"orphan-apk")

    monkeypatch.setattr(storage_pressure, "_load_db_artifact_rows", lambda _core_q: [])
    monkeypatch.setattr(storage_pressure, "_load_storage_roots", lambda _core_q: [
        {"root_id": 1, "host_name": "test", "data_root": (root / "device_apks").as_posix()}
    ])
    monkeypatch.setattr(storage_pressure, "_load_install_set_summary_by_hash", lambda _core_q, _lineage: {})
    monkeypatch.setattr(
        storage_pressure,
        "_load_install_set_table_summary",
        lambda _core_q, _lineage: _install_set_table_summary(total=0, complete=0),
    )
    monkeypatch.setattr(lineage, "fetch_base_rows", lambda _core_q, package_name=None: [])

    audit = storage_pressure.build_storage_pressure_audit(core_q=object(), data_root=root, verify_candidates=False)
    report = storage_pressure.build_blocked_sidecar_report(core_q=object(), data_root=root, audit=audit)

    row = report["rows"][0]
    assert row["manifest_present"] is False
    assert row["package_name"] == "com.example.orphan"
    assert row["package_name_source"] == "filename"
    assert row["safe_sidecar_reconstruction_possible"] is False
    assert row["recommended_action"] == "investigate_orphan_session_file"
    assert row["note"] == "orphan_session_file_outside_package_dir"


def test_storage_pressure_ignores_apk_named_directories(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "data"
    bogus_dir = root / "device_apks" / "SER1" / "runs" / "run1" / "com.google.android.appsearch.apk"
    bogus_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(storage_pressure, "_load_db_artifact_rows", lambda _core_q: [])
    monkeypatch.setattr(storage_pressure, "_load_storage_roots", lambda _core_q: [
        {"root_id": 1, "host_name": "test", "data_root": (root / "device_apks").as_posix()}
    ])
    monkeypatch.setattr(storage_pressure, "_load_install_set_summary_by_hash", lambda _core_q, _lineage: {})
    monkeypatch.setattr(
        storage_pressure,
        "_load_install_set_table_summary",
        lambda _core_q, _lineage: _install_set_table_summary(total=0, complete=0),
    )
    monkeypatch.setattr(lineage, "fetch_base_rows", lambda _core_q, package_name=None: [])

    audit = storage_pressure.build_storage_pressure_audit(core_q=object(), data_root=root, verify_candidates=False)

    assert audit["summary"]["session_regular_apk_files"] == 0
    assert audit["summary"]["eligible_unverified_files"] == 0
    assert audit["session_pressure"]["rows"] == []


def test_storage_pressure_exposes_status_counts_and_inode_accounting(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path / "data"
    data_root = (root / "device_apks").as_posix()

    rel_shared = "SER1/runs/run1/com.example.shared/Shared_v1/com_example_shared_1__base.apk"
    session_shared = root / "device_apks" / rel_shared
    shared_payload = b"shared-hardlink"
    shared_sha = _write_apk(session_shared, shared_payload)
    canonical_shared_rel = f"data/store/apk/sha256/{shared_sha[:2]}/{shared_sha}.apk"
    canonical_shared = tmp_path / canonical_shared_rel
    canonical_shared.parent.mkdir(parents=True, exist_ok=True)
    os.link(session_shared, canonical_shared)
    _write_sidecar(
        session_shared.with_suffix(".apk.meta.json"),
        package_name="com.example.shared",
        version_code="1",
        sha=shared_sha,
        canonical_rel=canonical_shared_rel,
        local_rel=rel_shared,
    )
    _write_manifest(session_shared.parent / "harvest_package_manifest.json", package_name="com.example.shared", version_code="1")

    rel_copy = "SER1/runs/run1/com.example.copy/Copy_v2/com_example_copy_2__base.apk"
    session_copy = root / "device_apks" / rel_copy
    copy_payload = b"distinct-copy"
    copy_sha = _write_apk(session_copy, copy_payload)
    canonical_copy_rel = f"data/store/apk/sha256/{copy_sha[:2]}/{copy_sha}.apk"
    canonical_copy = tmp_path / canonical_copy_rel
    _write_apk(canonical_copy, copy_payload)
    _write_sidecar(
        session_copy.with_suffix(".apk.meta.json"),
        package_name="com.example.copy",
        version_code="2",
        sha=copy_sha,
        canonical_rel=canonical_copy_rel,
        local_rel=rel_copy,
    )
    _write_manifest(session_copy.parent / "harvest_package_manifest.json", package_name="com.example.copy", version_code="2")

    monkeypatch.setattr(storage_pressure, "_load_db_artifact_rows", lambda _core_q: [
        _db_row(package_name="com.example.shared", sha=shared_sha, data_root=data_root, local_rel_path=rel_shared),
        _db_row(package_name="com.example.copy", sha=copy_sha, data_root=data_root, local_rel_path=rel_copy, version_code="2"),
    ])
    monkeypatch.setattr(storage_pressure, "_load_storage_roots", lambda _core_q: [
        {"root_id": 1, "host_name": "test", "data_root": data_root}
    ])
    monkeypatch.setattr(storage_pressure, "_load_install_set_summary_by_hash", lambda _core_q, _lineage: {})
    monkeypatch.setattr(
        storage_pressure,
        "_load_install_set_table_summary",
        lambda _core_q, _lineage: _install_set_table_summary(total=0, complete=0),
    )
    monkeypatch.setattr(lineage, "fetch_base_rows", lambda _core_q, package_name=None: [])

    audit = storage_pressure.build_storage_pressure_audit(core_q=object(), data_root=root, verify_candidates=False)

    assert audit["status_counts"] == {"eligible_unverified": 2}
    assert audit["classification_counts"] == {"eligible_unverified": 2}
    assert audit["summary"]["session_files_hardlinked_to_canonical"] == 1
    assert audit["summary"]["session_files_distinct_from_canonical"] == 1
    assert audit["summary"]["physical_reclaimable_bytes_estimate"] > 0
    assert audit["summary"]["shared_inode_reclaimable_bytes_estimate"] > 0
    inode = audit["inode_accounting"]
    assert inode["inodes_seen_in_both_session_and_canonical"] == 1
    assert inode["canonical_only_inodes"] == 1


def test_thin_session_gate_passes_for_all_symlink_session_with_policy_blocked_manifest(tmp_path: Path) -> None:
    root = tmp_path / "data"
    session_label = "SER1-20260626-170424-973587"
    rel = f"SER1/runs/{session_label}/com.example.good/Good_v1/com_example_good_1__base.apk"
    session_apk = root / "device_apks" / rel
    payload = b"good"
    sha = sha256(payload).hexdigest()
    canonical_rel = f"data/store/apk/sha256/{sha[:2]}/{sha}.apk"
    canonical_path = tmp_path / canonical_rel
    _write_apk(canonical_path, payload)
    _write_symlink(session_apk, canonical_path)
    _write_sidecar(
        session_apk.with_suffix(".apk.meta.json"),
        package_name="com.example.good",
        version_code="1",
        sha=sha,
        canonical_rel=canonical_rel,
        local_rel=rel,
        session_label=session_label,
    )
    _write_manifest_with_observed(
        session_apk.parent / "harvest_package_manifest.json",
        package_name="com.example.good",
        version_code="1",
        observed_artifacts=[_observed_entry(local_rel=rel, canonical_rel=canonical_rel, sha=sha)],
        session_label=session_label,
    )
    _write_manifest_with_observed(
        root / "device_apks" / "SER1" / "runs" / session_label / "com.example.blocked" / "Blocked_v2" / "harvest_package_manifest.json",
        package_name="com.example.blocked",
        version_code="2",
        observed_artifacts=[],
        session_label=session_label,
    )

    report = storage_pressure.build_thin_session_gate_report(data_root=root, session_label=session_label)
    summary = report["summary"]

    assert summary["gate_pass"] is True
    assert summary["apk_paths_total"] == 1
    assert summary["regular_apk_files"] == 0
    assert summary["symlink_apk_files"] == 1
    assert summary["package_manifests"] == 2
    assert summary["package_manifests_with_observed_artifacts"] == 1
    assert summary["package_manifests_policy_or_empty"] == 1
    assert summary["observed_artifacts"] == 1
    assert summary["local_artifact_path_points_to_session_path"] == 1


def test_thin_session_gate_fails_when_regular_apk_present(tmp_path: Path) -> None:
    root = tmp_path / "data"
    session_label = "run1"
    rel = f"SER1/runs/{session_label}/com.example.regular/Regular_v1/com_example_regular_1__base.apk"
    session_apk = root / "device_apks" / rel
    payload = b"regular"
    sha = _write_apk(session_apk, payload)
    canonical_rel = f"data/store/apk/sha256/{sha[:2]}/{sha}.apk"
    _write_apk(tmp_path / canonical_rel, payload)
    _write_sidecar(
        session_apk.with_suffix(".apk.meta.json"),
        package_name="com.example.regular",
        version_code="1",
        sha=sha,
        canonical_rel=canonical_rel,
        local_rel=rel,
    )
    _write_manifest_with_observed(
        session_apk.parent / "harvest_package_manifest.json",
        package_name="com.example.regular",
        version_code="1",
        observed_artifacts=[_observed_entry(local_rel=rel, canonical_rel=canonical_rel, sha=sha)],
    )

    summary = storage_pressure.build_thin_session_gate_report(data_root=root, session_label=session_label)["summary"]
    assert summary["gate_pass"] is False
    assert "regular_apk_files_present" in summary["gate_fail_reasons"]


def test_thin_session_gate_fails_when_sidecar_missing(tmp_path: Path) -> None:
    root = tmp_path / "data"
    session_label = "run1"
    rel = f"SER1/runs/{session_label}/com.example.nosidecar/NoSidecar_v1/com_example_nosidecar_1__base.apk"
    session_apk = root / "device_apks" / rel
    payload = b"nosidecar"
    sha = sha256(payload).hexdigest()
    canonical_rel = f"data/store/apk/sha256/{sha[:2]}/{sha}.apk"
    canonical_path = tmp_path / canonical_rel
    _write_apk(canonical_path, payload)
    _write_symlink(session_apk, canonical_path)
    _write_manifest_with_observed(
        session_apk.parent / "harvest_package_manifest.json",
        package_name="com.example.nosidecar",
        version_code="1",
        observed_artifacts=[_observed_entry(local_rel=rel, canonical_rel=canonical_rel, sha=sha)],
    )

    summary = storage_pressure.build_thin_session_gate_report(data_root=root, session_label=session_label)["summary"]
    assert summary["gate_pass"] is False
    assert summary["missing_sidecars"] == 1
    assert "missing_sidecars" in summary["gate_fail_reasons"]


def test_thin_session_gate_fails_when_manifest_missing_for_apk_path(tmp_path: Path) -> None:
    root = tmp_path / "data"
    session_label = "run1"
    rel = f"SER1/runs/{session_label}/com.example.nomanifest/NoManifest_v1/com_example_nomanifest_1__base.apk"
    session_apk = root / "device_apks" / rel
    payload = b"nomanifest"
    sha = sha256(payload).hexdigest()
    canonical_rel = f"data/store/apk/sha256/{sha[:2]}/{sha}.apk"
    canonical_path = tmp_path / canonical_rel
    _write_apk(canonical_path, payload)
    _write_symlink(session_apk, canonical_path)
    _write_sidecar(
        session_apk.with_suffix(".apk.meta.json"),
        package_name="com.example.nomanifest",
        version_code="1",
        sha=sha,
        canonical_rel=canonical_rel,
        local_rel=rel,
    )

    summary = storage_pressure.build_thin_session_gate_report(data_root=root, session_label=session_label)["summary"]
    assert summary["gate_pass"] is False
    assert summary["missing_manifests_for_apk_paths"] == 1
    assert "missing_manifests_for_apk_paths" in summary["gate_fail_reasons"]


def test_thin_session_gate_fails_when_canonical_blob_missing(tmp_path: Path) -> None:
    root = tmp_path / "data"
    session_label = "run1"
    rel = f"SER1/runs/{session_label}/com.example.missingblob/MissingBlob_v1/com_example_missingblob_1__base.apk"
    session_apk = root / "device_apks" / rel
    payload = b"missingblob"
    sha = sha256(payload).hexdigest()
    canonical_rel = f"data/store/apk/sha256/{sha[:2]}/{sha}.apk"
    canonical_path = tmp_path / canonical_rel
    _write_symlink(session_apk, canonical_path)
    _write_sidecar(
        session_apk.with_suffix(".apk.meta.json"),
        package_name="com.example.missingblob",
        version_code="1",
        sha=sha,
        canonical_rel=canonical_rel,
        local_rel=rel,
    )
    _write_manifest_with_observed(
        session_apk.parent / "harvest_package_manifest.json",
        package_name="com.example.missingblob",
        version_code="1",
        observed_artifacts=[_observed_entry(local_rel=rel, canonical_rel=canonical_rel, sha=sha)],
    )

    summary = storage_pressure.build_thin_session_gate_report(data_root=root, session_label=session_label)["summary"]
    assert summary["gate_pass"] is False
    assert summary["canonical_blobs_missing"] == 1
    assert "canonical_blobs_missing" in summary["gate_fail_reasons"]


def test_thin_session_gate_fails_when_symlink_target_outside_canonical_store(tmp_path: Path) -> None:
    root = tmp_path / "data"
    session_label = "run1"
    rel = f"SER1/runs/{session_label}/com.example.outside/Outside_v1/com_example_outside_1__base.apk"
    session_apk = root / "device_apks" / rel
    payload = b"outside"
    sha = sha256(payload).hexdigest()
    outside_target = tmp_path / "other-store" / "outside.apk"
    _write_apk(outside_target, payload)
    canonical_rel = f"data/store/apk/sha256/{sha[:2]}/{sha}.apk"
    _write_symlink(session_apk, outside_target)
    _write_sidecar(
        session_apk.with_suffix(".apk.meta.json"),
        package_name="com.example.outside",
        version_code="1",
        sha=sha,
        canonical_rel=canonical_rel,
        local_rel=rel,
    )
    _write_manifest_with_observed(
        session_apk.parent / "harvest_package_manifest.json",
        package_name="com.example.outside",
        version_code="1",
        observed_artifacts=[_observed_entry(local_rel=rel, canonical_rel=canonical_rel, sha=sha)],
    )

    summary = storage_pressure.build_thin_session_gate_report(data_root=root, session_label=session_label)["summary"]
    assert summary["gate_pass"] is False
    assert summary["symlink_targets_outside_canonical_store"] == 1
    assert "symlink_targets_outside_canonical_store" in summary["gate_fail_reasons"]


def test_thin_session_gate_fails_when_local_artifact_path_points_elsewhere(tmp_path: Path) -> None:
    root = tmp_path / "data"
    session_label = "run1"
    rel = f"SER1/runs/{session_label}/com.example.localpath/LocalPath_v1/com_example_localpath_1__base.apk"
    session_apk = root / "device_apks" / rel
    payload = b"localpath"
    sha = sha256(payload).hexdigest()
    canonical_rel = f"data/store/apk/sha256/{sha[:2]}/{sha}.apk"
    canonical_path = tmp_path / canonical_rel
    _write_apk(canonical_path, payload)
    _write_symlink(session_apk, canonical_path)
    _write_sidecar(
        session_apk.with_suffix(".apk.meta.json"),
        package_name="com.example.localpath",
        version_code="1",
        sha=sha,
        canonical_rel=canonical_rel,
        local_rel=rel,
    )
    _write_manifest_with_observed(
        session_apk.parent / "harvest_package_manifest.json",
        package_name="com.example.localpath",
        version_code="1",
        observed_artifacts=[
            _observed_entry(
                local_rel=f"SER1/runs/{session_label}/somewhere/else/base.apk",
                canonical_rel=canonical_rel,
                sha=sha,
            )
        ],
    )

    summary = storage_pressure.build_thin_session_gate_report(data_root=root, session_label=session_label)["summary"]
    assert summary["gate_pass"] is False
    assert summary["local_artifact_path_points_to_session_path"] == 0
    assert "observed_local_artifact_paths_not_pointing_to_session" in summary["gate_fail_reasons"]


def test_thin_session_gate_allows_split_package_with_multiple_artifacts(tmp_path: Path) -> None:
    root = tmp_path / "data"
    session_label = "run1"
    package_dir = root / "device_apks" / "SER1" / "runs" / session_label / "com.example.split" / "Split_v1"
    entries: list[dict[str, object]] = []
    for name, payload in [
        ("com_example_split_1__base.apk", b"split-base"),
        ("com_example_split_1__split_config.xhdpi.apk", b"split-xhdpi"),
    ]:
        rel = f"SER1/runs/{session_label}/com.example.split/Split_v1/{name}"
        session_apk = package_dir / name
        sha = sha256(payload).hexdigest()
        canonical_rel = f"data/store/apk/sha256/{sha[:2]}/{sha}.apk"
        canonical_path = tmp_path / canonical_rel
        _write_apk(canonical_path, payload)
        _write_symlink(session_apk, canonical_path)
        _write_sidecar(
            session_apk.with_suffix(".apk.meta.json"),
            package_name="com.example.split",
            version_code="1",
            sha=sha,
            canonical_rel=canonical_rel,
            local_rel=rel,
            session_label=session_label,
        )
        entries.append(_observed_entry(local_rel=rel, canonical_rel=canonical_rel, sha=sha, file_name=name))
    _write_manifest_with_observed(
        package_dir / "harvest_package_manifest.json",
        package_name="com.example.split",
        version_code="1",
        observed_artifacts=entries,
        session_label=session_label,
    )

    summary = storage_pressure.build_thin_session_gate_report(data_root=root, session_label=session_label)["summary"]
    assert summary["gate_pass"] is True
    assert summary["package_manifests"] == 1
    assert summary["observed_artifacts"] == 2
    assert summary["apk_paths_total"] == 2


def test_thin_session_gate_latest_session_selects_newest_directory_deterministically(tmp_path: Path) -> None:
    root = tmp_path / "data"
    old_label = "SER1-20260626-170424-000001"
    new_label = "SER1-20260626-170424-000002"
    for label, payload, offset in [
        (old_label, b"old", 10),
        (new_label, b"new", 20),
    ]:
        rel = f"SER1/runs/{label}/com.example.app/App_v1/com_example_app_1__base.apk"
        session_apk = root / "device_apks" / rel
        sha = sha256(payload).hexdigest()
        canonical_rel = f"data/store/apk/sha256/{sha[:2]}/{sha}.apk"
        canonical_path = tmp_path / canonical_rel
        _write_apk(canonical_path, payload)
        _write_symlink(session_apk, canonical_path)
        _write_sidecar(
            session_apk.with_suffix(".apk.meta.json"),
            package_name="com.example.app",
            version_code="1",
            sha=sha,
            canonical_rel=canonical_rel,
            local_rel=rel,
            session_label=label,
        )
        _write_manifest_with_observed(
            session_apk.parent / "harvest_package_manifest.json",
            package_name="com.example.app",
            version_code="1",
            observed_artifacts=[_observed_entry(local_rel=rel, canonical_rel=canonical_rel, sha=sha)],
            session_label=label,
        )
        session_dir = root / "device_apks" / "SER1" / "runs" / label
        os.utime(session_dir, (offset, offset))

    summary = storage_pressure.build_thin_session_gate_report(data_root=root, latest_session=True)["summary"]
    assert summary["session_label"] == new_label
