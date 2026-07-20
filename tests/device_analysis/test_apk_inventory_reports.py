from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from scripts.device_analysis import repair_apk_library_logical_paths as logical_repair
from scripts.device_analysis import repair_regular_legacy_apks as regular_repair
from scripts.device_analysis import report_apk_inventory_model as inventory
from scripts.device_analysis import report_apk_transition_debt as transition_debt
from scripts.device_analysis import report_legacy_harvest_run_retirement as retirement
from scripts.device_analysis import verify_apk_library_integrity as verifier
from scytaledroid.DeviceAnalysis.services import apk_library_service, artifact_store
from tests.device_analysis._harvest_runner_support import isolate_storage_contract


def _canonical_path(data: Path, digest: str) -> Path:
    return data / "store" / "apk" / "sha256" / digest[:2] / f"{digest}.apk"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _build_fixture(tmp_path: Path) -> tuple[Path, Path, str, str]:
    data = tmp_path / "repo" / "data"
    cold_root = tmp_path / "mnt" / "MERCURY_DATA_V2" / "scytaledroid_artifacts" / "apk_store" / "cold"
    hot_sha = sha256(b"hot").hexdigest()
    cold_sha = sha256(b"cold").hexdigest()
    hot_path = _canonical_path(data, hot_sha)
    hot_path.parent.mkdir(parents=True, exist_ok=True)
    hot_path.write_bytes(b"hot")
    cold_target = cold_root / "data" / "store" / "apk" / "sha256" / cold_sha[:2] / f"{cold_sha}.apk"
    cold_target.parent.mkdir(parents=True, exist_ok=True)
    cold_target.write_bytes(b"cold")
    cold_link = _canonical_path(data, cold_sha)
    cold_link.parent.mkdir(parents=True, exist_ok=True)
    cold_link.symlink_to(cold_target)
    content_hash = apk_library_service._content_split_set_hash(
        [
            {"role": "base", "split_name": "base", "sha256": hot_sha},
            {"role": "split", "split_name": "split_config.en", "sha256": cold_sha},
        ]
    )

    split_dir = data / "android_apks" / "packages" / "com.example" / "1" / "split_sets" / "split-a"
    _write_json(
        split_dir / "package_manifest.json",
        {
            "package_name": "com.example",
            "version_code": "1",
            "version_name": "1.0",
            "planned_split_set_hash": "split-a",
            "split_set_hash": content_hash,
            "source_device_serials": ["SER1"],
            "artifacts": [
                {
                    "role": "base",
                    "split_name": "base",
                    "file_name": "base.apk",
                    "sha256": hot_sha,
                    "size_bytes": 3,
                    "canonical_path": f"data/store/apk/sha256/{hot_sha[:2]}/{hot_sha}.apk",
                },
                {
                    "role": "split",
                    "split_name": "split_config.en",
                    "file_name": "split.apk",
                    "sha256": cold_sha,
                    "size_bytes": 4,
                    "canonical_path": f"data/store/apk/sha256/{cold_sha[:2]}/{cold_sha}.apk",
                },
            ],
        },
    )
    (split_dir / "artifacts.csv").write_text(
        "\n".join(
            [
                "role,split_name,file_name,device_path,sha256,size_bytes,canonical_path",
                f"base,base,base.apk,,{hot_sha},3,data/store/apk/sha256/{hot_sha[:2]}/{hot_sha}.apk",
                f"split,split_config.en,split.apk,,{cold_sha},4,data/store/apk/sha256/{cold_sha[:2]}/{cold_sha}.apk",
                "",
            ]
        ),
        encoding="utf-8",
    )
    _write_json(
        data / "android_apks" / "packages" / "com.example" / "1" / "package_manifest.json",
        {"package_name": "com.example", "version_code": "1", "version_name": "1.0", "split_sets": ["split-a"]},
    )

    receipt = {
        "package": {"package_name": "com.seed", "version_code": "2", "version_name": "2.0", "device_serial": "SER1"},
        "execution": {
            "observed_artifacts": [
                {
                    "is_base": True,
                    "split_label": "base",
                    "sha256": hot_sha,
                    "canonical_store_path": f"data/store/apk/sha256/{hot_sha[:2]}/{hot_sha}.apk",
                }
            ]
        },
    }
    _write_json(data / "receipts" / "harvest" / "run-1" / "com.seed.json", receipt)
    manifest = {
        "package": {"package_name": "com.example", "version_code": "1"},
        "execution": {"observed_artifacts": [{"sha256": hot_sha}]},
    }
    _write_json(data / "device_apks" / "SER1" / "runs" / "run-1" / "com.example" / "harvest_package_manifest.json", manifest)
    legacy_apk = data / "device_apks" / "SER1" / "runs" / "run-1" / "com.example" / "base.apk"
    legacy_apk.symlink_to(hot_path)
    return data, cold_root, hot_sha, cold_sha


def test_inventory_report_merges_library_receipts_and_byte_state(tmp_path: Path) -> None:
    data, cold_root, _hot_sha, _cold_sha = _build_fixture(tmp_path)

    report = inventory.build_report(data_root=data, cold_root=cold_root, write_outputs=False)

    summary = report["summary"]
    assert summary["total_packages"] == 1
    assert summary["total_split_sets"] == 1
    assert summary["hot_local_blobs"] == 1
    assert summary["cold_mercury_blobs"] == 1
    assert summary["versions_missing_from_android_apks_but_seedable_from_receipts"] == 1
    assert summary["receipt_rows_blocked_by_planned_split_set_collision"] == 0
    assert report["split_sets"][0]["byte_status"] == "mixed_hot_cold"


def test_inventory_report_separates_planned_hash_content_collisions(tmp_path: Path) -> None:
    data = tmp_path / "repo" / "data"
    cold_root = tmp_path / "mnt" / "MERCURY_DATA_V2" / "scytaledroid_artifacts" / "apk_store" / "cold"
    old_sha = sha256(b"old").hexdigest()
    new_sha = sha256(b"new").hexdigest()
    for digest, content in ((old_sha, b"old"), (new_sha, b"new")):
        path = _canonical_path(data, digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    receipt = {
        "package": {"package_name": "com.variant", "version_code": "1", "version_name": "1.0", "device_serial": "SER1"},
        "inventory": {
            "apk_paths": ["/data/app/com.variant/base.apk"],
            "primary_path": "/data/app/com.variant/base.apk",
            "split_count": 1,
        },
        "planning": {
            "expected_artifacts": [
                {
                    "file_name": "com_variant_1__base.apk",
                    "is_base": True,
                    "planned_source_path": "/data/app/com.variant/base.apk",
                    "split_label": "base",
                }
            ],
            "total_paths": 1,
        },
        "execution": {
            "observed_artifacts": [
                {
                    "file_name": "com_variant_1__base.apk",
                    "split_label": "base",
                    "is_base": True,
                    "sha256": new_sha,
                    "canonical_store_path": f"data/store/apk/sha256/{new_sha[:2]}/{new_sha}.apk",
                }
            ]
        },
    }
    plan = apk_library_service._plan_from_legacy_receipt(receipt)
    assert plan is not None
    planned_hash = apk_library_service.planned_split_set_hash_for_plan(plan)
    existing_content_hash = apk_library_service._content_split_set_hash(
        [{"role": "base", "split_name": "base", "sha256": old_sha}]
    )
    split_dir = data / "android_apks" / "packages" / "com.variant" / "1" / "split_sets" / planned_hash
    _write_json(
        split_dir / "package_manifest.json",
        {
            "package_name": "com.variant",
            "version_code": "1",
            "version_name": "1.0",
            "planned_split_set_hash": planned_hash,
            "split_set_hash": existing_content_hash,
            "artifacts": [
                {
                    "role": "base",
                    "split_name": "base",
                    "file_name": "com_variant_1__base.apk",
                    "sha256": old_sha,
                    "size_bytes": 3,
                    "canonical_path": f"data/store/apk/sha256/{old_sha[:2]}/{old_sha}.apk",
                }
            ],
        },
    )
    _write_json(
        data / "android_apks" / "packages" / "com.variant" / "1" / "package_manifest.json",
        {"package_name": "com.variant", "version_code": "1", "version_name": "1.0", "split_sets": [planned_hash]},
    )
    _write_json(data / "receipts" / "harvest" / "run-variant" / "com.variant.json", receipt)

    report = inventory.build_report(data_root=data, cold_root=cold_root, write_outputs=False)

    summary = report["summary"]
    assert summary["versions_missing_from_android_apks_but_seedable_from_receipts"] == 0
    assert summary["receipt_rows_blocked_by_planned_split_set_collision"] == 1
    assert report["content_variant_collisions"][0]["reason"] == "planned_split_set_hash_collision"


def test_legacy_retirement_report_marks_storage_safe_session(tmp_path: Path) -> None:
    data, cold_root, _hot_sha, _cold_sha = _build_fixture(tmp_path)

    report = retirement.build_report(data_root=data, cold_root=cold_root, write_outputs=False, run_sql=_zero_reference_sql)

    assert report["summary"]["session_count"] == 1
    assert report["summary"]["archive_candidate_count"] == 1
    assert report["rows"][0]["regular_apks"] == 0
    assert report["rows"][0]["all_apk_artifacts_indexed_in_apk_library"] == "yes"
    assert report["rows"][0]["retirement_class"] == "ARCHIVE_CANDIDATE_STORAGE_SAFE_DB_CLEAR"


def test_transition_debt_report_rolls_up_storage_and_model_state(tmp_path: Path) -> None:
    data, cold_root, _hot_sha, _cold_sha = _build_fixture(tmp_path)

    report = transition_debt.build_report(data_root=data, cold_root=cold_root, serial="SER1", write_outputs=False)

    assert report["summary"]["canonical_apk_blobs"] == 2
    assert report["summary"]["library_artifact_rows"] == 2
    assert report["summary"]["regular_legacy_apk_count"] == 0
    assert report["summary"]["legacy_session_count"] == 1
    assert report["summary"]["status"] == "OK"
    assert report["issues"] == []


def test_transition_debt_report_marks_represented_regular_legacy_apks(tmp_path: Path) -> None:
    data, cold_root, hot_sha, _cold_sha = _build_fixture(tmp_path)
    regular = data / "device_apks" / "SER1" / "runs" / "run-regular" / "com.example" / "base.apk"
    regular.parent.mkdir(parents=True)
    regular.write_bytes(b"hot")

    report = transition_debt.build_report(data_root=data, cold_root=cold_root, serial="SER1", write_outputs=False)

    assert report["summary"]["regular_legacy_apk_count"] == 1
    assert report["summary"]["regular_legacy_apk_represented_count"] == 1
    assert report["summary"]["regular_legacy_apk_unrepresented_count"] == 0
    row = report["regular_legacy_apks"][0]
    assert row["sha256"] == hot_sha
    assert row["apk_library_representation"] == "full"
    assert row["reason"] == "legacy_regular_apk_represented_but_unthinned"


def test_regular_legacy_apk_repair_canonicalizes_and_indexes_without_deleting_legacy_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    isolate_storage_contract(tmp_path, monkeypatch)
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

    rows = regular_repair.build_rows(
        data_root=data_root,
        serial="SER1",
        artifact_store=artifact_store,
        apk_library_service=apk_library_service,
    )

    assert len(rows) == 1
    assert rows[0]["action"] == "copy_to_canonical_and_index"
    assert rows[0]["safe_to_canonicalize"] is True

    regular_repair.apply_rows(rows, artifact_store=artifact_store, apk_library_service=apk_library_service)

    canonical = artifact_store.canonical_apk_path(digest)
    assert canonical.exists()
    assert canonical.read_bytes() == apk_bytes
    assert legacy_apk.exists()
    assert rows[0]["applied"] is True
    assert rows[0]["library_manifest_path"]
    assert Path(rows[0]["library_manifest_path"]).exists()


def test_transition_debt_cli_skips_sha256_by_default() -> None:
    args = transition_debt._build_parser().parse_args([])
    verify_args = transition_debt._build_parser().parse_args(["--verify-sha256"])

    assert args.verify_sha256 is False
    assert args.skip_sha256 is False
    assert verify_args.verify_sha256 is True


def test_apk_library_integrity_verifier_accepts_hot_and_cold_blobs(tmp_path: Path) -> None:
    data, _cold_root, hot_sha, _cold_sha = _build_fixture(tmp_path)
    _write_json(
        data / "android_apks" / "partial_artifacts" / "com.partial" / "1" / hot_sha / "artifact_manifest.json",
        {
            "package_name": "com.partial",
            "version_code": "1",
            "artifact": {
                "role": "base",
                "split_name": "base",
                "file_name": "base.apk",
                "sha256": hot_sha,
                "size_bytes": 3,
                "canonical_path": f"data/store/apk/sha256/{hot_sha[:2]}/{hot_sha}.apk",
            },
        },
    )

    report = verifier.build_report(data_root=data, write_outputs=False, verify_sha256=True)

    assert report["summary"]["status"] == "OK"
    assert report["summary"]["artifact_row_count"] == 3
    assert report["summary"]["partial_artifact_manifest_count"] == 1
    assert report["findings"] == []


def test_apk_library_integrity_verifier_blocks_missing_canonical_blob(tmp_path: Path) -> None:
    data, _cold_root, hot_sha, _cold_sha = _build_fixture(tmp_path)
    _canonical_path(data, hot_sha).unlink()

    report = verifier.build_report(data_root=data, write_outputs=False)

    assert report["summary"]["status"] == "BLOCKED"
    assert report["summary"]["missing_canonical_blob_count"] == 1
    assert any(row["finding_id"] == "MISSING_CANONICAL_BLOB" for row in report["findings"])


def test_apk_library_integrity_verifier_reports_artifacts_csv_drift(tmp_path: Path) -> None:
    data, _cold_root, _hot_sha, _cold_sha = _build_fixture(tmp_path)
    csv_path = data / "android_apks" / "packages" / "com.example" / "1" / "split_sets" / "split-a" / "artifacts.csv"
    payload = csv_path.read_text(encoding="utf-8").replace("split.apk", "wrong.apk")
    csv_path.write_text(payload, encoding="utf-8")

    report = verifier.build_report(data_root=data, write_outputs=False)

    assert report["summary"]["status"] == "WARN"
    assert report["summary"]["artifacts_csv_mismatch_count"] == 1
    assert any(row["finding_id"] == "ARTIFACTS_CSV_ROW_MISMATCH" for row in report["findings"])


def test_logical_path_repair_rewrites_absolute_cold_manifest_path(tmp_path: Path) -> None:
    data, cold_root, _hot_sha, cold_sha = _build_fixture(tmp_path)
    manifest = data / "android_apks" / "packages" / "com.example" / "1" / "split_sets" / "split-a" / "package_manifest.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    absolute_cold = cold_root / "data" / "store" / "apk" / "sha256" / cold_sha[:2] / f"{cold_sha}.apk"
    payload["artifacts"][1]["canonical_path"] = absolute_cold.as_posix()
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    dry_run = logical_repair.build_report(data_root=data, write_outputs=False)

    assert dry_run["summary"]["eligible_count"] == 1
    assert json.loads(manifest.read_text(encoding="utf-8"))["artifacts"][1]["canonical_path"] == absolute_cold.as_posix()

    applied = logical_repair.build_report(data_root=data, write_outputs=False, apply=True)

    logical = f"data/store/apk/sha256/{cold_sha[:2]}/{cold_sha}.apk"
    assert applied["summary"]["applied_count"] == 1
    assert json.loads(manifest.read_text(encoding="utf-8"))["artifacts"][1]["canonical_path"] == logical


def test_logical_path_repair_rewrites_artifacts_csv_path(tmp_path: Path) -> None:
    data, cold_root, _hot_sha, cold_sha = _build_fixture(tmp_path)
    csv_path = data / "android_apks" / "packages" / "com.example" / "1" / "split_sets" / "split-a" / "artifacts.csv"
    absolute_cold = cold_root / "data" / "store" / "apk" / "sha256" / cold_sha[:2] / f"{cold_sha}.apk"
    csv_path.write_text(
        "\n".join(
            [
                "role,split_name,file_name,device_path,sha256,size_bytes,canonical_path",
                f"split,split_config.en,split.apk,/data/app/split.apk,{cold_sha},4,{absolute_cold.as_posix()}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    dry_run = logical_repair.build_report(data_root=data, write_outputs=False)

    assert any(row["source_kind"] == "artifacts_csv" and row["status"] == "eligible" for row in dry_run["actions"])
    assert absolute_cold.as_posix() in csv_path.read_text(encoding="utf-8")

    applied = logical_repair.build_report(data_root=data, write_outputs=False, apply=True)

    logical = f"data/store/apk/sha256/{cold_sha[:2]}/{cold_sha}.apk"
    assert any(row["source_kind"] == "artifacts_csv" and row["status"] == "applied" for row in applied["actions"])
    assert logical in csv_path.read_text(encoding="utf-8")
    assert absolute_cold.as_posix() not in csv_path.read_text(encoding="utf-8")


def test_legacy_retirement_report_retains_static_referenced_session(tmp_path: Path) -> None:
    data, cold_root, _hot_sha, _cold_sha = _build_fixture(tmp_path)

    report = retirement.build_report(data_root=data, cold_root=cold_root, write_outputs=False, run_sql=_static_reference_sql)

    row = report["rows"][0]
    assert row["referenced_by_static"] == "yes"
    assert row["safe_to_archive_later"] == "no"
    assert row["retirement_class"] == "RETAIN_ACTIVE_STATIC_REFERENCE"


def test_legacy_retirement_report_blocks_when_db_unknown(tmp_path: Path) -> None:
    data, cold_root, _hot_sha, _cold_sha = _build_fixture(tmp_path)

    report = retirement.build_report(data_root=data, cold_root=cold_root, write_outputs=False, run_sql=None)

    row = report["rows"][0]
    assert row["referenced_by_static"] == "unknown"
    assert row["safe_to_archive_later"] == "no"
    assert row["retirement_class"] == "BLOCKED_UNKNOWN_DB_REFERENCE"


def _zero_reference_sql(_query: str, _params: tuple[object, ...] = (), **_kwargs: object) -> dict[str, int]:
    return {"n": 0}


def _static_reference_sql(query: str, _params: tuple[object, ...] = (), **_kwargs: object) -> dict[str, int]:
    if "FROM static_analysis_runs" in query:
        return {"n": 1}
    return {"n": 0}
