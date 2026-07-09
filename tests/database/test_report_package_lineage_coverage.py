"""Pure action-classification tests for the package lineage coverage report."""

from __future__ import annotations

from scripts.db import report_apk_lineage_availability as report


def test_missing_bytes_in_missing_root_recommends_restore() -> None:
    action = report._recommended_action(
        bytes_available=False,
        static_qualifying=0,
        dynamic_sessions=10,
        dynamic_unlinked=10,
        availability_state="MISSING_RESTORABLE_ROOT",
        app_version_present=True,
    )

    assert action == "restore_artifacts"


def test_available_dynamic_gap_recommends_analysis() -> None:
    action = report._recommended_action(
        bytes_available=True,
        static_qualifying=0,
        dynamic_sessions=3,
        dynamic_unlinked=3,
        availability_state="AVAILABLE_CANONICAL_ONLY",
        app_version_present=True,
    )

    assert action == "analyze_available_hash"


def test_exact_static_with_unlinked_dynamic_recommends_link_preview() -> None:
    action = report._recommended_action(
        bytes_available=True,
        static_qualifying=1,
        dynamic_sessions=3,
        dynamic_unlinked=3,
        availability_state="AVAILABLE_RECORDED_AND_CANONICAL",
        app_version_present=True,
    )

    assert action == "link_repair_preview_available"


def test_same_version_hash_change_promotes_review_action() -> None:
    packages = [
        {
            "recommended_actions": ["covered"],
            "recommended_action": "covered",
            "hashes": [
                {
                    "version_code": "1",
                    "version_name": "1.0",
                    "base_apk_sha256": "a" * 64,
                    "artifact_set_hash": "c" * 64,
                },
                {
                    "version_code": "1",
                    "version_name": "1.0",
                    "base_apk_sha256": "b" * 64,
                    "artifact_set_hash": "d" * 64,
                },
            ],
        }
    ]

    report._annotate_lineage_review_actions(packages)

    assert packages[0]["same_version_hash_changed_review"] is True
    assert "same_version_hash_changed_review" in packages[0]["recommended_actions"]
    assert packages[0]["recommended_action"] == "same_version_hash_changed_review"


def test_recovery_action_maps_missing_old_root_to_restore_old_root() -> None:
    from scripts.db import report_dynamic_static_recovery_plan as recovery

    action = recovery._recovery_action(
        {
            "recommended_action": "restore_artifacts",
            "recorded_storage_root": "/missing/old/root",
            "recorded_storage_root_exists": False,
            "canonical_store_file_available": False,
        },
        static_exact_coverage=0,
    )

    assert action == "restore_old_root"


def test_recovery_action_can_mark_missing_old_root_unrecoverable() -> None:
    from scripts.db import report_dynamic_static_recovery_plan as recovery

    action = recovery._recovery_action(
        {
            "recommended_action": "restore_artifacts",
            "recorded_storage_root": "/missing/old/root",
            "recorded_storage_root_exists": False,
            "canonical_store_file_available": False,
        },
        static_exact_coverage=0,
        old_root_policy="unrecoverable",
    )

    assert action == "historical_identity_only"


def test_recovery_operator_conclusion_unrecoverable_and_reharvest() -> None:
    from scripts.db import report_dynamic_static_recovery_plan as recovery

    rows = [
        {
            "recommended_action": "historical_identity_only",
            "dynamic_sessions": 139,
        },
        {
            "recommended_action": "explicit_reharvest",
            "dynamic_sessions": 1,
        },
    ]

    conclusion = recovery._operator_conclusion(rows)

    assert conclusion == [
        "No exact static analysis can be run for the 2 dynamic/static gap(s) from current local bytes.",
        "1 are historical identity only unless an external archive is explicitly provided.",
        "1 require explicit reharvest (1 dynamic session(s) affected).",
        "Dynamic link repair remains blocked for rows without exact completed static coverage.",
    ]


def test_pairing_eligibility_classification_and_dataset_use() -> None:
    from scripts.db import report_dynamic_static_pairing_eligibility as pairing

    assert (
        pairing._classify_session({"linked_exact_static": 1}, recovery_action=None)
        == "paired_exact_static"
    )
    assert (
        pairing._classify_session(
            {"unlinked_exact_static_available": 1},
            recovery_action=None,
        )
        == "unpaired_exact_static_available"
    )
    assert (
        pairing._classify_session(
            {"base_apk_sha256": "a" * 64},
            recovery_action="historical_identity_only",
        )
        == "historical_identity_only"
    )
    assert (
        pairing._classify_session(
            {"base_apk_sha256": "c" * 64},
            recovery_action="restore_old_root",
        )
        == "unpaired_restore_required"
    )
    assert (
        pairing._classify_session(
            {"base_apk_sha256": "b" * 64},
            recovery_action="explicit_reharvest",
        )
        == "unpaired_reharvest_required"
    )
    assert (
        pairing._dataset_use_for_classification("historical_identity_only")
        == "exclude_from_paired_analysis_missing_artifact"
    )
    assert (
        pairing._dataset_use_for_classification("unpaired_restore_required")
        == "exclude_from_paired_analysis_missing_artifact"
    )


def test_pairing_eligibility_restore_blocks_package_strict_pair_use() -> None:
    from scripts.db import report_dynamic_static_pairing_eligibility as pairing

    packages = pairing._package_summary(
        [
            {
                "package_name": "com.example",
                "classification": "paired_exact_static",
            },
            {
                "package_name": "com.example",
                "classification": "unpaired_restore_required",
            },
        ]
    )

    assert packages == [
        {
            "package_name": "com.example",
            "dynamic_sessions": 2,
            "paired_exact_static": 1,
            "unpaired_exact_static_available": 0,
            "historical_identity_only": 0,
            "unrecoverable_without_archive": 0,
            "restore_required": 1,
            "reharvest_required": 0,
            "bytes_available_but_static_missing": 0,
            "dynamic_only_valid": 0,
            "strict_quota_valid_pairs": 0,
            "strict_supplemental_pairs": 0,
            "invalid_dynamic": 0,
            "legacy_dynamic_unknown": 0,
            "recommended_dataset_use": "exclude_from_paired_analysis_missing_artifact",
        }
    ]


def test_pairing_eligibility_dataset_use_prefers_normalized_governance() -> None:
    from scripts.db import report_dynamic_static_pairing_eligibility as pairing

    assert (
        pairing._dataset_use_for_session(
            {
                "technical_validity_state": "TECH_VALID",
                "quota_state": "QUOTA_VALID",
            },
            classification="paired_exact_static",
        )
        == "strict_static_dynamic_pair"
    )
    assert (
        pairing._dataset_use_for_session(
            {
                "technical_validity_state": "TECH_VALID",
                "quota_state": "SUPPLEMENTAL_VALID",
            },
            classification="paired_exact_static",
        )
        == "paired_static_dynamic_supplemental_only"
    )
    assert (
        pairing._dataset_use_for_session(
            {
                "technical_validity_state": "TECH_INVALID",
                "quota_state": "QUOTA_INELIGIBLE",
            },
            classification="paired_exact_static",
        )
        == "exclude_invalid_dynamic"
    )
    assert (
        pairing._dataset_use_for_session(
            {
                "technical_validity_state": "TECH_LEGACY_UNKNOWN",
                "quota_state": "QUOTA_LEGACY_UNKNOWN",
            },
            classification="paired_exact_static",
        )
        == "exclude_legacy_dynamic_unknown"
    )


def test_pairing_eligibility_package_summary_tracks_governance_buckets() -> None:
    from scripts.db import report_dynamic_static_pairing_eligibility as pairing

    packages = pairing._package_summary(
        [
            {
                "package_name": "com.example",
                "classification": "paired_exact_static",
                "recommended_dataset_use": "strict_static_dynamic_pair",
            },
            {
                "package_name": "com.example",
                "classification": "paired_exact_static",
                "recommended_dataset_use": "paired_static_dynamic_supplemental_only",
            },
            {
                "package_name": "com.example",
                "classification": "paired_exact_static",
                "recommended_dataset_use": "exclude_invalid_dynamic",
            },
        ]
    )

    assert packages == [
        {
            "package_name": "com.example",
            "dynamic_sessions": 3,
            "paired_exact_static": 3,
            "unpaired_exact_static_available": 0,
            "historical_identity_only": 0,
            "unrecoverable_without_archive": 0,
            "restore_required": 0,
            "reharvest_required": 0,
            "bytes_available_but_static_missing": 0,
            "dynamic_only_valid": 0,
            "strict_quota_valid_pairs": 1,
            "strict_supplemental_pairs": 1,
            "invalid_dynamic": 1,
            "legacy_dynamic_unknown": 0,
            "recommended_dataset_use": "exclude_invalid_dynamic",
        }
    ]


def test_pairing_eligibility_report_bundle_splits_worklists(tmp_path) -> None:
    from scripts.db import report_dynamic_static_pairing_eligibility as pairing

    payload = {
        "report_type": "dynamic_static_pairing_eligibility",
        "schema_version": "1",
        "filters": {},
        "summary": {"dynamic_sessions": 3},
        "packages": [
            {
                "package_name": "com.example.old",
                "historical_identity_only": 1,
                "reharvest_required": 0,
            }
        ],
        "sessions": [
            {
                "dynamic_run_id": "old-1",
                "package_name": "com.example.old",
                "classification": "historical_identity_only",
            },
            {
                "dynamic_run_id": "reharvest-1",
                "package_name": "com.example.current",
                "classification": "unpaired_reharvest_required",
            },
            {
                "dynamic_run_id": "static-1",
                "package_name": "com.example.ready",
                "classification": "unpaired_static_missing_but_bytes_available",
            },
        ],
        "notes": [],
    }

    files = pairing._write_report_bundle(payload, output_dir=tmp_path)

    assert sorted(files) == [
        "historical_identity_only_csv",
        "packages_csv",
        "reharvest_candidates_csv",
        "sessions_csv",
        "static_analysis_candidates_csv",
        "summary_json",
    ]
    assert "old-1" in (tmp_path / "historical_identity_only.csv").read_text()
    assert "reharvest-1" in (tmp_path / "reharvest_candidates.csv").read_text()
    assert "static-1" in (tmp_path / "static_analysis_candidates.csv").read_text()
    assert '"output_files"' in (tmp_path / "summary.json").read_text()


def test_recovery_action_recorded_bytes_without_canonical_rehydrates_store() -> None:
    from scripts.db import report_dynamic_static_recovery_plan as recovery

    action = recovery._recovery_action(
        {
            "recommended_action": "exact_static_available",
            "recorded_local_file_available": True,
            "canonical_store_file_available": False,
        },
        static_exact_coverage=0,
    )

    assert action == "analyze_exact_static_available"

    action = recovery._recovery_action(
        {
            "recommended_action": "restore_artifacts",
            "recorded_local_file_available": True,
            "canonical_store_file_available": False,
        },
        static_exact_coverage=0,
    )

    assert action == "rehydrate_canonical_store"


def test_recovery_action_static_coverage_wins() -> None:
    from scripts.db import report_dynamic_static_recovery_plan as recovery

    action = recovery._recovery_action(
        {"recommended_action": "restore_artifacts"},
        static_exact_coverage=1,
    )

    assert action == "no_action_already_covered"


def test_recovery_root_summary_groups_actions() -> None:
    from scripts.db import report_dynamic_static_recovery_plan as recovery

    roots = recovery._root_summary(
        [
            {
                "recorded_root": "/old",
                "recorded_root_exists": False,
                "recommended_action": "restore_old_root",
                "dynamic_sessions": 2,
            },
            {
                "recorded_root": "/old",
                "recorded_root_exists": False,
                "recommended_action": "restore_old_root",
                "dynamic_sessions": 3,
            },
        ]
    )

    assert roots == [
        {
            "recorded_root": "/old",
            "root_exists": False,
            "hashes": 2,
            "dynamic_sessions": 5,
            "actions": {"restore_old_root": 2},
        }
    ]


def test_recovery_plan_receipt_write_is_explicit(tmp_path) -> None:
    from scripts.db import report_dynamic_static_recovery_plan as recovery

    payload = {
        "receipt_type": "artifact_recovery_plan",
        "schema_version": "1",
        "created_at": "2026-05-14T12:00:00Z",
        "decision": "plan_only_no_apply",
        "filters": {"package_name": "com.example.app", "old_root_policy": "unrecoverable"},
        "operator_notes": ["Legacy CARS2025 APK root retired; reharvest current corpus"],
        "operator_state": {"legacy_apk_root_retired": True},
        "summary": {"exact_gap_hashes": 1},
        "packages": [],
        "storage_roots": [],
        "gaps": [],
        "notes": [],
    }

    path = recovery._write_receipt(payload, receipt_dir=tmp_path)

    assert path.name == "20260514T120000_com.example.app.json"
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert '"decision": "plan_only_no_apply"' in text
    assert '"receipt_type": "artifact_recovery_plan"' in text


def test_recovery_plan_report_bundle_splits_action_worklists(tmp_path) -> None:
    from scripts.db import report_dynamic_static_recovery_plan as recovery

    payload = {
        "receipt_type": "artifact_recovery_plan",
        "schema_version": "1",
        "created_at": "2026-05-14T12:00:00Z",
        "summary": {"exact_gap_hashes": 2},
        "packages": [
            {
                "package_name": "com.example.old",
                "dynamic_sessions_affected": 3,
                "recommended_action": "historical_identity_only",
            }
        ],
        "storage_roots": [
            {
                "recorded_root": "/old",
                "root_exists": False,
                "hashes": 1,
                "dynamic_sessions": 3,
                "actions": {"historical_identity_only": 1},
            }
        ],
        "gaps": [
            {
                "package_name": "com.example.old",
                "base_apk_sha256": "a" * 64,
                "recommended_action": "historical_identity_only",
            },
            {
                "package_name": "com.example.current",
                "base_apk_sha256": "b" * 64,
                "recommended_action": "explicit_reharvest",
            },
        ],
        "notes": [],
    }

    files = recovery._write_report_bundle(payload, output_dir=tmp_path)

    assert sorted(files) == [
        "gaps_csv",
        "historical_identity_only_csv",
        "packages_csv",
        "reharvest_candidates_csv",
        "storage_roots_csv",
        "summary_json",
    ]
    assert "com.example.old" in (tmp_path / "historical_identity_only.csv").read_text()
    assert "com.example.current" not in (tmp_path / "historical_identity_only.csv").read_text()
    assert "com.example.current" in (tmp_path / "reharvest_candidates.csv").read_text()
    assert '""historical_identity_only"": 1' in (tmp_path / "storage_roots.csv").read_text()
    assert '"output_files"' in (tmp_path / "summary.json").read_text()


def test_static_target_dynamic_gap_missing_old_root_is_blocked() -> None:
    from scripts.db import report_static_analysis_targets as targets

    byte_status = targets._byte_status(
        recorded_exists=False,
        canonical_exists=False,
        recorded_root_exists=False,
        recorded_location_known=True,
    )
    status = targets._target_status(
        exact_static=0,
        byte_status=byte_status,
        split_status="unknown_until_bytes_restored",
        dynamic_unlinked=5,
        same_version_hash_drift=False,
    )
    reason = targets._target_reason(
        exact_static=0,
        byte_status=byte_status,
        dynamic_sessions=5,
        dynamic_unlinked=5,
        same_version_hash_drift=False,
    )

    assert byte_status == "missing_old_root"
    assert status == "blocked_missing_bytes"
    assert reason == "dynamic_static_gap"


def test_static_target_exact_static_with_unlinked_dynamic_is_link_preview() -> None:
    from scripts.db import report_static_analysis_targets as targets

    status = targets._target_status(
        exact_static=1,
        byte_status="available_canonical",
        split_status="install_set_known",
        dynamic_unlinked=2,
        same_version_hash_drift=False,
    )

    assert status == "link_repair_preview_available"


def test_static_target_static_covered_recorded_only_rebuilds_store() -> None:
    from scripts.db import report_static_analysis_targets as targets

    status = targets._target_status(
        exact_static=1,
        byte_status="available_recorded",
        split_status="install_set_known",
        dynamic_unlinked=0,
        same_version_hash_drift=False,
    )

    assert status == "rebuild_canonical_store"


def test_static_target_static_covered_missing_current_root_is_artifact_lifecycle() -> None:
    from scripts.db import report_static_analysis_targets as targets

    status = targets._target_status(
        exact_static=1,
        byte_status="missing_current_root_file",
        split_status="unknown_until_bytes_restored",
        dynamic_unlinked=0,
        same_version_hash_drift=False,
    )
    reason = targets._target_reason(
        exact_static=1,
        byte_status="missing_current_root_file",
        dynamic_sessions=0,
        dynamic_unlinked=0,
        same_version_hash_drift=False,
    )

    assert reason == "artifact_lifecycle_gap"
    assert status == "artifact_lifecycle_gap"
    assert targets._operator_action(status) == "Restore or reharvest bytes"


def test_workbench_action_mapping_keeps_states_distinct() -> None:
    from scripts.db import report_package_lineage_workbench as workbench

    assert workbench._workbench_action("covered") == "already_covered"
    assert workbench._workbench_action("ready") == "analyze_exact_static"
    assert workbench._workbench_action("blocked_missing_bytes") == "restore_artifacts"
    assert workbench._workbench_action("needs_reharvest") == "reharvest_required"
    assert workbench._workbench_action("artifact_lifecycle_gap") == "restore_artifacts"
    assert (
        workbench._workbench_action("link_repair_preview_available")
        == "dynamic_link_preview_available"
    )


def test_workbench_actionable_filter_keeps_lifecycle_gap() -> None:
    from scripts.db import report_package_lineage_workbench as workbench

    assert (
        workbench._is_actionable(
            {
                "recommended_action": "already_covered",
                "bytes_available": True,
                "unpaired_dynamic_sessions": 0,
                "exact_static_dynamic_gap": False,
                "review_flags": [],
            }
        )
        is False
    )
    assert (
        workbench._is_actionable(
            {
                "recommended_action": "already_covered",
                "bytes_available": False,
                "unpaired_dynamic_sessions": 0,
                "exact_static_dynamic_gap": False,
                "review_flags": [],
            }
        )
        is True
    )


def test_workbench_summary_counts_actions_and_availability() -> None:
    from scripts.db import report_package_lineage_workbench as workbench

    summary = workbench._summary(
        [
            {
                "version_code": "1",
                "version_name": "1.0",
                "apk_set_id": 10,
                "bytes_available": True,
                "static_coverage_state": "covered",
                "dynamic_sessions": 2,
                "paired_dynamic_sessions": 1,
                "exact_static_dynamic_gap": False,
                "recommended_action": "already_covered",
                "target_status": "covered",
                "availability_state": "available_canonical",
            },
            {
                "version_code": "2",
                "version_name": "2.0",
                "apk_set_id": None,
                "bytes_available": False,
                "static_coverage_state": "covered",
                "dynamic_sessions": 0,
                "paired_dynamic_sessions": 0,
                "exact_static_dynamic_gap": False,
                "recommended_action": "restore_artifacts",
                "target_status": "artifact_lifecycle_gap",
                "availability_state": "missing_current_root_file",
            },
        ],
        package_name="com.example.app",
    )

    assert summary["static_covered_missing_bytes"] == 1
    assert summary["action_counts"] == {"already_covered": 1, "restore_artifacts": 1}
    assert summary["availability_counts"] == {
        "available_canonical": 1,
        "missing_current_root_file": 1,
    }
