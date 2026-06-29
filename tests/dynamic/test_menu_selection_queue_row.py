from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DynamicAnalysis import menu_selection


class _Cfg:
    baseline_required = 3
    interactive_required = 4


def test_build_package_selection_row_accepts_live_build_drift_for_refresh_action() -> None:
    row = menu_selection.build_package_selection_row(
        idx=2,
        package="com.cnn.mobile.android.phone",
        app_label="CNN",
        collisions=set(),
        dataset_pkgs={"com.cnn.mobile.android.phone"},
        tracker_apps={
            "com.cnn.mobile.android.phone": {
                "runs": [
                    {
                        "run_id": "run-1",
                        "version_code": "19127521",
                        "base_sha256": "abc123",
                    }
                ]
            }
        },
        cfg=_Cfg(),
        recent_tracker_runs=lambda _package, limit=1: [
            SimpleNamespace(
                valid=False,
                run_id="run-1",
                invalid_reason_code="PCAP_MISSING",
                pcap_failure_detail="PCAP_LOCAL_FILE_MISSING",
            )
        ],
        live_build_drift={
            "observed_version_code": "19250507",
            "expected_version_code": "19127521",
            "expected_version_name": "8.4.50",
            "static_run_id": 4701,
        },
        db_lineage_context={"db_active_sessions": 1, "db_historical_sessions": 0, "db_total_sessions": 1},
        truncate_visible_fn=lambda value, _limit: value,
        bucket_progress_label_fn=lambda count, required, extra_count=0: f"{count}/{required}" + (f" +{extra_count}" if extra_count else ""),
        quota_progress_label_fn=lambda count, required, extra_count=0: f"{count}/{required}" + (f" +{extra_count}" if extra_count else ""),
        static_build_label_fn=lambda active_runs, legacy_valid: "current" if active_runs or not legacy_valid else "legacy",
        next_action_from_need_fn=lambda need: need,
        build_scoped_dataset_counts_fn=lambda _package, _runs, cfg: {
            "baseline_countable": 3,
            "baseline_extra": 0,
            "interactive_countable": 4,
            "interactive_extra": 0,
            "legacy_valid": 0,
            "legacy_builds": 0,
            "active_version_code": "19127521",
            "active_base_sha": "abc123",
            "technical_valid_active": 7,
        },
        resolve_tracker_run_identity_fn=lambda _package, run: (
            str(run.get("version_code") or "") or None,
            str(run.get("base_sha256") or "") or None,
        ),
    )

    assert row.live_build_drift is True
    assert row.full_row[5] == "refresh"
    assert row.next_label == "refresh static"
    assert row.prep_label == "stale"
