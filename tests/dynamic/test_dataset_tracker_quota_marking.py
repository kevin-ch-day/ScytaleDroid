from __future__ import annotations

from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import (
    BASELINE_REQUIRED,
    INTERACTION_REQUIRED,
    TOTAL_REQUIRED_PER_APP,
    DatasetTrackerConfig,
    _apply_quota_marking,
    _known_identity_value,
)


def test_known_identity_value_skips_unknown_placeholders() -> None:
    assert _known_identity_value("UNKNOWN", None, "abc123") == "abc123"
    assert _known_identity_value("", "none", "null") is None


def test_research_dataset_alpha_quota_defaults_are_explicit() -> None:
    cfg = DatasetTrackerConfig()

    assert BASELINE_REQUIRED == 3
    assert INTERACTION_REQUIRED == 4
    assert TOTAL_REQUIRED_PER_APP == 7
    assert cfg.baseline_required == 3
    assert cfg.interactive_required == 4


def test_interaction_before_baseline_quota_still_counts_by_lane() -> None:
    cfg = DatasetTrackerConfig()
    app_entry = {
        "runs": [
            {
                "run_id": "b1",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-05-14T01:00:00+00:00",
            },
            {
                "run_id": "i1",
                "run_profile": "interaction_scripted",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-05-14T02:00:00+00:00",
            },
            {
                "run_id": "b2",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-05-14T03:00:00+00:00",
            },
            {
                "run_id": "b3",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-05-14T04:00:00+00:00",
            },
            {
                "run_id": "i2",
                "run_profile": "interaction_scripted",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-05-14T05:00:00+00:00",
            },
        ]
    }

    _apply_quota_marking(app_entry, cfg)
    by_id = {row["run_id"]: row for row in app_entry["runs"]}

    assert by_id["b1"]["counts_toward_quota"] is True
    assert by_id["i1"]["counts_toward_quota"] is True
    assert by_id["i1"]["extra_run"] == 0
    assert by_id["b2"]["counts_toward_quota"] is True
    assert by_id["b3"]["counts_toward_quota"] is True
    assert by_id["i2"]["counts_toward_quota"] is True
    assert app_entry["quota_met"] is False


def test_interactions_collected_before_refreshed_baselines_remain_countable() -> None:
    cfg = DatasetTrackerConfig()
    app_entry = {
        "runs": [
            {
                "run_id": f"i{idx}",
                "run_profile": "interaction_manual",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": f"2026-05-14T0{idx}:00:00+00:00",
            }
            for idx in range(1, 5)
        ]
        + [
            {
                "run_id": f"b{idx}",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": f"2026-05-15T0{idx}:00:00+00:00",
            }
            for idx in range(1, 4)
        ]
    }

    _apply_quota_marking(app_entry, cfg)
    by_id = {row["run_id"]: row for row in app_entry["runs"]}

    assert all(by_id[f"i{idx}"]["counts_toward_quota"] is True for idx in range(1, 5))
    assert all(by_id[f"b{idx}"]["counts_toward_quota"] is True for idx in range(1, 4))
    assert app_entry["quota_met"] is True
    assert app_entry["extra_valid_runs"] == 0


def test_quota_marking_scopes_current_build_separately_from_legacy_runs() -> None:
    cfg = DatasetTrackerConfig()
    app_entry = {
        "runs": [
            {
                "run_id": "legacy-b1",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "version_code": "311990001",
                "base_apk_sha256": "legacysha",
                "started_at": "2026-06-15T01:00:00+00:00",
            },
            {
                "run_id": "legacy-b2",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "version_code": "311990001",
                "base_apk_sha256": "legacysha",
                "started_at": "2026-06-15T02:00:00+00:00",
            },
            {
                "run_id": "legacy-b3",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "version_code": "311990001",
                "base_apk_sha256": "legacysha",
                "started_at": "2026-06-15T03:00:00+00:00",
            },
            {
                "run_id": "current-b1",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "version_code": "312021000",
                "base_apk_sha256": "currentsha",
                "started_at": "2026-06-26T01:00:00+00:00",
            },
            {
                "run_id": "current-b2",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "version_code": "312021000",
                "base_apk_sha256": "currentsha",
                "started_at": "2026-06-26T02:00:00+00:00",
            },
        ]
    }

    _apply_quota_marking(
        app_entry,
        cfg,
        package_name="com.twitter.android",
        resolve_tracker_run_identity_fn=lambda _pkg, row: (
            str(row.get("version_code") or "") or None,
            str(row.get("base_apk_sha256") or "") or None,
        ),
        scope_tracker_runs_to_active_identity_fn=lambda _pkg, runs, resolve_tracker_run_identity_fn: {
            "active_identity": ("312021000", "currentsha"),
            "active_runs": [r for r in runs if r.get("base_apk_sha256") == "currentsha"],
            "valid_runs": list(runs),
            "legacy_runs": [r for r in runs if r.get("base_apk_sha256") == "legacysha"],
            "legacy_valid": 3,
            "legacy_builds": 1,
        },
    )

    by_id = {row["run_id"]: row for row in app_entry["runs"]}

    assert by_id["legacy-b1"]["counts_toward_quota"] is False
    assert by_id["legacy-b1"]["extra_run"] == 0
    assert by_id["legacy-b2"]["counts_toward_quota"] is False
    assert by_id["legacy-b3"]["counts_toward_quota"] is False
    assert by_id["current-b1"]["counts_toward_quota"] is True
    assert by_id["current-b2"]["counts_toward_quota"] is True
    assert app_entry["quota_met"] is False
    assert app_entry["extra_valid_runs"] == 0


def test_low_signal_baseline_idle_is_supplemental_extra_not_countable() -> None:
    cfg = DatasetTrackerConfig()
    app_entry = {
        "runs": [
            {
                "run_id": "b1",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "low_signal": False,
                "started_at": "2026-06-28T01:00:00+00:00",
            },
            {
                "run_id": "b2",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "low_signal": False,
                "started_at": "2026-06-28T02:00:00+00:00",
            },
            {
                "run_id": "b3-low",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "low_signal": True,
                "low_signal_reasons": ["PCAP_BYTES_LOW"],
                "started_at": "2026-06-28T03:00:00+00:00",
            },
        ]
    }

    _apply_quota_marking(app_entry, cfg)
    by_id = {row["run_id"]: row for row in app_entry["runs"]}

    assert by_id["b1"]["counts_toward_quota"] is True
    assert by_id["b2"]["counts_toward_quota"] is True
    assert by_id["b3-low"]["counts_toward_quota"] is False
    assert by_id["b3-low"]["countable"] is False
    assert by_id["b3-low"]["extra_run"] == 1
    assert by_id["b3-low"]["cohort_eligibility"] == "EXTRA"
    assert app_entry["extra_valid_runs"] == 1


def test_explicit_non_countable_interactive_run_stays_supplemental() -> None:
    cfg = DatasetTrackerConfig()
    app_entry = {
        "runs": [
            {
                "run_id": "b1",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-06-29T01:00:00+00:00",
            },
            {
                "run_id": "b2",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-06-29T02:00:00+00:00",
            },
            {
                "run_id": "b3",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-06-29T03:00:00+00:00",
            },
            {
                "run_id": "i1",
                "run_profile": "interaction_scripted",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "started_at": "2026-06-29T04:00:00+00:00",
            },
            {
                "run_id": "i2-extra",
                "run_profile": "interaction_manual",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": False,
                "cohort_eligibility": "EXTRA",
                "started_at": "2026-06-29T05:00:00+00:00",
            },
        ]
    }

    _apply_quota_marking(app_entry, cfg)
    by_id = {row["run_id"]: row for row in app_entry["runs"]}

    assert by_id["i1"]["counts_toward_quota"] is True
    assert by_id["i2-extra"]["counts_toward_quota"] is False
    assert by_id["i2-extra"]["countable"] is False
    assert by_id["i2-extra"]["extra_run"] == 1
    assert by_id["i2-extra"]["cohort_eligibility"] == "EXTRA"
    assert app_entry["extra_valid_runs"] == 1
    assert app_entry["quota_met"] is False


def test_explicit_countable_interactive_runs_survive_recompute_ordering() -> None:
    cfg = DatasetTrackerConfig()
    app_entry = {
        "runs": [
            {
                "run_id": "b1",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": True,
                "started_at": "2026-06-29T01:00:00+00:00",
            },
            {
                "run_id": "b2",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": True,
                "started_at": "2026-06-29T02:00:00+00:00",
            },
            {
                "run_id": "b3",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": True,
                "started_at": "2026-06-29T03:00:00+00:00",
            },
            {
                "run_id": "i1",
                "run_profile": "interaction_scripted",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": True,
                "started_at": "2026-06-29T04:00:00+00:00",
            },
            {
                "run_id": "i2",
                "run_profile": "interaction_scripted",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": True,
                "started_at": "2026-06-29T05:00:00+00:00",
            },
            {
                "run_id": "i3-extra",
                "run_profile": "interaction_manual",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": False,
                "cohort_eligibility": "EXTRA",
                "started_at": "2026-06-29T06:00:00+00:00",
            },
        ]
    }

    _apply_quota_marking(app_entry, cfg)
    by_id = {row["run_id"]: row for row in app_entry["runs"]}

    assert by_id["i1"]["counts_toward_quota"] is True
    assert by_id["i2"]["counts_toward_quota"] is True
    assert by_id["i1"]["countable"] is True
    assert by_id["i2"]["countable"] is True
    assert by_id["i3-extra"]["counts_toward_quota"] is False
    assert by_id["i3-extra"]["countable"] is False
    assert by_id["i3-extra"]["extra_run"] == 1
    assert app_entry["extra_valid_runs"] == 1
    assert app_entry["quota_met"] is False


def test_explicit_countable_true_cannot_exceed_baseline_quota_cap() -> None:
    cfg = DatasetTrackerConfig()
    app_entry = {
        "runs": [
            {
                "run_id": f"b{idx}",
                "run_profile": "baseline_idle",
                "valid_dataset_run": True,
                "paper_eligible": True,
                "countable": True,
                "low_signal": False,
                "started_at": f"2026-06-29T0{idx}:00:00+00:00",
            }
            for idx in range(1, 5)
        ]
    }

    _apply_quota_marking(app_entry, cfg)
    by_id = {row["run_id"]: row for row in app_entry["runs"]}

    assert by_id["b1"]["countable"] is True
    assert by_id["b2"]["countable"] is True
    assert by_id["b3"]["countable"] is True
    assert by_id["b4"]["counts_toward_quota"] is False
    assert by_id["b4"]["countable"] is False
    assert by_id["b4"]["extra_run"] == 1
    assert sum(1 for row in app_entry["runs"] if row["countable"]) == cfg.baseline_required


def test_explicit_countable_true_cannot_exceed_interactive_quota_cap() -> None:
    cfg = DatasetTrackerConfig()
    baseline_rows = [
        {
            "run_id": f"b{idx}",
            "run_profile": "baseline_idle",
            "valid_dataset_run": True,
            "paper_eligible": True,
            "countable": True,
            "low_signal": False,
            "started_at": f"2026-06-29T0{idx}:00:00+00:00",
        }
        for idx in range(1, 4)
    ]
    interactive_rows = [
        {
            "run_id": f"i{idx}",
            "run_profile": "interaction_scripted",
            "valid_dataset_run": True,
            "paper_eligible": True,
            "countable": True,
            "started_at": f"2026-06-29T{idx + 3:02d}:00:00+00:00",
        }
        for idx in range(1, 6)
    ]
    app_entry = {"runs": baseline_rows + interactive_rows}

    _apply_quota_marking(app_entry, cfg)
    by_id = {row["run_id"]: row for row in app_entry["runs"]}

    assert by_id["i1"]["countable"] is True
    assert by_id["i2"]["countable"] is True
    assert by_id["i3"]["countable"] is True
    assert by_id["i4"]["countable"] is True
    assert by_id["i5"]["counts_toward_quota"] is False
    assert by_id["i5"]["countable"] is False
    assert by_id["i5"]["extra_run"] == 1
    assert sum(1 for row in app_entry["runs"] if row["countable"]) == TOTAL_REQUIRED_PER_APP
    assert app_entry["quota_met"] is True
