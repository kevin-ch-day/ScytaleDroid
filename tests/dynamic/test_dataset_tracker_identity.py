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
    assert INTERACTION_REQUIRED == 2
    assert TOTAL_REQUIRED_PER_APP == 5
    assert cfg.baseline_required == 3
    assert cfg.interactive_required == 2


def test_interaction_before_baseline_quota_is_supplemental() -> None:
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
    assert by_id["i1"]["counts_toward_quota"] is False
    assert by_id["i1"]["extra_run"] == 1
    assert by_id["b2"]["counts_toward_quota"] is True
    assert by_id["b3"]["counts_toward_quota"] is True
    assert by_id["i2"]["counts_toward_quota"] is True
    assert app_entry["quota_met"] is False


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
