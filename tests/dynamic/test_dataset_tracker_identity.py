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
