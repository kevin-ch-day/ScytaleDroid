from __future__ import annotations

from scytaledroid.Database.db_utils.bridge_posture import (
    bridge_posture_map,
    bridge_posture_summary,
    list_bridge_postures,
)


def test_bridge_posture_registry_covers_expected_tables() -> None:
    rows = list_bridge_postures()
    names = {row.table for row in rows}
    assert names == {
        "runs",
        "findings",
        "metrics",
        "buckets",
        "contributors",
        "risk_scores",
        "correlations",
    }


def test_bridge_posture_summary_counts() -> None:
    summary = bridge_posture_summary()
    assert summary["compat_only_keep"] == 1
    assert summary["compat_mirror_review"] == 4
    assert summary["derived_review"] == 1
    assert summary["freeze_candidate"] == 1


def test_bridge_posture_map_exposes_risk_scores_and_correlations() -> None:
    posture_map = bridge_posture_map()
    assert posture_map["risk_scores"].posture == "derived_review"
    assert posture_map["correlations"].posture == "freeze_candidate"
    assert posture_map["correlations"].current_writers == ()
    assert posture_map["correlations"].current_readers == ()
