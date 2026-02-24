from __future__ import annotations

from scytaledroid.DynamicAnalysis import menu


def test_next_action_from_need_prefers_baseline_when_baseline_missing() -> None:
    assert menu._next_action_from_need(1, 2) == "baseline"


def test_next_action_from_need_scripted_when_only_interactive_missing() -> None:
    assert menu._next_action_from_need(0, 2) == "scripted"


def test_next_action_from_need_scripted_when_quota_complete() -> None:
    assert menu._next_action_from_need(0, 0) == "—"
