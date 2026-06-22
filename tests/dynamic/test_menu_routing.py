from __future__ import annotations

from scytaledroid.DynamicAnalysis import menu


def test_resolve_active_cohort_for_run_prefers_existing_active_context(monkeypatch) -> None:
    monkeypatch.setattr(menu, "active_research_cohort_key", lambda: "research_dataset_beta")
    monkeypatch.setattr(
        menu,
        "chooseable_active_research_cohorts",
        lambda: [
            {"cohort_key": "research_dataset_alpha", "display_name": "Research Dataset Alpha", "active_member_count": 12},
            {"cohort_key": "research_dataset_beta", "display_name": "Research Dataset Beta", "active_member_count": 15},
        ],
    )
    chooser_calls = {"count": 0}
    monkeypatch.setattr(
        menu,
        "_choose_active_research_cohort",
        lambda: chooser_calls.__setitem__("count", chooser_calls["count"] + 1),
    )

    selected = menu._resolve_active_cohort_for_run()

    assert selected == {
        "cohort_key": "research_dataset_beta",
        "display_name": "Research Dataset Beta",
        "active_member_count": 15,
    }
    assert chooser_calls["count"] == 0


def test_resolve_active_cohort_for_run_falls_back_to_selector_when_no_active_key(monkeypatch) -> None:
    monkeypatch.setattr(menu, "active_research_cohort_key", lambda: None)
    monkeypatch.setattr(
        menu,
        "chooseable_active_research_cohorts",
        lambda: [{"cohort_key": "research_dataset_alpha", "display_name": "Research Dataset Alpha", "active_member_count": 12}],
    )
    monkeypatch.setattr(
        menu,
        "_choose_active_research_cohort",
        lambda: {"cohort_key": "research_dataset_alpha", "display_name": "Research Dataset Alpha", "active_member_count": 12},
    )

    selected = menu._resolve_active_cohort_for_run()

    assert selected == {
        "cohort_key": "research_dataset_alpha",
        "display_name": "Research Dataset Alpha",
        "active_member_count": 12,
    }
