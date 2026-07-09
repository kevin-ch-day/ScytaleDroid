from __future__ import annotations

from scytaledroid.Database.db_func import research_cohorts


def test_resolve_preferred_research_cohort_key_prefers_largest_active_cohort(monkeypatch) -> None:
    monkeypatch.setattr(
        research_cohorts,
        "list_active_research_cohorts",
        lambda **_kwargs: [
            {"cohort_key": "research_dataset_alpha", "active_member_count": 12},
            {"cohort_key": "research_dataset_beta", "active_member_count": 15},
        ],
    )

    resolved = research_cohorts.resolve_preferred_research_cohort_key(
        env={},
    )

    assert resolved == "research_dataset_beta"


def test_resolve_preferred_research_cohort_key_respects_env_override(monkeypatch) -> None:
    monkeypatch.setattr(
        research_cohorts,
        "list_active_research_cohorts",
        lambda **_kwargs: [
            {"cohort_key": "research_dataset_alpha"},
            {"cohort_key": "research_dataset_beta"},
        ],
    )

    resolved = research_cohorts.resolve_preferred_research_cohort_key(
        env={"SCYTALEDROID_RESEARCH_COHORT_KEY": "research_dataset_beta"},
    )

    assert resolved == "research_dataset_beta"


def test_resolve_research_cohort_context_returns_display_profile_and_packages(monkeypatch) -> None:
    monkeypatch.setattr(
        research_cohorts,
        "list_active_research_cohorts",
        lambda **_kwargs: [{"cohort_key": "research_dataset_beta"}],
    )
    monkeypatch.setattr(
        research_cohorts,
        "fetch_research_cohort",
        lambda cohort_key, **_kwargs: {
            "cohort_key": cohort_key,
            "display_name": "Research Dataset Beta",
        },
    )
    monkeypatch.setattr(
        research_cohorts,
        "resolve_research_cohort_packages",
        lambda cohort_key, fallback_profile_key=None, **_kwargs: [  # noqa: ARG005
            "bbc.mobile.news.ww",
            "com.guardian",
        ],
    )

    context = research_cohorts.resolve_research_cohort_context(
        preferred_key="research_dataset_beta",
        env={},
    )

    assert context == {
        "cohort_key": "research_dataset_beta",
        "profile_key": "RESEARCH_DATASET_BETA",
        "display_name": "Research Dataset Beta",
        "packages": ("bbc.mobile.news.ww", "com.guardian"),
        "cohort": {
            "cohort_key": "research_dataset_beta",
            "display_name": "Research Dataset Beta",
        },
    }
