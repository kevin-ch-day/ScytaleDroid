from __future__ import annotations

from scytaledroid.DynamicAnalysis.datasets import research_dataset_alpha


def test_load_dataset_packages_prefers_db_backed_research_cohort(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_func.research_cohorts.fetch_active_research_cohort_packages",
        lambda _key: ["com.example.one", "com.example.two"],
    )

    packages = research_dataset_alpha.load_dataset_packages()

    assert packages == ["com.example.one", "com.example.two"]
