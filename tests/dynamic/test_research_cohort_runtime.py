from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis import research_cohort_runtime
from scytaledroid.DynamicAnalysis.datasets import research_dataset_alpha


def test_load_dataset_packages_prefers_db_backed_research_cohort(monkeypatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_func.research_cohorts.fetch_active_research_cohort_packages",
        lambda _key: ["com.example.one", "com.example.two"],
    )

    packages = research_dataset_alpha.load_dataset_packages()

    assert packages == ["com.example.one", "com.example.two"]


def test_active_research_cohort_context_uses_persisted_selection_when_env_unset(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(research_cohort_runtime.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.delenv("SCYTALEDROID_RESEARCH_COHORT_KEY", raising=False)

    calls: list[str | None] = []

    def _resolve_context(preferred_key=None):  # noqa: ANN001
        calls.append(preferred_key)
        return {
            "cohort_key": preferred_key or "research_dataset_alpha",
            "display_name": "Research Dataset Beta" if preferred_key == "research_dataset_beta" else "Research Dataset Alpha",
            "packages": ("com.example.beta",),
        }

    monkeypatch.setattr(
        "scytaledroid.Database.db_func.research_cohorts.resolve_research_cohort_context",
        _resolve_context,
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_func.research_cohorts.configured_research_cohort_key",
        lambda: None,
    )

    research_cohort_runtime.persist_active_research_cohort_key(
        "research_dataset_beta",
        label="Research Dataset Beta",
    )

    context = research_cohort_runtime.active_research_cohort_context()

    assert calls == ["research_dataset_beta"]
    assert context["cohort_key"] == "research_dataset_beta"
    assert research_cohort_runtime.active_research_cohort_packages() == ("com.example.beta",)


def test_active_research_cohort_context_prefers_persisted_selection_over_env_override(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(research_cohort_runtime.app_config, "DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SCYTALEDROID_RESEARCH_COHORT_KEY", "research_dataset_alpha")

    calls: list[str | None] = []

    def _resolve_context(preferred_key=None):  # noqa: ANN001
        calls.append(preferred_key)
        return {
            "cohort_key": preferred_key or "research_dataset_alpha",
            "display_name": "Research Dataset Alpha",
            "packages": ("com.example.alpha",),
        }

    monkeypatch.setattr(
        "scytaledroid.Database.db_func.research_cohorts.resolve_research_cohort_context",
        _resolve_context,
    )

    research_cohort_runtime.persist_active_research_cohort_key(
        "research_dataset_beta",
        label="Research Dataset Beta",
    )

    context = research_cohort_runtime.active_research_cohort_context()

    assert calls == ["research_dataset_beta"]
    assert context["cohort_key"] == "research_dataset_beta"
