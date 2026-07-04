from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.menus import dynamic_menu as menu


def test_resolve_active_cohort_for_run_prefers_existing_active_context(monkeypatch) -> None:
    monkeypatch.setattr(menu, "active_research_cohort_key", lambda: "research_dataset_beta")
    monkeypatch.setattr(
        menu,
        "chooseable_active_research_cohorts",
        lambda: [
            {
                "cohort_key": "research_dataset_alpha",
                "display_name": "Research Dataset Alpha",
                "active_member_count": 12,
            },
            {
                "cohort_key": "research_dataset_beta",
                "display_name": "Research Dataset Beta",
                "active_member_count": 15,
            },
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


def test_resolve_active_cohort_for_run_falls_back_to_selector_when_no_active_key(
    monkeypatch,
) -> None:
    monkeypatch.setattr(menu, "active_research_cohort_key", lambda: None)
    monkeypatch.setattr(
        menu,
        "chooseable_active_research_cohorts",
        lambda: [
            {
                "cohort_key": "research_dataset_alpha",
                "display_name": "Research Dataset Alpha",
                "active_member_count": 12,
            }
        ],
    )
    monkeypatch.setattr(
        menu,
        "_choose_active_research_cohort",
        lambda: {
            "cohort_key": "research_dataset_alpha",
            "display_name": "Research Dataset Alpha",
            "active_member_count": 12,
        },
    )

    selected = menu._resolve_active_cohort_for_run()

    assert selected == {
        "cohort_key": "research_dataset_alpha",
        "display_name": "Research Dataset Alpha",
        "active_member_count": 12,
    }


def test_repair_reindex_tracker_passes_working_json_reader(monkeypatch, tmp_path: Path) -> None:
    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps({"run_id": "abc", "valid": True}), encoding="utf-8")

    captured: dict[str, object] = {}

    def _fake_repair_reindex_tracker(**kwargs) -> None:
        captured["payload"] = kwargs["read_json_fn"](sample)
        captured["min_windows"] = kwargs["min_windows_per_run"]()
        captured["summary"] = kwargs["summarize_evidence_quota"](set(), object())
        kwargs["run_state_summary"]()

    monkeypatch.setattr(
        menu._maintenance_adapter,
        "repair_reindex_tracker",
        _fake_repair_reindex_tracker,
    )
    monkeypatch.setattr(menu, "_min_windows_per_run", lambda: 24)
    monkeypatch.setattr(
        menu, "_summarize_evidence_quota", lambda *_a, **_k: {"quota_runs_counted": 7}
    )
    monkeypatch.setattr(
        menu, "_run_state_summary", lambda: captured.__setitem__("state_summary_called", True)
    )

    menu._repair_reindex_tracker()

    assert captured == {
        "payload": {"run_id": "abc", "valid": True},
        "min_windows": 24,
        "summary": {"quota_runs_counted": 7},
        "state_summary_called": True,
    }
