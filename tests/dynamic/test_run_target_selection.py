from __future__ import annotations

from scytaledroid.DynamicAnalysis.menus import run_target_selection


def test_select_dynamic_target_custom_fast_path_does_not_group_artifacts(monkeypatch) -> None:
    monkeypatch.setattr(run_target_selection.prompt_utils, "get_choice", lambda *_a, **_k: "1")

    def _group_artifacts():
        raise AssertionError("custom single-app target should not build artifact groups")

    selected = run_target_selection.select_dynamic_target(
        group_artifacts_fn=_group_artifacts,
        active_research_cohort_packages_fn=lambda: ("com.instagram.android",),
        active_research_cohort_label_fn=lambda: "Research Dataset Beta",
        select_package_from_groups_fn=lambda *_a, **_k: None,
        prompt_custom_package_fn=lambda: "com.instagram.android",
        resolve_custom_tier_fn=lambda package, dataset_pkgs: (package, "dataset" if package in dataset_pkgs else "exploration"),
        select_profile_package_fn=lambda *_a, **_k: None,
    )

    assert selected == ("com.instagram.android", "dataset")


def test_resolve_custom_tier_accepts_app_display_name(monkeypatch) -> None:
    from scytaledroid.Database.db_core import db_queries

    monkeypatch.setattr(
        db_queries,
        "run_sql",
        lambda *_a, **_k: [{"package_name": "com.instagram.android", "display_name": "Instagram"}],
    )
    monkeypatch.setattr(run_target_selection.prompt_utils, "prompt_yes_no", lambda *_a, **_k: True)

    selected = run_target_selection.resolve_custom_tier(
        "Instagram",
        {"com.instagram.android"},
        active_research_cohort_label_fn=lambda: "Research Dataset Beta",
    )

    assert selected == ("com.instagram.android", "dataset")


def test_resolve_custom_tier_disambiguates_app_display_name(monkeypatch) -> None:
    from scytaledroid.Database.db_core import db_queries

    monkeypatch.setattr(
        db_queries,
        "run_sql",
        lambda *_a, **_k: [
            {"package_name": "com.facebook.katana", "display_name": "Facebook"},
            {"package_name": "com.facebook.orca", "display_name": "Facebook Msg"},
        ],
    )
    monkeypatch.setattr(run_target_selection.prompt_utils, "get_choice", lambda *_a, **_k: "2")
    monkeypatch.setattr(run_target_selection.prompt_utils, "prompt_yes_no", lambda *_a, **_k: True)

    selected = run_target_selection.resolve_custom_tier(
        "Facebook",
        {"com.facebook.katana", "com.facebook.orca"},
        active_research_cohort_label_fn=lambda: "Research Dataset Beta",
    )

    assert selected == ("com.facebook.orca", "dataset")


def test_resolve_custom_tier_cancels_ambiguous_app_display_name(monkeypatch) -> None:
    from scytaledroid.Database.db_core import db_queries

    monkeypatch.setattr(
        db_queries,
        "run_sql",
        lambda *_a, **_k: [
            {"package_name": "com.facebook.katana", "display_name": "Facebook"},
            {"package_name": "com.facebook.orca", "display_name": "Facebook Msg"},
        ],
    )
    monkeypatch.setattr(run_target_selection.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    selected = run_target_selection.resolve_custom_tier(
        "Facebook",
        {"com.facebook.katana", "com.facebook.orca"},
        active_research_cohort_label_fn=lambda: "Research Dataset Beta",
    )

    assert selected is None
