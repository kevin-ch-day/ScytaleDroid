from __future__ import annotations

from scytaledroid.Reporting import menu, runtime_network_menu, static_exposure_menu
from scytaledroid.Utils.DisplayUtils.menu_utils import MenuOption, selectable_keys


def test_reporting_menu_source_explains_study_lineage_without_replacement_claims() -> None:
    source = menu.reporting_menu.__code__.co_consts
    text = "\n".join(str(item) for item in source)
    assert "Static Exposure & Privacy Assessment" in text
    assert "Runtime Network Behavior Analysis" in text
    assert "Paper #1 compatibility audit" in text
    assert "Paper #2 method-regeneration package" in text
    assert "Integrated analysis" in text
    assert "Integrated Static-Runtime Privacy & Security Analysis" in text
    assert "General cohort and app analysis" in text
    assert "Legacy archive tools" in text
    assert "current analysis window or app history" in text
    assert "published static predecessor" in text
    assert "published runtime predecessor" in text
    assert "current static-runtime study" in text
    assert "integrated-study foundation evidence" in text
    assert "Integrated static-runtime study" in text
    assert "Paper #3" not in text
    assert "publication candidate" not in text
    assert "Contract" not in text
    assert "freeze, session, manifest, or as-of basis" not in text
    assert "Publication study reports" not in text
    assert "replacement Paper #2" not in text
    assert "revised published paper" not in text
    assert "exact reproduction of the original 12-app results" not in text
    assert "time-series" not in text


def test_top_reporting_study_options_are_flat_and_disabled_future_studies_are_not_selectable() -> None:
    options = [
        MenuOption("1", "Static Exposure & Privacy Assessment"),
        MenuOption("2", "Runtime Network Behavior Analysis"),
        MenuOption("3", "Integrated Static-Runtime Privacy & Security Analysis", disabled=True),
        MenuOption("4", "General cohort and app analysis"),
        MenuOption("5", "Evidence and provenance exports"),
        MenuOption("6", "Saved report bundles"),
        MenuOption("7", "Experimental analyses"),
        MenuOption("8", "Legacy archive tools"),
    ]
    assert selectable_keys(options, include_exit=True) == ["1", "2", "4", "5", "6", "7", "8", "0"]


def test_runtime_reporting_next_step_keeps_training_in_machine_learning() -> None:
    status = {
        "locked_dataset": "blocked - dataset plan missing",
        "lockfile_state": "missing",
        "ml_tables_ready": False,
        "qa": "missing",
        "bundle": "missing",
    }

    assert runtime_network_menu._recommended_runtime_next_step(status) == (
        "Use Machine Learning to build the locked dataset"
    )


def test_runtime_reporting_next_step_generates_bundle_after_qa_ready() -> None:
    status = {
        "locked_dataset": "ready - 15 apps · 112 runs · selected build groups",
        "lockfile_state": "ready",
        "ml_tables_ready": True,
        "qa": "ready - primary OK · secondary caveats (12 warning(s))",
        "bundle": "missing",
    }

    assert runtime_network_menu._recommended_runtime_next_step(status) == (
        "2) Generate locked runtime report bundle"
    )


def test_runtime_reporting_next_step_ready_for_writing_after_bundle() -> None:
    status = {
        "locked_dataset": "ready - 15 apps · 112 runs · selected build groups",
        "lockfile_state": "ready",
        "ml_tables_ready": True,
        "qa": "ready - primary OK · secondary caveats (12 warning(s))",
        "bundle": "ready - 8 table CSV(s) · 6 figure PNG(s)",
    }

    assert runtime_network_menu._recommended_runtime_next_step(status) == "Ready for writing"


def test_runtime_reporting_status_uses_shared_ml_status(monkeypatch) -> None:
    monkeypatch.setattr(
        runtime_network_menu.ml_status,
        "runtime_ml_status_snapshot",
        lambda: {
            "freeze_status": "ready - 15 apps · 112 runs · selected build groups",
            "qa_status": "ready",
            "bundle_status": "missing",
            "lockfile_state": "ready",
            "required_tables": 7,
            "existing_tables": 7,
            "stale_tables": 0,
        },
    )

    status = runtime_network_menu._runtime_status_snapshot()

    assert status == {
        "locked_dataset": "ready - 15 apps · 112 runs · selected build groups",
        "qa": "ready",
        "bundle": "missing",
        "lockfile_state": "ready",
        "ml_tables_ready": True,
    }


def test_runtime_reporting_bundle_generation_waits_for_qa(monkeypatch) -> None:
    monkeypatch.setattr(
        runtime_network_menu,
        "_runtime_status_snapshot",
        lambda: {
            "locked_dataset": "ready - 15 apps · 112 runs · selected build groups",
            "lockfile_state": "ready",
            "ml_tables_ready": True,
            "qa": "missing",
            "bundle": "missing",
        },
    )

    assert runtime_network_menu._runtime_outputs_ready_for_bundle() == (
        False,
        "Run report QA check first",
    )


def test_runtime_reporting_exposes_validated_paper2_foundation_package(monkeypatch, capsys) -> None:
    calls: list[str] = []

    monkeypatch.setattr(runtime_network_menu.prompt_utils, "prompt_yes_no", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(runtime_network_menu.prompt_utils, "press_enter_to_continue", lambda: None)

    def fake_writer():
        calls.append("writer")
        return {
            "output_root": "output/_internal/publication/paper2_v2",
            "apps": 15,
            "runs": 112,
            "publication_results_v2": "output/_internal/publication/paper2_v2/publication_results_v2.json",
            "paper2_qa_v2": "output/_internal/publication/paper2_v2/paper2_qa_v2.json",
            "hash_manifest": "output/_internal/publication/paper2_v2/manifest/paper2_results_v2_manifest.json",
            "qa_status": "OK",
            "warnings": 0,
        }

    runtime_network_menu._generate_paper2_foundation_package(writer=fake_writer)
    out = capsys.readouterr().out

    assert calls == ["writer"]
    menu_text = "\n".join(str(item) for item in runtime_network_menu.handle_runtime_network_behavior_analysis.__code__.co_consts)
    assert "Generate validated Paper #2 foundation package" in menu_text
    assert runtime_network_menu.PAPER2_FOUNDATION_LABEL in out
    assert "held-out baseline" in out
    assert "feature ablation" in out
    assert "bytes/sec control" in out
    assert "seed stability" in out
    assert "temporal-order" in out
    assert "replacement Paper #2" not in out
    assert "revised published paper" not in out
    assert "exact reproduction of the original 12-app results" not in out


def test_static_completion_summary_exposes_paper1_foundation_outputs(tmp_path, capsys) -> None:
    report_dir = tmp_path / "static_report"
    (report_dir / "report").mkdir(parents=True)
    (report_dir / "tables").mkdir(parents=True)
    (report_dir / "report" / "paper1_reproduction_map.csv").write_text(
        "paper1_item,status,current_artifact,gap\n"
        "Table II,reproducible_with_current_schema,tables/paper1_permission_usage_matrix.csv,\n"
        "Table I,partial,tables/paper1_manifest_component_parity.csv,intent filters archive-derived\n"
        "Table V,blocked,tables/paper1_score_model_inputs.csv,score formula not verified\n",
        encoding="utf-8",
    )
    (report_dir / "tables" / "paper1_score_status.csv").write_text(
        "paper1_output,current_status,current_source,reason,safe_current_substitute\n"
        "Table V Overall Static Risk Scores,blocked,tables/paper1_score_model_inputs.csv,not verified,input ledger\n",
        encoding="utf-8",
    )

    static_exposure_menu._print_paper1_foundation_summary({"output_dir": str(report_dir)})
    out = capsys.readouterr().out

    assert "Paper #1 Foundation Compatibility" in out
    assert "Exact/reproducible items" in out
    assert "Partial items" in out
    assert "Blocked historical metrics" in out
    assert "paper1_reproduction_map.csv" in out
    assert "rewrite the published Paper #1 manuscript" in out


def test_legacy_archive_tools_keep_historical_published_artifact_boundary() -> None:
    source = menu._legacy_archive_tools_menu.__code__.co_consts
    text = "\n".join(str(item) for item in source)

    assert "Published Paper #2" in text
    assert "historical snapshots and artifacts stay here" in text
    assert "Legacy archive profiles preserve earlier archive workflows" in text
    assert "Generate legacy frozen runtime results package" in "\n".join(
        str(item) for item in menu._reporting_menu_v2_frozen.__code__.co_consts
    )


def test_static_evidence_window_defaults_to_recent_current_window(monkeypatch) -> None:
    choices: list[str] = []

    def fake_menu_choice(valid, *, default="0", **_kwargs):
        choices.append(default or "")
        assert list(valid) == ["1", "2", "3", "0"]
        return "1"

    monkeypatch.setattr(static_exposure_menu.prompt_utils, "menu_choice", fake_menu_choice)
    selected = static_exposure_menu._choose_static_evidence_window(
        lambda: "2026-07-10T00:00:00+00:00",
        scope_type="research_cohort",
    )

    assert selected == (
        "fixed_recent_window",
        "current_static_evidence_30d",
        None,
        "2026-06-10T00:00:00+00:00",
        "2026-07-10T00:00:00+00:00",
    )
    assert choices == ["1"]


def test_static_evidence_window_supports_app_version_history(monkeypatch) -> None:
    def fake_menu_choice(valid, *, default="0", **_kwargs):
        assert list(valid) == ["1", "2", "3", "0"]
        assert default == "1"
        return "2"

    monkeypatch.setattr(static_exposure_menu.prompt_utils, "menu_choice", fake_menu_choice)
    selected = static_exposure_menu._choose_static_evidence_window(
        lambda: "2026-07-10T00:00:00+00:00",
        scope_type="research_cohort",
    )

    assert selected == (
        "fixed_recent_window",
        "app_version_history_30d",
        None,
        "2026-06-10T00:00:00+00:00",
        "2026-07-10T00:00:00+00:00",
    )


def test_static_evidence_window_latest_valid_now_is_explicit_third_choice(monkeypatch) -> None:
    def fake_menu_choice(valid, *, default="0", **_kwargs):
        assert list(valid) == ["1", "2", "3", "0"]
        assert default == "1"
        return "3"

    monkeypatch.setattr(static_exposure_menu.prompt_utils, "menu_choice", fake_menu_choice)
    selected = static_exposure_menu._choose_static_evidence_window(
        lambda: "2026-07-10T00:00:00+00:00",
        scope_type="application_category",
    )

    assert selected == (
        "latest_valid_as_of",
        "latest_valid_static_evidence",
        "2026-07-10T00:00:00+00:00",
        None,
        None,
    )


def test_static_evidence_window_display_uses_short_dates() -> None:
    class Request:
        window_start_utc = "2026-06-11T02:55:23+00:00"
        window_end_utc = "2026-07-11T02:55:23+00:00"
        as_of_utc = None

    assert static_exposure_menu._describe_static_evidence_window(Request()) == "6/11/2026 to 7/11/2026"


def test_static_evidence_as_of_display_uses_short_date() -> None:
    class Request:
        window_start_utc = None
        window_end_utc = None
        as_of_utc = "2026-07-11T02:55:23+00:00"

    assert static_exposure_menu._describe_static_evidence_window(Request()) == "as of 7/11/2026"


def test_app_name_preview_uses_display_names_without_redundant_total(monkeypatch) -> None:
    monkeypatch.setattr(
        static_exposure_menu,
        "_load_app_display_names",
        lambda packages: {
            "com.facebook.katana": "Facebook",
            "com.snapchat.android": "Snapchat",
        },
    )

    preview = static_exposure_menu._app_name_preview(
        ["com.facebook.katana", "com.snapchat.android"],
    )

    assert preview == "Facebook, Snapchat"
    assert "total" not in preview
    assert "com.facebook.katana" not in preview


def test_app_name_preview_truncates_without_count_suffix(monkeypatch) -> None:
    packages = [f"com.example.app{i}" for i in range(10)]
    monkeypatch.setattr(
        static_exposure_menu,
        "_load_app_display_names",
        lambda package_names: {package: f"App {idx}" for idx, package in enumerate(package_names)},
    )

    preview = static_exposure_menu._app_name_preview(packages, limit=8)

    assert preview == "App 0, App 1, App 2, App 3, App 4, App 5, App 6, App 7, ..."
    assert "(10 total)" not in preview


def test_single_app_evidence_window_defaults_to_current_version(monkeypatch) -> None:
    def fake_menu_choice(valid, *, default="0", **_kwargs):
        assert list(valid) == ["1", "2", "0"]
        assert default == "1"
        return "1"

    monkeypatch.setattr(static_exposure_menu.prompt_utils, "menu_choice", fake_menu_choice)
    selected = static_exposure_menu._choose_static_evidence_window(
        lambda: "2026-07-10T00:00:00+00:00",
        scope_type="single_app",
    )

    assert selected == (
        "latest_valid_as_of",
        "latest_valid_static_evidence",
        "2026-07-10T00:00:00+00:00",
        None,
        None,
    )


def test_single_app_history_window_prompts_for_days_capped_at_30(monkeypatch) -> None:
    def fake_menu_choice(_valid, *, default="0", **_kwargs):
        return "2"

    def fake_prompt_text(prompt, *, validator=None, **_kwargs):
        assert prompt == "History window days"
        assert validator is not None
        assert validator("30")
        assert validator("1")
        assert not validator("31")
        assert not validator("0")
        return "14"

    monkeypatch.setattr(static_exposure_menu.prompt_utils, "menu_choice", fake_menu_choice)
    monkeypatch.setattr(static_exposure_menu.prompt_utils, "prompt_text", fake_prompt_text)
    selected = static_exposure_menu._choose_static_evidence_window(
        lambda: "2026-07-10T00:00:00+00:00",
        scope_type="single_app",
    )

    assert selected == (
        "fixed_recent_window",
        "single_app_history_14d",
        None,
        "2026-06-26T00:00:00+00:00",
        "2026-07-10T00:00:00+00:00",
    )


def test_single_app_scope_resolves_exact_display_name_without_extra_prompt() -> None:
    selected = static_exposure_menu._resolve_single_static_app_scope(
        "facebook",
        lambda _query: [
            {
                "package_name": "com.facebook.katana",
                "display_name": "Facebook",
                "app_category": "Social",
            }
        ],
    )

    assert selected == ("com.facebook.katana", "Facebook", ["com.facebook.katana"])


def test_single_app_scope_disambiguates_partial_app_label(monkeypatch) -> None:
    def fake_menu_choice(valid, *, default="0", **_kwargs):
        assert list(valid) == ["1", "2", "0"]
        assert default == "1"
        return "2"

    monkeypatch.setattr(static_exposure_menu.prompt_utils, "menu_choice", fake_menu_choice)
    selected = static_exposure_menu._resolve_single_static_app_scope(
        "face",
        lambda _query: [
            {
                "package_name": "com.facebook.katana",
                "display_name": "Facebook",
                "app_category": "Social",
            },
            {
                "package_name": "com.facebook.orca",
                "display_name": "Facebook Messenger",
                "app_category": "Messaging",
            },
        ],
    )

    assert selected == ("com.facebook.orca", "Facebook Messenger", ["com.facebook.orca"])


def test_single_app_scope_requires_full_package_when_no_match() -> None:
    assert static_exposure_menu._resolve_single_static_app_scope("facebook", lambda _query: []) is None
    assert static_exposure_menu._resolve_single_static_app_scope("com.example.app", lambda _query: []) == (
        "com.example.app",
        "com.example.app",
        ["com.example.app"],
    )


def test_static_report_interactive_flow_hides_low_level_legacy_source_labels() -> None:
    source = static_exposure_menu.handle_generate_static_exposure_privacy_report.__code__.co_consts
    text = "\n".join(str(item) for item in source)
    assert "Research dataset" in text
    assert "Application category" in text
    assert "Single application" in text
    assert "App name" in text
    assert "Apps" in text
    assert "Packages" not in text
    assert "App name or package" not in text
    assert "Exact manifest/freeze file" not in text
    assert "Named static session" not in text
    assert "Advanced Evidence Source" not in text
    assert "static_social_media_2025" not in text
    assert "Output Contract" not in text
    assert "exploratory" not in text
    assert "frozen" not in text
