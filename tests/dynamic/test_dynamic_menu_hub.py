from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.menus.menu_hub import (
    DynamicAnalysisMenuCallbacks,
    run_dynamic_analysis_menu,
)


def test_menu_hub_routes_choice_1_to_single_app_run(monkeypatch) -> None:
    from scytaledroid.DynamicAnalysis.menus import menu_hub as hub_module

    calls: list[str] = []

    choices = iter(["1", "0"])

    monkeypatch.setattr(
        hub_module.schema_gate,
        "dynamic_schema_gate",
        lambda: (True, "ok", None),
    )
    monkeypatch.setattr(
        hub_module,
        "build_dynamic_menu_sections",
        lambda: SimpleNamespace(
            all_options=[],
            primary_actions=[],
            validation=[],
            maintenance=[],
            archive_export=[],
        ),
    )
    monkeypatch.setattr(hub_module, "render_dynamic_menu_overview", lambda: None)
    monkeypatch.setattr(hub_module.menu_utils, "print_menu", lambda *_a, **_k: None)
    monkeypatch.setattr(hub_module.menu_utils, "print_section", lambda *_a, **_k: None)
    monkeypatch.setattr(hub_module.prompt_utils, "get_choice", lambda *_a, **_k: next(choices))

    callbacks = DynamicAnalysisMenuCallbacks(
        warn_if_code_changed=lambda: None,
        load_ui_defaults=lambda: SimpleNamespace(),
        resolve_active_cohort_for_run=lambda: None,
        run_guided_dataset_run=lambda _ui: None,
        run_focused_app_run=lambda _ui: calls.append("focused"),
        run_paper_freeze_readiness=lambda: calls.append("paper"),
        run_state_summary=lambda: calls.append("state"),
        run_freeze_readiness_audit=lambda: calls.append("freeze"),
        verify_host_pcap_tools=lambda: calls.append("tools"),
        choose_active_research_cohort=lambda: calls.append("cohort"),
        repair_reindex_tracker=lambda: calls.append("repair"),
        prune_incomplete_dynamic_evidence_dirs=lambda: calls.append("prune"),
        open_legacy_structural_archive=lambda _pause: calls.append("legacy"),
        run_cohort_security_audit_export=lambda: calls.append("security_export"),
    )

    run_dynamic_analysis_menu(callbacks)

    assert calls == ["focused"]


def test_menu_hub_routes_choice_3_to_paper_freeze_readiness(monkeypatch) -> None:
    from scytaledroid.DynamicAnalysis.menus import menu_hub as hub_module

    calls: list[str] = []

    choices = iter(["3", "0"])

    monkeypatch.setattr(
        hub_module.schema_gate,
        "dynamic_schema_gate",
        lambda: (True, "ok", None),
    )
    monkeypatch.setattr(
        hub_module,
        "build_dynamic_menu_sections",
        lambda: SimpleNamespace(
            all_options=[],
            primary_actions=[],
            validation=[],
            maintenance=[],
            archive_export=[],
        ),
    )
    monkeypatch.setattr(hub_module, "render_dynamic_menu_overview", lambda: None)
    monkeypatch.setattr(hub_module.menu_utils, "print_menu", lambda *_a, **_k: None)
    monkeypatch.setattr(hub_module.menu_utils, "print_section", lambda *_a, **_k: None)
    monkeypatch.setattr(hub_module.prompt_utils, "get_choice", lambda *_a, **_k: next(choices))

    callbacks = DynamicAnalysisMenuCallbacks(
        warn_if_code_changed=lambda: None,
        load_ui_defaults=lambda: SimpleNamespace(),
        resolve_active_cohort_for_run=lambda: None,
        run_guided_dataset_run=lambda _ui: None,
        run_focused_app_run=lambda _ui: None,
        run_paper_freeze_readiness=lambda: calls.append("paper"),
        run_state_summary=lambda: calls.append("state"),
        run_freeze_readiness_audit=lambda: calls.append("freeze"),
        verify_host_pcap_tools=lambda: calls.append("tools"),
        choose_active_research_cohort=lambda: calls.append("cohort"),
        repair_reindex_tracker=lambda: calls.append("repair"),
        prune_incomplete_dynamic_evidence_dirs=lambda: calls.append("prune"),
        open_legacy_structural_archive=lambda _pause: calls.append("legacy"),
        run_cohort_security_audit_export=lambda: calls.append("security_export"),
    )

    run_dynamic_analysis_menu(callbacks)

    assert calls == ["paper"]


def test_menu_hub_routes_choice_8_to_maintenance_submenu(monkeypatch) -> None:
    from scytaledroid.DynamicAnalysis.menus import menu_hub as hub_module

    calls: list[str] = []
    choices = iter(["8", "4", "0", "0"])

    monkeypatch.setattr(
        hub_module.schema_gate,
        "dynamic_schema_gate",
        lambda: (True, "ok", None),
    )
    monkeypatch.setattr(
        hub_module,
        "build_dynamic_menu_sections",
        lambda: SimpleNamespace(
            all_options=[],
            primary_actions=[],
            validation=[],
            maintenance=[],
            archive_export=[],
        ),
    )
    monkeypatch.setattr(hub_module, "render_dynamic_menu_overview", lambda: None)
    monkeypatch.setattr(hub_module.menu_utils, "print_menu", lambda *_a, **_k: None)
    monkeypatch.setattr(hub_module.menu_utils, "print_section", lambda *_a, **_k: None)
    monkeypatch.setattr(hub_module.prompt_utils, "get_choice", lambda *_a, **_k: next(choices))

    callbacks = DynamicAnalysisMenuCallbacks(
        warn_if_code_changed=lambda: None,
        load_ui_defaults=lambda: SimpleNamespace(),
        resolve_active_cohort_for_run=lambda: None,
        run_guided_dataset_run=lambda _ui: None,
        run_focused_app_run=lambda _ui: None,
        run_paper_freeze_readiness=lambda: None,
        run_state_summary=lambda: None,
        run_freeze_readiness_audit=lambda: None,
        verify_host_pcap_tools=lambda: None,
        choose_active_research_cohort=lambda: None,
        repair_reindex_tracker=lambda: calls.append("repair"),
        prune_incomplete_dynamic_evidence_dirs=lambda: calls.append("prune"),
        open_legacy_structural_archive=lambda _pause: calls.append("legacy"),
        run_cohort_security_audit_export=lambda: calls.append("security_export"),
    )

    run_dynamic_analysis_menu(callbacks)

    assert calls == ["security_export"]


def test_menu_hub_renders_single_line_option_blocks(monkeypatch) -> None:
    from scytaledroid.DynamicAnalysis.menus import menu_hub as hub_module

    print_calls: list[dict[str, object]] = []

    monkeypatch.setattr(
        hub_module.schema_gate,
        "dynamic_schema_gate",
        lambda: (True, "ok", None),
    )
    monkeypatch.setattr(
        hub_module,
        "build_dynamic_menu_sections",
        lambda: SimpleNamespace(
            all_options=[],
            primary_actions=[SimpleNamespace(key="1", disabled=False)],
            validation=[
                SimpleNamespace(key="4", disabled=False),
                SimpleNamespace(key="5", disabled=False),
                SimpleNamespace(key="6", disabled=False),
                SimpleNamespace(key="7", disabled=False),
            ],
            maintenance=[SimpleNamespace(key="8", disabled=False)],
            archive_export=[],
        ),
    )
    monkeypatch.setattr(hub_module, "render_dynamic_menu_overview", lambda: None)
    monkeypatch.setattr(hub_module.menu_utils, "print_section", lambda *_a, **_k: None)
    monkeypatch.setattr(
        hub_module.menu_utils,
        "print_menu",
        lambda items, **kwargs: print_calls.append({"count": len(items), **kwargs}),
    )
    monkeypatch.setattr(hub_module.menu_utils, "selectable_keys", lambda *_a, **_k: ["0"])
    monkeypatch.setattr(hub_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    callbacks = DynamicAnalysisMenuCallbacks(
        warn_if_code_changed=lambda: None,
        load_ui_defaults=lambda: SimpleNamespace(),
        resolve_active_cohort_for_run=lambda: None,
        run_guided_dataset_run=lambda _ui: None,
        run_focused_app_run=lambda _ui: None,
        run_paper_freeze_readiness=lambda: None,
        run_state_summary=lambda: None,
        run_freeze_readiness_audit=lambda: None,
        verify_host_pcap_tools=lambda: None,
        choose_active_research_cohort=lambda: None,
        repair_reindex_tracker=lambda: None,
        prune_incomplete_dynamic_evidence_dirs=lambda: None,
        open_legacy_structural_archive=lambda _pause: None,
        run_cohort_security_audit_export=lambda: None,
    )

    run_dynamic_analysis_menu(callbacks)

    option_calls = [call for call in print_calls if call["count"] > 0]
    assert option_calls
    assert all(call.get("show_descriptions") is False for call in option_calls)
    assert len(option_calls) == 1
    assert option_calls[0]["count"] == 6
