from __future__ import annotations

import importlib
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.commands.models import Command
from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, RepositoryArtifact


def _dummy_group(package_name: str = "com.example.app", version_name: str = "1.0.0", version_code: str = "42"):
    artifact = RepositoryArtifact(
        path=Path(f"/tmp/{package_name}-{version_code}.apk"),
        display_path=f"{package_name}-{version_code}.apk",
        metadata={
            "package_name": package_name,
            "version_code": version_code,
            "version_name": version_name,
        },
    )
    return ArtifactGroup(
        group_key=f"{package_name}:{version_name}",
        package_name=package_name,
        version_display=version_name,
        session_stamp=None,
        capture_id=f"capture-{version_code}",
        artifacts=(artifact,),
    )


def test_static_menu_renders_pipeline_state(monkeypatch, capsys):
    menu_module = importlib.import_module("scytaledroid.StaticAnalysis.cli.menus.static_analysis_menu")
    dummy_group = _dummy_group()

    monkeypatch.setattr("scytaledroid.StaticAnalysis.core.repository.group_artifacts", lambda *_a, **_k: (dummy_group,))
    monkeypatch.setattr(menu_module.static_scope_service, "count", lambda: 0)
    monkeypatch.setattr(menu_module.static_scope_service, "selected_set", lambda: set())
    monkeypatch.setattr(menu_module.static_scope_service, "prune_missing_paths", lambda *_a, **_k: 0)
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.schema_gate.check_base_schema",
        lambda: (True, None, None),
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.schema_gate.static_schema_gate",
        lambda: (True, None, None),
    )
    monkeypatch.setattr(
        menu_module,
        "describe_last_selection",
        lambda _groups: {"available": True, "label": "Example | com.example.app", "source": "static-run"},
    )
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.static_analysis_menu()

    out = capsys.readouterr().out
    assert "harvested and stored locally" in out
    assert "does not query the live device inventory" in out
    assert "Harvested library" in out
    assert "Packages          : 1" in out
    assert "Harvest captures  : 1" in out
    assert "Capture meaning" in out
    assert "Profile vs pipeline" not in out
    assert "Run scope" in out
    assert "Analyze all harvested apps" in out
    assert "Analyze by profile" in out
    assert "Analyze one app" in out
    assert "Re-analyze last app" in out
    assert "Review" in out
    assert "View previous static runs" in out
    assert "Compare two app versions" in out
    assert "APK drilldown" in out
    assert "Library details" in out


def test_reanalyze_last_command_prompts_reset() -> None:
    from scytaledroid.StaticAnalysis.cli.commands import get_command

    command = get_command("3")

    assert command is not None
    assert command.prompt_reset is True


def test_choose_run_profile_full_shows_pipeline_summary_after_selection(monkeypatch, capsys) -> None:
    menu_module = importlib.import_module("scytaledroid.StaticAnalysis.cli.menus.static_analysis_menu")

    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "1")

    command = menu_module._choose_run_profile()

    assert command is not None
    assert command.profile == "full"
    out = capsys.readouterr().out
    assert "Preset            : Full analysis" in out
    assert "Analyzer modules  : 9" in out
    assert "Detector stages   :" in out and "ordered" in out


def test_choose_run_profile_exposes_focused_validation_modes(monkeypatch) -> None:
    menu_module = importlib.import_module("scytaledroid.StaticAnalysis.cli.menus.static_analysis_menu")

    choices = iter(["4", "2"])
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: next(choices))

    command = menu_module._choose_run_profile()

    assert command is not None
    assert command.profile == "permissions"
    assert command.title == "Permission audit"


def test_choose_all_scope_variant_returns_smoke_batch(monkeypatch) -> None:
    menu_module = importlib.import_module("scytaledroid.StaticAnalysis.cli.menus.static_analysis_menu")
    groups = tuple(_dummy_group(package_name=f"com.example.app{i}", version_code=str(i)) for i in range(1, 13))
    selection = menu_module._latest_scope_for_all(groups)

    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "3")

    scoped = menu_module._choose_all_scope_variant(selection)

    assert scoped is not None
    assert scoped.label == "Smoke batch (10 apps)"
    assert len(scoped.groups) == 10


def test_choose_all_scope_variant_returns_persistence_test_batch(monkeypatch) -> None:
    menu_module = importlib.import_module("scytaledroid.StaticAnalysis.cli.menus.static_analysis_menu")
    groups = tuple(_dummy_group(package_name=f"com.example.persist{i}", version_code=str(i)) for i in range(1, 13))
    selection = menu_module._latest_scope_for_all(groups)

    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "5")

    scoped = menu_module._choose_all_scope_variant(selection)

    assert scoped is not None
    assert scoped.label == "Persistence test (10 apps)"
    assert len(scoped.groups) == 10


def test_choose_run_profile_exposes_persistence_test_preset(monkeypatch) -> None:
    menu_module = importlib.import_module("scytaledroid.StaticAnalysis.cli.menus.static_analysis_menu")

    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "3")

    command = menu_module._choose_run_profile()

    assert command is not None
    assert command.profile == "full"
    assert command.title == "Persistence test"
    assert command.prompt_reset is True
    assert command.auto_verify is True
    assert command.workers_override == "2"


def test_choose_run_profile_can_back_out_from_advanced_profiles(monkeypatch) -> None:
    menu_module = importlib.import_module("scytaledroid.StaticAnalysis.cli.menus.static_analysis_menu")

    choices = iter(["4", "0"])
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: next(choices))

    command = menu_module._choose_run_profile()

    assert command is None


def test_run_setup_replace_existing_is_single_confirmation(monkeypatch, capsys) -> None:
    actions = importlib.import_module("scytaledroid.StaticAnalysis.cli.menus.actions")
    selection = ScopeSelection("app", "Facebook | com.facebook.katana", (_dummy_group("com.facebook.katana"),))
    params = RunParameters(
        profile="full",
        scope="app",
        scope_label="Facebook | com.facebook.katana",
        session_stamp="20260429-fcfk-full",
    )
    command = Command(
        id="1",
        title="Run Static Pipeline (Full)",
        description="Run full static profile.",
        kind="scan",
        profile="full",
    )

    monkeypatch.setattr(actions, "_lookup_existing_session_state", lambda _stamp: (True, 1, 1832))
    monkeypatch.setattr(actions.prompt_utils, "get_choice", lambda *_a, **_k: "1")

    action, effective, reset_mode = actions.prompt_run_setup(params, selection, command)

    out = capsys.readouterr().out
    assert "Run Setup" in out
    assert "Post-run audit" in out
    assert "audit_static_session.py" in out
    assert "Existing session" in out
    assert "Canonical run" in out
    assert "static_run_id=1832" in out
    assert "Replace this session and rerun" in out
    assert "Session reset" not in out
    assert action == "run"
    assert effective.canonical_action == "replace"
    assert reset_mode == "session"


def test_run_setup_change_options_routes_to_advanced(monkeypatch) -> None:
    actions = importlib.import_module("scytaledroid.StaticAnalysis.cli.menus.actions")
    selection = ScopeSelection("app", "Signal", (_dummy_group("org.thoughtcrime.securesms"),))
    params = RunParameters(profile="lightweight", scope="app", scope_label="Signal")
    command = Command(
        id="2",
        title="Run Static Pipeline (Fast)",
        description="Run fast static profile.",
        kind="scan",
        profile="lightweight",
    )

    monkeypatch.setattr(actions, "_lookup_existing_session_state", lambda _stamp: (False, 0, None))
    monkeypatch.setattr(actions.prompt_utils, "get_choice", lambda *_a, **_k: "3")

    action, _effective, reset_mode = actions.prompt_run_setup(params, selection, command)

    assert action == "advanced"
    assert reset_mode is None


def test_static_menu_shows_persistence_warning_when_schema_is_unavailable(monkeypatch, capsys):
    menu_module = importlib.import_module("scytaledroid.StaticAnalysis.cli.menus.static_analysis_menu")
    dummy_group = _dummy_group()

    monkeypatch.setattr("scytaledroid.StaticAnalysis.core.repository.group_artifacts", lambda *_a, **_k: (dummy_group,))
    monkeypatch.setattr(menu_module.static_scope_service, "count", lambda: 0)
    monkeypatch.setattr(menu_module.static_scope_service, "selected_set", lambda: set())
    monkeypatch.setattr(menu_module.static_scope_service, "prune_missing_paths", lambda *_a, **_k: 0)
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.schema_gate.check_base_schema",
        lambda: (False, "Database disabled.", "DB is optional."),
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.schema_gate.static_schema_gate",
        lambda: (False, "Static Analysis schema unavailable.", "offline"),
    )
    monkeypatch.setattr(menu_module, "describe_last_selection", lambda _groups: {"available": False, "label": "", "source": "none"})
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.static_analysis_menu()

    out = capsys.readouterr().out
    assert "Persistence unavailable" in out
    assert "Dry-run commands remain available" in out


def test_static_menu_renders_library_size_not_internal_state(monkeypatch, capsys):
    menu_module = importlib.import_module("scytaledroid.StaticAnalysis.cli.menus.static_analysis_menu")
    older_group = _dummy_group(version_code="41")
    latest_group = _dummy_group(version_code="42")
    older_group = ArtifactGroup(
        group_key=older_group.group_key,
        package_name=older_group.package_name,
        version_display=older_group.version_display,
        session_stamp="20260416",
        capture_id="20260416",
        artifacts=older_group.artifacts,
    )
    latest_group = ArtifactGroup(
        group_key=latest_group.group_key,
        package_name=latest_group.package_name,
        version_display=latest_group.version_display,
        session_stamp="20260427",
        capture_id="20260427",
        artifacts=latest_group.artifacts,
    )

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.core.repository.group_artifacts",
        lambda *_a, **_k: (older_group, latest_group),
    )
    monkeypatch.setattr(menu_module.static_scope_service, "count", lambda: 0)
    monkeypatch.setattr(menu_module.static_scope_service, "selected_set", lambda: set())
    monkeypatch.setattr(menu_module.static_scope_service, "prune_missing_paths", lambda *_a, **_k: 0)
    monkeypatch.setattr("scytaledroid.Database.db_utils.schema_gate.check_base_schema", lambda: (True, None, None))
    monkeypatch.setattr("scytaledroid.Database.db_utils.schema_gate.static_schema_gate", lambda: (True, None, None))
    monkeypatch.setattr(menu_module, "describe_last_selection", lambda _groups: {"available": False, "label": "", "source": "none"})
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.static_analysis_menu()

    out = capsys.readouterr().out
    assert "Harvest captures  : 2" in out
    assert "Capture sessions" not in out
    assert "Target groups" not in out
    assert "Primary Actions" not in out
    assert "Review" in out
    assert "Tools" not in out
