from __future__ import annotations

import importlib
from pathlib import Path

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
    monkeypatch.setattr(menu_module.static_scope_service, "count", lambda: 2)
    monkeypatch.setattr(menu_module.static_scope_service, "prune_missing_paths", lambda *_a, **_k: 0)
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.schema_gate.check_base_schema",
        lambda: (True, None, None),
    )
    monkeypatch.setattr(
        "scytaledroid.Database.db_utils.schema_gate.static_schema_gate",
        lambda: (True, None, None),
    )
    monkeypatch.setattr(menu_module, "describe_last_selection", lambda _groups: {"available": True, "label": "com.example.app", "source": "static-run"})
    monkeypatch.setattr(menu_module, "diff_last_available", lambda _groups: (False, "com.example.app"))
    monkeypatch.setattr(menu_module.menu_utils, "render_menu", lambda *_a, **_k: None)
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.static_analysis_menu()

    out = capsys.readouterr().out
    assert "Static Pipeline State" in out
    assert "Library groups" in out
    assert "Selected APKs" in out
    assert "Persistence" in out
    assert "Re-analyze last" in out
    assert "Version diff" in out
    assert "Last target" in out


def test_static_menu_disables_unavailable_history_actions(monkeypatch):
    menu_module = importlib.import_module("scytaledroid.StaticAnalysis.cli.menus.static_analysis_menu")
    dummy_group = _dummy_group()
    captured_specs = []

    monkeypatch.setattr("scytaledroid.StaticAnalysis.core.repository.group_artifacts", lambda *_a, **_k: (dummy_group,))
    monkeypatch.setattr(menu_module.static_scope_service, "count", lambda: 0)
    monkeypatch.setattr(menu_module.static_scope_service, "prune_missing_paths", lambda *_a, **_k: 0)
    monkeypatch.setattr("scytaledroid.Database.db_utils.schema_gate.check_base_schema", lambda: (True, None, None))
    monkeypatch.setattr("scytaledroid.Database.db_utils.schema_gate.static_schema_gate", lambda: (True, None, None))
    monkeypatch.setattr(menu_module, "describe_last_selection", lambda _groups: {"available": False, "label": "", "source": "none"})
    monkeypatch.setattr(menu_module, "diff_last_available", lambda _groups: (False, ""))
    monkeypatch.setattr(menu_module.menu_utils, "render_menu", lambda spec: captured_specs.append(spec))
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "0")

    menu_module.static_analysis_menu()

    flattened = [item for spec in captured_specs for item in getattr(spec, "items", [])]
    by_key = {item.key: item for item in flattened if hasattr(item, "key")}
    assert by_key["3"].disabled is True
    assert by_key["3"].badge == "not available"
    assert by_key["4"].disabled is True
    assert by_key["4"].badge == "not available"
