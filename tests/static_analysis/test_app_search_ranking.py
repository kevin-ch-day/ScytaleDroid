from __future__ import annotations

import importlib
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import ScopeSelection
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, RepositoryArtifact


def _group(package_name: str) -> ArtifactGroup:
    artifact = RepositoryArtifact(
        path=Path(f"/tmp/{package_name}.apk"),
        display_path=f"{package_name}.apk",
        metadata={"package_name": package_name},
    )
    return ArtifactGroup(
        group_key=package_name,
        package_name=package_name,
        version_display="1.0.0",
        session_stamp="20260427",
        capture_id="20260427",
        artifacts=(artifact,),
    )


def test_search_app_scope_prioritizes_exact_package_match(monkeypatch) -> None:
    menu_module = importlib.import_module("scytaledroid.StaticAnalysis.cli.menus.static_analysis_menu")

    kindle = _group("com.amazon.kindle")
    shopping = _group("com.amazon.mshop.android.shopping")
    groups = (kindle, shopping)

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.core.repository.list_packages",
        lambda _groups: [
            ("com.amazon.kindle", "1", 1, "Amazon Kindle"),
            ("com.amazon.mshop.android.shopping", "1", 1, "Amazon Shopping"),
        ],
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.flows.selection.select_latest_groups",
        lambda selected: tuple(selected),
    )
    monkeypatch.setattr(
        menu_module.prompt_utils,
        "prompt_text",
        lambda *_a, **_k: "com.amazon.mshop.android.shopping",
    )
    monkeypatch.setattr(menu_module.prompt_utils, "get_choice", lambda *_a, **_k: "1")

    selection = menu_module._search_app_scope(groups)

    assert isinstance(selection, ScopeSelection)
    assert selection.scope == "app"
    assert selection.label == "Amazon Shopping | com.amazon.mshop.android.shopping"
    assert selection.groups == (shopping,)
