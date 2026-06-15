from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
import scytaledroid.DynamicAnalysis as dynamic_analysis
from scytaledroid.StaticAnalysis.cli.flows import selection as scope


@dataclass
class FakeGroup:
    package_name: str
    category: str
    session_stamp: str
    artifacts: tuple
    base_artifact: object | None = None


@pytest.mark.unit
def test_select_category_scope_keeps_newest_session(monkeypatch):
    groups = (
        FakeGroup("pkg.alpha", "Social media", "20251025-000000", artifacts=tuple()),
        FakeGroup("pkg.alpha", "Social media", "20251026-202635", artifacts=tuple()),
        FakeGroup("pkg.beta", "Social media", "20251026-202635", artifacts=tuple()),
    )

    mtimes: dict[tuple[str, str], float] = {
        ("pkg.alpha", "20251025-000000"): 1.0,
        ("pkg.alpha", "20251026-202635"): 5.0,
        ("pkg.beta", "20251026-202635"): 3.0,
    }
    monkeypatch.setattr(
        scope,
        "_group_latest_mtime",
        lambda group: mtimes[(group.package_name, group.session_stamp)],
    )
    monkeypatch.setattr(scope, "load_profile_map", lambda _groups: {})
    monkeypatch.setattr(scope.prompt_utils, "prompt_text", lambda *args, **kwargs: "1")
    monkeypatch.setattr(scope.menu_utils, "print_header", lambda *args, **kwargs: None)
    monkeypatch.setattr(scope.table_utils, "render_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(scope, "fetch_prior_profile_session_snapshot", lambda *_args, **_kwargs: None)

    logged: list[str] = []

    def fake_status(message: str, *, level: str = "info", **_: Any) -> str:
        logged.append(message)
        return message

    monkeypatch.setattr(scope.status_messages, "status", fake_status)

    selection = scope.select_category_scope(groups)

    assert selection.scope == "profile"
    assert [group.package_name for group in selection.groups] == ["pkg.alpha", "pkg.beta"]
    assert [group.session_stamp for group in selection.groups] == [
        "20251026-202635",
        "20251026-202635",
    ]
    assert all("older capture" not in message.lower() for message in logged)


@pytest.mark.unit
def test_select_category_scope_preserves_order_without_duplicates(monkeypatch):
    groups = (
        FakeGroup("pkg.alpha", "Social media", "20251026-202635", artifacts=tuple()),
        FakeGroup("pkg.beta", "Social media", "20251026-202635", artifacts=tuple()),
    )

    monkeypatch.setattr(scope.prompt_utils, "prompt_text", lambda *args, **kwargs: "1")
    monkeypatch.setattr(scope.menu_utils, "print_header", lambda *args, **kwargs: None)
    monkeypatch.setattr(scope.table_utils, "render_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(scope.status_messages, "status", lambda message, **kwargs: message)
    monkeypatch.setattr(scope, "_group_latest_mtime", lambda group: 1.0)
    monkeypatch.setattr(scope, "load_profile_map", lambda _groups: {})

    selection = scope.select_category_scope(groups)

    assert [group.package_name for group in selection.groups] == [
        "pkg.alpha",
        "pkg.beta",
    ]


@pytest.mark.unit
def test_select_scope_no_longer_offers_profile_v3_shortcut(monkeypatch):
    groups = (
        FakeGroup("pkg.alpha", "Social media", "20251026-202635", artifacts=tuple()),
    )

    captured: dict[str, object] = {}

    def _choice(valid, default="1", prompt=None):
        captured["valid"] = list(valid)
        return "3"

    monkeypatch.setattr(scope.prompt_utils, "get_choice", _choice)
    monkeypatch.setattr(scope.menu_utils, "print_header", lambda *args, **kwargs: None)

    selection = scope.select_scope(groups)

    assert captured["valid"] == ["1", "2", "3"]
    assert selection.scope == "all"
    assert selection.label == "All apps"


@pytest.mark.unit
def test_resolve_profile_scope_reuses_profile_selection_logic(monkeypatch):
    groups = (
        FakeGroup("pkg.alpha", "Research Dataset Alpha", "20251025-000000", artifacts=tuple()),
        FakeGroup("pkg.alpha", "Research Dataset Alpha", "20251026-202635", artifacts=tuple()),
        FakeGroup("pkg.beta", "Research Dataset Alpha", "20251026-202635", artifacts=tuple()),
    )

    monkeypatch.setattr(scope, "load_profile_map", lambda _groups: {})
    monkeypatch.setattr(scope, "_group_latest_mtime", lambda group: 1.0 if group.session_stamp.endswith("000000") else 5.0)
    monkeypatch.setattr(scope.menu_utils, "print_header", lambda *args, **kwargs: None)
    monkeypatch.setattr(scope, "_render_profile_selection_table", lambda *args, **kwargs: None)

    selection = scope.resolve_profile_scope(groups, "Research Dataset Alpha")

    assert selection.scope == "profile"
    assert selection.label == "Research Dataset Alpha"
    assert [group.package_name for group in selection.groups] == ["pkg.alpha", "pkg.beta"]


@pytest.mark.unit
def test_select_category_scope_filters_inactive_profiles(monkeypatch):
    groups = (
        FakeGroup("pkg.alpha", "Social media", "20251026-202635", artifacts=tuple()),
    )

    captured_rows: dict[str, object] = {}

    monkeypatch.setattr(
        scope,
        "list_categories",
        lambda _groups: [
            ("Social media", 1),
            ("Profile v3 Structural Cohort", 12),
        ],
    )
    monkeypatch.setattr(
        scope,
        "resolve_profile_scope",
        lambda _groups, category_name, **_kwargs: scope.ScopeSelection(
            "profile", category_name, tuple()
        ),
    )
    monkeypatch.setattr(scope.prompt_utils, "prompt_text", lambda *args, **kwargs: "1")
    monkeypatch.setattr(scope.status_messages, "status", lambda message, **kwargs: message)
    monkeypatch.setattr(scope.menu_utils, "print_header", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        scope.table_utils,
        "render_table",
        lambda _headers, rows, **_kwargs: captured_rows.setdefault("rows", rows),
    )

    selection = scope.select_category_scope(groups)

    assert selection.label == "Social media"
    assert captured_rows["rows"] == [["1", "Social media", "1"]]


@pytest.mark.unit
def test_select_category_scope_auto_selects_single_active_profile(monkeypatch):
    groups = (
        FakeGroup("pkg.alpha", "Social media", "20251026-202635", artifacts=tuple()),
    )

    captured: dict[str, object] = {"prompted": False}
    notices: list[str] = []

    monkeypatch.setattr(scope, "list_categories", lambda _groups: [("Social media", 1)])
    monkeypatch.setattr(
        scope,
        "resolve_profile_scope",
        lambda _groups, category_name, **_kwargs: scope.ScopeSelection(
            "profile", category_name, tuple()
        ),
    )
    monkeypatch.setattr(scope.menu_utils, "print_header", lambda *args, **kwargs: None)
    monkeypatch.setattr(scope.table_utils, "render_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        scope.prompt_utils,
        "prompt_text",
        lambda *args, **kwargs: captured.__setitem__("prompted", True),
    )

    def _status(message: str, **_kwargs: Any) -> str:
        notices.append(message)
        return message

    monkeypatch.setattr(scope.status_messages, "status", _status)

    selection = scope.select_category_scope(groups)

    assert selection.label == "Social media"
    assert captured["prompted"] is False
    assert any("Only one active profile is available" in notice for notice in notices)


@pytest.mark.unit
def test_select_category_scope_excludes_research_datasets(monkeypatch):
    groups = (
        FakeGroup("pkg.alpha", "Research Dataset Alpha", "20251026-202635", artifacts=tuple()),
        FakeGroup("pkg.beta", "Research Dataset Beta", "20251026-202635", artifacts=tuple()),
        FakeGroup("pkg.gamma", "Social media", "20251026-202635", artifacts=tuple()),
    )

    captured_rows: dict[str, object] = {}

    monkeypatch.setattr(
        scope,
        "list_categories",
        lambda _groups: [
            ("Research Dataset Alpha", 1),
            ("Research Dataset Beta", 2),
            ("Social media", 1),
        ],
    )
    monkeypatch.setattr(scope.menu_utils, "print_header", lambda *args, **kwargs: None)
    monkeypatch.setattr(scope.status_messages, "status", lambda message, **kwargs: message)
    monkeypatch.setattr(scope.prompt_utils, "prompt_text", lambda *args, **kwargs: "1")
    monkeypatch.setattr(
        scope.table_utils,
        "render_table",
        lambda _headers, rows, **_kwargs: captured_rows.setdefault("rows", rows),
    )

    resolved: dict[str, object] = {}

    def _resolve(_groups, category_name, **kwargs):
        resolved["category_name"] = category_name
        resolved["profile_key"] = kwargs.get("profile_key")
        resolved["packages"] = kwargs.get("packages")
        return scope.ScopeSelection("profile", category_name, tuple())

    monkeypatch.setattr(scope, "resolve_profile_scope", _resolve)

    class _FakeProfileLoader:
        @staticmethod
        def load_operational_profiles():
            return [
                {
                    "profile_key": "RESEARCH_DATASET_ALPHA",
                    "display_name": "Research Dataset Alpha",
                },
                {
                    "profile_key": "RESEARCH_DATASET_BETA",
                    "display_name": "Research Dataset Beta",
                },
                {
                    "profile_key": "SOCIAL_MEDIA",
                    "display_name": "Social media",
                },
            ]

        @staticmethod
        def load_profile_packages(profile_key):
            if profile_key == "SOCIAL_MEDIA":
                return ("pkg.gamma",)
            return tuple()

    monkeypatch.setattr(dynamic_analysis, "profile_loader", _FakeProfileLoader, raising=False)

    selection = scope.select_category_scope(groups)

    assert selection.label == "Social media"
    assert captured_rows["rows"] == [
        ["1", "Social media", "1"],
    ]
    assert resolved["category_name"] == "Social media"
    assert resolved["profile_key"] == "SOCIAL_MEDIA"
    assert resolved["packages"] == {"pkg.gamma"}


@pytest.mark.unit
def test_resolve_profile_scope_prunes_redundant_workload_copy(monkeypatch, capsys):
    groups = (
        FakeGroup("pkg.alpha", "Research Dataset Beta", "20251025-000000", artifacts=tuple()),
        FakeGroup("pkg.alpha", "Research Dataset Beta", "20251026-202635", artifacts=tuple()),
        FakeGroup("pkg.beta", "Research Dataset Beta", "20251026-202635", artifacts=tuple()),
    )

    monkeypatch.setattr(scope, "load_profile_map", lambda _groups: {})
    monkeypatch.setattr(
        scope,
        "_group_latest_mtime",
        lambda group: 1.0 if group.session_stamp.endswith("000000") else 5.0,
    )
    monkeypatch.setattr(scope, "_render_profile_selection_table", lambda *args, **kwargs: None)
    monkeypatch.setattr(scope, "load_display_name_map", lambda _groups: {})
    monkeypatch.setattr(scope.menu_utils, "print_header", lambda *args, **kwargs: None)

    scope.resolve_profile_scope(groups, "Research Dataset Beta")

    out = capsys.readouterr().out
    assert "Profile: Research Dataset Beta" in out
    assert "Newest harvested capture per package is selected automatically." in out
    assert "Research workflow" not in out
    assert "Rule   :" not in out
    assert "Older captures excluded from this run" not in out
    assert "Use Advanced / edit run options" not in out
