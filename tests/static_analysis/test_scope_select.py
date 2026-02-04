from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
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
    assert any("skipped 1 older capture" in message for message in logged)


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
