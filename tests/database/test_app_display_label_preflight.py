"""Unit tests for ``apps.display_name`` coverage helpers (no live DB)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest


@pytest.fixture
def preflight_mod():
    from scytaledroid.Database.db_utils.catalog import app_display_label_preflight

    return app_display_label_preflight


def test_summarize_empty_groups_returns_none(preflight_mod, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_config.db_enabled",
        lambda: True,
    )
    assert preflight_mod.summarize_apps_display_labels_for_groups(()) is None


def test_summarize_none_when_db_disabled(preflight_mod, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_config.db_enabled",
        lambda: False,
    )
    groups = (SimpleNamespace(package_name="com.example.app"),)
    assert preflight_mod.summarize_apps_display_labels_for_groups(groups) is None


def test_summarize_labeled_counts(preflight_mod, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_config.db_enabled",
        lambda: True,
    )

    def _fake_map(_groups):
        return {"com.foo": "Foo App", "com.bar": "   "}

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.core.repository.load_display_name_map",
        _fake_map,
    )
    groups = (
        SimpleNamespace(package_name="com.foo"),
        SimpleNamespace(package_name="COM.BAR"),
    )
    assert preflight_mod.summarize_apps_display_labels_for_groups(groups) == (1, 2)


def test_format_line_when_db_disabled(preflight_mod, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_config.db_enabled",
        lambda: False,
    )
    line = preflight_mod.format_apps_display_name_hygiene_line(
        (SimpleNamespace(package_name="com.foo"),)
    )
    assert line is not None
    assert "skipped" in line.lower()


def test_format_line_includes_counts_and_option_hint(preflight_mod, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_config.db_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.core.repository.load_display_name_map",
        lambda _g: {"com.foo": "X", "com.bar": ""},
    )
    groups = (
        SimpleNamespace(package_name="com.foo"),
        SimpleNamespace(package_name="com.bar"),
    )
    line = preflight_mod.format_apps_display_name_hygiene_line(groups)
    assert line is not None
    assert "1/2" in line
    assert "option 11" in line


def test_format_line_explains_preflight_vs_focus_bucket_gap(
    preflight_mod, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_config.db_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.core.repository.load_display_name_map",
        lambda _g: {f"com.app{i}": "" for i in range(9)},
    )
    monkeypatch.setattr(preflight_mod, "_resolve_latest_inventory_snapshot_id", lambda: 501)
    monkeypatch.setattr(
        preflight_mod,
        "_count_play_store_focus_bucket_hits",
        lambda _snap, keys: 8 if len(keys) == 9 else 0,
    )
    groups = tuple(SimpleNamespace(package_name=f"com.app{i}") for i in range(9))
    line = preflight_mod.format_apps_display_name_hygiene_line(groups)
    assert line is not None
    assert "0/9 labeled" in line
    assert "Play/Unclassified hygiene focus matches 8/9" in line
    assert "1 outside that bucket" in line
    assert "snapshot 501" in line
