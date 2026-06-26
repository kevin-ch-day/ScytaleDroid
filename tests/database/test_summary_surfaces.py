from __future__ import annotations

from scytaledroid.Database import summary_surfaces


def test_preferred_static_dynamic_summary_relation_ignores_stale_cache(monkeypatch):
    monkeypatch.setattr(
        summary_surfaces,
        "static_dynamic_summary_cache_status",
        lambda **_kwargs: (547, "2026-04-28 00:00:00"),
    )
    monkeypatch.setattr(
        summary_surfaces,
        "static_dynamic_summary_cache_is_stale",
        lambda **_kwargs: True,
    )
    monkeypatch.setattr(
        summary_surfaces,
        "static_dynamic_summary_cache_has_required_runtime_columns",
        lambda **_kwargs: True,
    )

    assert (
        summary_surfaces.preferred_static_dynamic_summary_relation()
        == summary_surfaces.STATIC_DYNAMIC_SUMMARY_VIEW
    )


def test_preferred_static_dynamic_summary_relation_uses_fresh_cache(monkeypatch):
    monkeypatch.setattr(
        summary_surfaces,
        "static_dynamic_summary_cache_status",
        lambda **_kwargs: (547, "2026-04-28 00:00:00"),
    )
    monkeypatch.setattr(
        summary_surfaces,
        "static_dynamic_summary_cache_is_stale",
        lambda **_kwargs: False,
    )
    monkeypatch.setattr(
        summary_surfaces,
        "static_dynamic_summary_cache_has_required_runtime_columns",
        lambda **_kwargs: True,
    )

    assert (
        summary_surfaces.preferred_static_dynamic_summary_relation()
        == summary_surfaces.STATIC_DYNAMIC_SUMMARY_CACHE
    )


def test_preferred_static_dynamic_summary_relation_rejects_cache_missing_runtime_columns(monkeypatch):
    monkeypatch.setattr(
        summary_surfaces,
        "static_dynamic_summary_cache_status",
        lambda **_kwargs: (547, "2026-04-28 00:00:00"),
    )
    monkeypatch.setattr(
        summary_surfaces,
        "static_dynamic_summary_cache_is_stale",
        lambda **_kwargs: False,
    )
    monkeypatch.setattr(
        summary_surfaces,
        "static_dynamic_summary_cache_has_required_runtime_columns",
        lambda **_kwargs: False,
    )

    assert (
        summary_surfaces.preferred_static_dynamic_summary_relation()
        == summary_surfaces.STATIC_DYNAMIC_SUMMARY_VIEW
    )


def test_static_dynamic_summary_relation_has_required_runtime_columns_checks_named_relation(monkeypatch):
    calls: list[tuple[str, tuple[object, ...], str | None]] = []

    def fake_runner(sql, params=(), *, fetch="one", query_name=None, **_kwargs):  # noqa: ANN001,ARG001
        calls.append((sql, tuple(params), fetch))
        return (len(summary_surfaces.STATIC_DYNAMIC_SUMMARY_REQUIRED_RUNTIME_COLUMNS),)

    ok = summary_surfaces.static_dynamic_summary_relation_has_required_runtime_columns(
        "v_web_static_dynamic_app_summary",
        runner=fake_runner,
    )

    assert ok is True
    assert calls
    _sql, params, fetch = calls[0]
    assert params[0] == "v_web_static_dynamic_app_summary"
    assert params[1:] == summary_surfaces.STATIC_DYNAMIC_SUMMARY_REQUIRED_RUNTIME_COLUMNS
    assert fetch == "one"
