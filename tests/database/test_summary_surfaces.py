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

    assert (
        summary_surfaces.preferred_static_dynamic_summary_relation()
        == summary_surfaces.STATIC_DYNAMIC_SUMMARY_CACHE
    )
