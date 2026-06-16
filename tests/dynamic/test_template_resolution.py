from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.templates import category_map


def test_resolved_template_falls_back_to_category_map() -> None:
    category_map._load_mapping.cache_clear()
    assert category_map.resolved_template_for_package("com.linkedin.android") == "social_feed_basic_v2"


def test_resolved_template_uses_override_when_present(tmp_path: Path, monkeypatch) -> None:
    override_path = tmp_path / "app_template_overrides_v1.json"
    override_path.write_text(
        json.dumps(
            {
                "version": "v1",
                "packages": {"com.snapchat.android": "snapchat_basic_v1"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(category_map, "_OVERRIDE_PATH", override_path)
    assert category_map.resolved_template_for_package("com.snapchat.android") == "snapchat_basic_v1"


def test_news_packages_resolve_to_news_reader_template() -> None:
    category_map._load_mapping.cache_clear()
    assert category_map.resolved_template_for_package("bbc.mobile.news.ww") == "news_reader_basic_v1"
    assert category_map.resolved_template_for_package("com.cnn.mobile.android.phone") == "news_reader_basic_v1"
    assert category_map.resolved_template_for_package("com.guardian") == "news_reader_basic_v1"


def test_v3_news_overrides_resolve_without_catalog_membership(monkeypatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_TEMPLATE_MAP_PROFILE", "v3")
    category_map._load_v3_catalog.cache_clear()
    assert category_map.resolved_template_for_package("bbc.mobile.news.ww") == "news_reader_basic_v1"
    assert category_map.resolved_template_for_package("com.cnn.mobile.android.phone") == "news_reader_basic_v1"
    assert category_map.resolved_template_for_package("com.guardian") == "news_reader_basic_v1"
