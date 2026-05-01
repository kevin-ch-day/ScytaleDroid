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
