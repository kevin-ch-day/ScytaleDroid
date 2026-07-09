from __future__ import annotations

import warnings

from scytaledroid.StaticAnalysis.engine import aapt2_fallback
from scytaledroid.StaticAnalysis.modules.string_analysis.indexing.sources import collect_aapt2_resource_strings


def test_parse_resource_strings_from_aapt2_dump_resources() -> None:
    text = """
Binary APK
Package name=com.example id=7f
  type string id=13 entryCount=2
    resource 0x7f130000 string/app_name
      () "Example App"
    resource 0x7f130001 string/search_hint
      (en-rUS) "Search"
"""

    rows = aapt2_fallback.parse_resource_strings(text)

    assert rows == [
        {"name": "app_name", "locale": "", "value": "Example App"},
        {"name": "search_hint", "locale": "en-rUS", "value": "Search"},
    ]


def test_parse_resource_strings_ignores_non_string_resources() -> None:
    text = """
  type color id=01 entryCount=1
    resource 0x7f010000 color/primary
      () #ff000000
  type string id=13 entryCount=1
    resource 0x7f130000 string/app_name
      () "Example App"
"""

    rows = aapt2_fallback.parse_resource_strings(text)

    assert rows == [{"name": "app_name", "locale": "", "value": "Example App"}]


def test_parse_resource_strings_keeps_invalid_backslash_literals_quiet() -> None:
    text = r'''
  type string id=13 entryCount=1
    resource 0x7f130000 string/pattern
      () "Use \% and \_ literally"
'''

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        rows = aapt2_fallback.parse_resource_strings(text)

    assert caught == []
    assert rows == [{"name": "pattern", "locale": "", "value": r"Use \% and \_ literally"}]


class _FakeApk:
    filename = "fake.apk"
    split_name = "base"

    def get_buff(self):
        return b"fake-apk"


def test_collect_aapt2_resource_strings_keeps_default_and_english_unique_values(monkeypatch) -> None:
    monkeypatch.setattr(
        aapt2_fallback,
        "extract_resource_strings",
        lambda _path: [
            {"name": "title", "locale": "", "value": "Title"},
            {"name": "title", "locale": "en-rGB", "value": "Title"},
            {"name": "title", "locale": "es", "value": "Titulo"},
            {"name": "subtitle", "locale": "en-rUS", "value": "Subtitle"},
        ],
    )

    rows = collect_aapt2_resource_strings(_FakeApk())

    assert [row.value for row in rows] == ["Title", "Subtitle"]
    assert [row.locale_qualifier for row in rows] == [None, "en-rUS"]
