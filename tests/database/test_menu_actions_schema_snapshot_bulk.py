"""Tests for bulk schema snapshot helpers (no live DB)."""

from __future__ import annotations

from scytaledroid.Database.db_utils import menu_actions as ma


def test_index_signatures_from_statistics_rows_composite_primary() -> None:
    rows = (
        ("apps", "PRIMARY", 0, 1, "id"),
        ("apps", "PRIMARY", 0, 2, "name"),
        ("apps", "idx_pkg", 1, 1, "package_name"),
    )
    out = ma._index_signatures_from_statistics_rows(rows)
    assert out["apps"] == {
        "PRIMARY|unique|id,name",
        "idx_pkg|non_unique|package_name",
    }


def test_index_signatures_from_statistics_rows_skips_empty_column() -> None:
    rows = (("t", "PRIMARY", 0, 1, ""),)
    assert ma._index_signatures_from_statistics_rows(rows) == {}
