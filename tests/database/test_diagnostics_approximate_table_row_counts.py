"""Unit tests for diagnostics.approximate_table_row_counts (no live DB)."""

from __future__ import annotations

from contextlib import contextmanager

import pytest

from scytaledroid.Database.db_utils import diagnostics


class _FakeMysqlEngine:
    _dialect = "mysql"

    def __init__(self, rows: tuple[tuple[object, ...], ...]) -> None:
        self._rows = rows

    def fetch_all(self, *_a: object, **_kw: object) -> list[tuple[object, ...]]:
        return list(self._rows)


def test_approximate_table_row_counts_parses_int_and_null(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = (("apps", 42, "BASE TABLE"), ("v_only", None, "VIEW"))

    @contextmanager
    def fake_session(reuse_connection: bool = False):
        yield _FakeMysqlEngine(rows)

    monkeypatch.setattr(diagnostics, "database_session", fake_session)

    out = diagnostics.approximate_table_row_counts()

    assert out["apps"] == 42
    assert out["v_only"] is None


def test_approximate_table_row_counts_non_mysql_short_circuits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Sqlite:
        _dialect = "sqlite"

        def fetch_all(self, *_a: object, **_kw: object) -> list[tuple[object, ...]]:
            raise AssertionError("should not query information_schema under sqlite")

    @contextmanager
    def _sess(reuse_connection: bool = False):
        yield _Sqlite()

    monkeypatch.setattr(diagnostics, "database_session", _sess)

    assert diagnostics.approximate_table_row_counts() == {}
