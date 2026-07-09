"""Menu bulk snapshot helpers, diagnostics row counts, SQL exception context.

Merged from ``test_menu_actions_schema_snapshot_bulk``,
``test_diagnostics_approximate_table_row_counts``, ``test_sql_exception_context``.
"""

from __future__ import annotations

from contextlib import contextmanager

import pytest

from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.Database.db_utils import menu_actions as ma
from scytaledroid.Database.db_utils import reference_seed
from scytaledroid.Database.db_utils.sql_exception_context import (
    extract_sql_exception_context,
    infer_failing_table,
)


# --- menu_actions: bulk schema snapshot helpers (no live DB) ---


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


# --- diagnostics.approximate_table_row_counts (no live DB) ---


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


# --- sql_exception_context ---


def test_extract_sql_exception_context_tuple_args() -> None:
    class _OpErr(Exception):
        pass

    err = _OpErr(1062, "Duplicate entry 'pk'", "23000")
    ctx = extract_sql_exception_context(err)
    assert ctx["errno"] == 1062
    assert ctx["sqlstate"] == "23000"
    assert "Duplicate" in str(ctx["message"])


def test_extract_sql_exception_context_chained() -> None:
    class _Inner(Exception):
        pass

    inner = _Inner(1213, "Deadlock found")
    outer = RuntimeError("wrap")
    outer.__cause__ = inner
    ctx = extract_sql_exception_context(outer)
    assert ctx["errno"] == 1213


def test_infer_failing_table_permission_risk() -> None:
    msg = "static_permission_risk_vnext upsert failed: something"
    assert infer_failing_table(exception_message=msg, failure_stage="permission_risk.write") == (
        "static_permission_risk_vnext"
    )


def test_reference_seed_executes_inserts(monkeypatch):
    calls = []

    def fake_run_sql(sql, params=None, **kwargs):
        calls.append((sql, params, kwargs.get("query_name")))
        return None

    monkeypatch.setattr(reference_seed, "run_sql", fake_run_sql)
    monkeypatch.setattr(reference_seed, "table_exists", lambda *_a, **_k: True)

    reference_seed.ensure_default_reference_rows()

    # We expect at least the publishers + profiles inserts to run.
    assert any("android_app_publishers" in sql for sql, _p, _q in calls)
    assert any("android_publisher_prefix_rules" in sql for sql, _p, _q in calls)
    assert any("android_app_profiles" in sql for sql, _p, _q in calls)
    assert any("SET display_name" in sql for sql, _p, _q in calls)
