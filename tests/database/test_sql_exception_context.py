"""Tests for SQL exception context extraction."""

from __future__ import annotations

from scytaledroid.Database.db_utils.sql_exception_context import (
    extract_sql_exception_context,
    infer_failing_table,
)


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
