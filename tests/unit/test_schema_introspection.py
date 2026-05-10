"""Unit tests for database.db_core.schema_introspection."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from scytaledroid.Database.db_core import schema_introspection


def test_table_exists_true_when_count_positive(monkeypatch):
    mock_run = MagicMock(return_value=(1,))
    monkeypatch.setattr(schema_introspection, "run_sql", mock_run)
    assert schema_introspection.table_exists("some_table") is True
    mock_run.assert_called_once()
    assert mock_run.call_args[0][1] == ("some_table",)


def test_table_exists_false_on_zero(monkeypatch):
    monkeypatch.setattr(schema_introspection, "run_sql", MagicMock(return_value=(0,)))
    assert schema_introspection.table_exists("missing") is False


def test_table_exists_false_on_exception(monkeypatch):
    monkeypatch.setattr(schema_introspection, "run_sql", MagicMock(side_effect=RuntimeError("boom")))
    assert schema_introspection.table_exists("x") is False


def test_table_exists_forwards_query_name(monkeypatch):
    mock_run = MagicMock(return_value=(1,))
    monkeypatch.setattr(schema_introspection, "run_sql", mock_run)
    assert schema_introspection.table_exists("t", query_name="probe.table") is True
    assert mock_run.call_args.kwargs.get("query_name") == "probe.table"
