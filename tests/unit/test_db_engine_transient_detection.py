from __future__ import annotations

from pymysql import err

from scytaledroid.Database.db_core import db_engine


def test_mysql_errno_parses_from_args_code() -> None:
    exc = err.OperationalError(2013, "Lost connection to MySQL server during query")
    assert db_engine._mysql_errno(exc) == 2013


def test_mysql_errno_parses_from_message_when_code_missing() -> None:
    exc = err.OperationalError("OperationalError(2013, 'Lost connection to MySQL server during query')")
    assert db_engine._mysql_errno(exc) == 2013


def test_is_transient_detects_timeout_marker_without_errno() -> None:
    exc = err.OperationalError("Lost connection to MySQL server during query (timed out)")
    assert db_engine._is_transient(exc) is True
