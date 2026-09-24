from __future__ import annotations

import pytest
from pymysql import err
from scytaledroid.Database.db_core import db_engine, db_queries

LIKE_SQL = "SELECT name FROM t WHERE name LIKE '%smoke%' AND status = %s"
NAMED_IN_LITERAL_SQL = "SELECT name FROM t WHERE name LIKE '%(name)s' AND id = %(id)s"


def test_like_percent_s_is_not_a_placeholder() -> None:
    assert (
        db_engine.detect_placeholder_style("SELECT name FROM t WHERE name LIKE '%smoke%'") == "none"
    )
    assert (
        db_queries._detect_placeholder_style("SELECT name FROM t WHERE name LIKE '%smoke%'")
        == "none"
    )


def test_like_literal_does_not_mask_real_positional_placeholder() -> None:
    assert db_engine.detect_placeholder_style(LIKE_SQL) == "positional"


def test_quoted_named_token_does_not_mask_real_named_placeholder() -> None:
    assert db_engine.detect_placeholder_style(NAMED_IN_LITERAL_SQL) == "named"


def test_comment_percent_s_is_not_a_placeholder() -> None:
    sql = "SELECT 1 -- keep %s out of the scan\nFROM dual"
    assert db_engine.detect_placeholder_style(sql) == "none"


def test_sqlite_rewrite_preserves_like_literals() -> None:
    rewritten = db_engine._rewrite_for_sqlite(LIKE_SQL)
    assert "'%smoke%'" in rewritten
    assert rewritten.endswith("status = ?")
    assert "?moke" not in rewritten


def test_sqlite_rewrite_strips_mariadb_collate_clauses() -> None:
    sql = (
        "SELECT session_stamp COLLATE utf8mb4_unicode_ci AS session_stamp "
        "FROM static_analysis_sessions WHERE session_stamp = %s"
    )
    rewritten = db_engine._rewrite_for_sqlite(sql)
    assert "COLLATE" not in rewritten.upper()
    assert rewritten.endswith("session_stamp = ?")


def test_named_rewrite_skips_quoted_tokens() -> None:
    rewritten = db_engine._rewrite_unquoted_named_to_positional(NAMED_IN_LITERAL_SQL)
    assert "LIKE '%(name)s'" in rewritten
    assert rewritten.endswith("id = %s")


def test_normalise_single_orders_named_params_and_keeps_quoted_tokens() -> None:
    normalised = db_engine._normalise_single(NAMED_IN_LITERAL_SQL, {"id": 7})
    assert normalised.detected_style == "named"
    assert normalised.params == (7,)
    assert "LIKE '%(name)s'" in normalised.sql
    assert normalised.sql.endswith("id = %s")


def test_mixed_unquoted_placeholders_still_rejected() -> None:
    with pytest.raises(db_engine.ParamStyleError, match="mixes named and positional"):
        db_engine._normalise_single("SELECT %(a)s, %s", {"a": 1})


def test_validate_placeholder_style_allows_like_literal_without_params() -> None:
    db_queries._validate_placeholder_style("SELECT name FROM t WHERE name LIKE '%smoke%'", ())


def test_database_error_preserves_errno_and_sqlstate() -> None:
    wrapped = db_engine.DatabaseError("Illegal mix of collations", errno=1271, sqlstate="HY000")
    assert wrapped.errno == 1271
    assert wrapped.sqlstate == "HY000"
    assert "Illegal mix of collations" in str(wrapped)


def test_wrap_db_error_copies_mysql_errno() -> None:
    source = err.OperationalError(1271, "Illegal mix of collations")
    source.sqlstate = "HY000"
    wrapped = db_engine._wrap_db_error(db_engine.DatabaseError, source)
    assert wrapped.errno == 1271
    assert wrapped.sqlstate == "HY000"
    assert "Illegal mix of collations" in str(wrapped)
