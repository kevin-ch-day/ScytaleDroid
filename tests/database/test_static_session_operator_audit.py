from __future__ import annotations

from scytaledroid.Database.db_utils.static_session_operator_audit import sql_literal_for_session


def test_sql_literal_for_session_escapes_single_quotes() -> None:
    assert sql_literal_for_session("2026-all") == "'2026-all'"
    assert sql_literal_for_session("o'reilly") == "'o''reilly'"
    assert sql_literal_for_session("") == "''"
