from __future__ import annotations

import pytest
from scytaledroid.Database.db_core.sql_ident import (
    quote_sql_ident,
    quote_viewlike_ident,
    require_sql_ident,
)
from scytaledroid.Database.db_utils.diagnostics import _quote_identifier


def test_quote_sql_ident_accepts_plain_names() -> None:
    assert quote_sql_ident("static_analysis_runs") == "`static_analysis_runs`"
    assert quote_sql_ident("v_web_static_session_index_v2") == "`v_web_static_session_index_v2`"


@pytest.mark.parametrize(
    "name",
    [
        "runs`; DROP TABLE apps; --",
        "foo bar",
        "runs`x",
        "../apps",
        "",
        "123runs",
    ],
)
def test_quote_sql_ident_rejects_unsafe_names(name: str) -> None:
    assert quote_sql_ident(name) is None
    with pytest.raises(ValueError, match="unsafe SQL identifier"):
        require_sql_ident(name)


def test_quote_viewlike_ident_requires_v_or_vw_prefix() -> None:
    assert quote_viewlike_ident("v_static_session_health_v2") == "`v_static_session_health_v2`"
    assert quote_viewlike_ident("vw_web_example") == "`vw_web_example`"
    assert quote_viewlike_ident("static_analysis_runs") is None
    assert quote_viewlike_ident("v_foo`; DROP TABLE apps; --") is None


def test_diagnostics_quote_identifier_rejects_injection() -> None:
    assert _quote_identifier("static_analysis_runs") == "`static_analysis_runs`"
    with pytest.raises(ValueError, match="unsafe SQL identifier"):
        _quote_identifier("runs`; DROP TABLE apps; --")
