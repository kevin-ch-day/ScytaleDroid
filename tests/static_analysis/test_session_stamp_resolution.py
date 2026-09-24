from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.flows import session_stamp_resolution
from scytaledroid.StaticAnalysis.cli.menus import actions


def test_existing_session_label_sql_forces_unicode_collation() -> None:
    sql = session_stamp_resolution.EXISTING_SESSION_LABELS_SQL
    assert "UNION" in sql
    assert sql.count("COLLATE utf8mb4_unicode_ci") >= 8
    assert "static_analysis_runs" in sql
    assert "static_analysis_sessions" in sql


def test_existing_db_session_labels_parses_union_rows(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_run_sql(query, params=(), **_kwargs):
        captured["query"] = query
        captured["params"] = params
        return [("20260919-rda-full",), {"label": "20260919-rda-full-2"}]

    monkeypatch.setattr(
        "scytaledroid.Database.db_core.db_queries.run_sql",
        _fake_run_sql,
    )

    labels = session_stamp_resolution._existing_db_session_labels("20260919-rda-full")

    assert labels == ["20260919-rda-full", "20260919-rda-full-2"]
    assert "COLLATE utf8mb4_unicode_ci" in str(captured["query"])
    assert (
        captured["params"]
        == (
            "20260919-rda-full",
            "20260919-rda-full-%",
            "20260919-rda-full",
            "20260919-rda-full-%",
        )
        * 2
    )


def test_append_session_label_uses_next_numeric_suffix(monkeypatch) -> None:
    monkeypatch.setattr(
        actions,
        "_existing_db_session_labels",
        lambda _stamp: ["20260919-rda-full"],
    )

    assert actions._next_session_append_label("20260919-rda-full") == "20260919-rda-full-2"
