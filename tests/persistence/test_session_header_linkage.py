from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.persistence.session_header_linkage import (
    resolve_static_session_id_for_run,
)


def test_resolve_static_session_id_blank_stamp():
    assert resolve_static_session_id_for_run(None, None) is None
    assert resolve_static_session_id_for_run("  ", "x") is None


def test_resolve_static_session_id_tuple_row(monkeypatch):
    calls: list[tuple[object, ...]] = []

    def fake_run_sql(query, params=None, *, fetch="none", **kwargs):
        calls.append((query.strip(), params, fetch))
        if fetch == "one":
            return (42,)
        return None

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.session_header_linkage.core_q.run_sql",
        fake_run_sql,
    )
    assert resolve_static_session_id_for_run("stamp-a", "scope-b") == 42
    assert calls and calls[0][1] == ("stamp-a", "scope-b")


def test_resolve_static_session_id_swallows_db_errors(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("db down")

    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.session_header_linkage.core_q.run_sql",
        boom,
    )
    assert resolve_static_session_id_for_run("s", "") is None
