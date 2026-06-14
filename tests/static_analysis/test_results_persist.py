from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.execution import results_persist


def test_persist_cohort_rollup_refreshes_static_session_header(monkeypatch) -> None:
    calls: list[tuple[str | None, str | None, str]] = []

    def _run_sql(sql, params=(), fetch=None, dictionary=False, **_kwargs):  # type: ignore[no-untyped-def]
        normalized = " ".join(str(sql).split())
        if "SELECT COUNT(*) AS total" in normalized and "FROM static_analysis_runs" in normalized:
            if dictionary:
                return {"total": 4, "completed": 4, "failed": 0, "running": 0}
            return (4, 4, 0, 0)
        if normalized.startswith("INSERT INTO static_session_rollups"):
            return None
        raise AssertionError((sql, params, fetch, dictionary))

    monkeypatch.setattr(results_persist.core_q, "run_sql", _run_sql)
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.static_session_summary.maybe_refresh_static_analysis_session_summary",
        lambda stamp, scope, *, reason: calls.append((stamp, scope, reason)),
    )

    results_persist._persist_cohort_rollup("sess-1", "All harvested apps")

    assert calls == [("sess-1", "All harvested apps", "post_cohort_rollup")]

