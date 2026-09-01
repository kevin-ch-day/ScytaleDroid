from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.persistence import static_session_summary as sss
from scytaledroid.StaticAnalysis.cli.persistence.static_session_summary import (
    StaticSessionRunRollups,
)


def test_record_completion_reconciliation_persists_frozen_denominator(monkeypatch):
    writes: list[tuple[object, ...]] = []

    def _write(_sql, params, **_kwargs):
        writes.append(params)
        return 1

    monkeypatch.setattr(sss.core_q, "run_sql_rowcount", _write)

    assert sss.record_static_session_completion_reconciliation(
        session_stamp="session-1",
        scope_label="All harvested apps",
        receipt={
            "status": "INCOMPLETE",
            "selected_packages": 15,
            "terminal_packages": 14,
            "selection_artifact_manifest_sha256": "a" * 64,
        },
    ) is True
    assert writes
    assert writes[0][0:4] == (15, 14, "INCOMPLETE", "a" * 64)


def test_record_completion_reconciliation_rejects_invalid_receipt(monkeypatch):
    monkeypatch.setattr(
        sss.core_q,
        "run_sql_rowcount",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected DB write")),
    )

    assert sss.record_static_session_completion_reconciliation(
        session_stamp="session-1",
        scope_label="scope",
        receipt={"status": "COMPLETE_RECONCILED", "selection_artifact_manifest_sha256": "bad"},
    ) is False


def test_maybe_refresh_static_analysis_session_summary_noop_blank_stamp(monkeypatch):
    called: list[object] = []

    def boom(*_a, **_k):
        called.append(True)
        raise RuntimeError("should not run")

    monkeypatch.setattr(sss, "refresh_static_analysis_session_summary", boom)
    sss.maybe_refresh_static_analysis_session_summary("  ", "x", reason="t")
    assert called == []


def test_maybe_refresh_static_analysis_session_summary_swallows_errors(monkeypatch):
    warnings: list[str] = []

    def boom(**_k):
        raise RuntimeError("db unavailable")

    monkeypatch.setattr(sss, "refresh_static_analysis_session_summary", boom)
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.cli.persistence.static_session_summary.log.warning",
        lambda msg, **_kw: warnings.append(msg),
    )

    sss.maybe_refresh_static_analysis_session_summary("s1", "scope-a", reason="unit")
    assert len(warnings) == 1
    assert "session_refresh" in warnings[0] or "unit" in warnings[0]


def test_materialize_static_session_rollup_upserts_run_aggregate(monkeypatch):
    inserts: list[tuple[object, ...]] = []

    def _run_sql(sql, params=(), fetch=None, **_kwargs):  # type: ignore[no-untyped-def]
        normalized = " ".join(str(sql).split())
        if "COUNT(*) AS total_run_count" in normalized and "FROM static_analysis_runs" in normalized:
            return {
                "total_run_count": 5,
                "completed_run_count": 4,
                "failed_run_count": 1,
                "running_run_count": 0,
                "interrupted_run_count": 1,
                "persist_error_run_count": 0,
                "missing_artifacts_run_count": 0,
                "first_created_at": None,
                "last_ended_at": None,
            }
        if normalized.startswith("INSERT INTO static_session_rollups"):
            inserts.append(tuple(params))
            return None
        raise AssertionError((sql, params, fetch))

    monkeypatch.setattr(sss.core_q, "run_sql", _run_sql)

    assert sss.materialize_static_session_rollup(
        session_stamp="sess-1",
        scope_label=" All harvested apps ",
    )
    assert inserts == [("sess-1", "All harvested apps", 5, 4, 1, 1, 0)]


def test_refresh_static_analysis_session_summary_can_materialize_rollup(monkeypatch):
    materialize_calls: list[tuple[str, str | None]] = []
    updates: list[tuple[object, ...]] = []
    rollups = StaticSessionRunRollups(
        total_run_count=2,
        completed_run_count=2,
        failed_run_count=0,
        running_run_count=0,
        interrupted_run_count=0,
        persist_error_run_count=0,
        missing_artifacts_run_count=0,
        first_created_at=None,
        last_ended_at=None,
    )

    monkeypatch.setattr(sss, "fetch_static_session_run_rollups", lambda *_a: rollups)
    monkeypatch.setattr(
        sss,
        "materialize_static_session_rollup",
        lambda *, session_stamp, scope_label: materialize_calls.append((session_stamp, scope_label))
        or True,
    )

    def _run_sql(sql, params=(), fetch=None, **_kwargs):  # type: ignore[no-untyped-def]
        normalized = " ".join(str(sql).split())
        if "SELECT static_session_id FROM static_analysis_sessions" in normalized:
            return {"static_session_id": 42}
        if "COUNT(*) AS child_cnt" in normalized:
            return {"child_cnt": 0}
        if "latest_run_provenance" in str(_kwargs.get("query_name", "")):
            return (None, None, None)
        if normalized.startswith("UPDATE static_analysis_sessions"):
            updates.append(tuple(params))
            return None
        raise AssertionError((sql, params, fetch, _kwargs))

    monkeypatch.setattr(sss.core_q, "run_sql", _run_sql)

    assert sss.refresh_static_analysis_session_summary(
        session_stamp="sess-1",
        scope_label="scope-a",
        materialize_rollup=True,
    )
    assert materialize_calls == [("sess-1", "scope-a")]
    assert updates
