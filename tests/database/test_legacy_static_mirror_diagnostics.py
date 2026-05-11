"""Unit tests for ``legacy_static_mirror_diagnostics`` (no live DB)."""

from __future__ import annotations

from scytaledroid.Database.db_utils import legacy_static_mirror_diagnostics as lsm


def test_legacy_findings_via_runs_returns_count() -> None:
    calls: list[tuple[str, tuple]] = []

    def fake_run_sql(sql, params=None, fetch=None, dictionary=False):
        calls.append((str(sql), tuple(params or ())))
        assert fetch == "one"
        return (7,)

    lf, st = lsm.legacy_findings_count_via_runs_session_stamp(fake_run_sql, "sess-a")
    assert st == "OK"
    assert lf == 7
    assert "from findings f" in calls[0][0].lower()
    assert "inner join runs" in calls[0][0].lower()
    assert calls[0][1] == ("sess-a",)


def test_legacy_findings_via_static_run_id_returns_count(monkeypatch) -> None:
    def fake_run_sql(sql, params=None, fetch=None, dictionary=False):
        assert fetch == "one"
        assert "static_analysis_runs" in str(sql).lower()
        return (3,)

    lf, st = lsm.legacy_findings_count_via_static_run_id(fake_run_sql, "sess-b")
    assert st == "OK"
    assert lf == 3


def test_legacy_findings_propagates_sql_error() -> None:
    def boom(sql, params=None, fetch=None, dictionary=False):
        raise RuntimeError("boom")

    lf, st = lsm.legacy_findings_count_via_runs_session_stamp(boom, "x")
    assert lf is None
    assert "ERROR" in st


def test_legacy_mirror_table_presence_audit_calls_diagnostics(monkeypatch) -> None:
    monkeypatch.setattr(
        lsm.diagnostics,
        "check_required_tables",
        lambda names: {n: n == "runs" for n in names},
    )
    out = lsm.legacy_mirror_table_presence_audit()
    assert out["runs"] is True
    assert out["findings"] is False


def test_legacy_runs_count_by_session_stamp() -> None:
    def fake_run_sql(sql, params=None, fetch=None, dictionary=False):
        assert fetch == "one"
        assert "from runs" in str(sql).lower()
        return (42,)

    n, st = lsm.legacy_runs_count_by_session_stamp(fake_run_sql, "sess-z")
    assert st == "OK"
    assert n == 42


def test_db_schema_snapshot_shares_legacy_mirror_tuple() -> None:
    from scytaledroid.Database.tools import db_schema_snapshot as dss

    assert dss.LEGACY_MIRROR_TABLES_SNAPSHOT is lsm.LEGACY_MIRROR_TABLES_SNAPSHOT


def test_db_verification_shares_legacy_audit_probe_tuple() -> None:
    from scytaledroid.StaticAnalysis.cli.execution import db_verification

    assert db_verification.LEGACY_MIRROR_TABLES_AUDIT is lsm.LEGACY_MIRROR_TABLES_AUDIT


def test_legacy_mirror_tables_snapshot_is_status_actions_legacy_five() -> None:
    """Schema snapshot policy must stay aligned with ``LEGACY_MIRROR_TABLES_SNAPSHOT``."""
    from scytaledroid.Database.db_utils.action_groups import status_actions as sa

    assert lsm.LEGACY_MIRROR_TABLES_SNAPSHOT is sa.DB_SNAPSHOT_LEGACY_MIRROR_TABLES
    assert set(lsm.LEGACY_MIRROR_TABLES_SNAPSHOT) == {
        "runs",
        "findings",
        "metrics",
        "buckets",
        "contributors",
    }


def test_legacy_mirror_runs_findings_presence(monkeypatch) -> None:
    monkeypatch.setattr(
        lsm.diagnostics,
        "check_required_tables",
        lambda names: {"runs": True, "findings": True},
    )
    assert lsm.LEGACY_MIRROR_RUNS_FINDINGS == ("runs", "findings")
    assert lsm.legacy_mirror_runs_findings_presence() == {"runs": True, "findings": True}
