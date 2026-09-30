from __future__ import annotations

import json
from contextlib import contextmanager

import pytest
from scripts.db.reconcile_stale_static_run import reconcile_one


def _fixture(tmp_path):
    row = {
        "id": 8002,
        "session_stamp": "20260929-all-full",
        "started_at_utc": "2026-09-29 22:18:56",
        "status": "STARTED",
        "ended_at_utc": None,
        "abort_reason": None,
        "is_canonical": 0,
        "static_session_id": 1150,
        "scope_label": "All harvested apps",
    }
    calls = {"updates": [], "refreshes": []}
    children = {}

    def run_sql(sql, params, **_kwargs):
        if sql == "SELECT DATABASE()":
            return ("scytaledroid_core_prod",)
        if sql.startswith("SELECT * FROM static_analysis_runs WHERE id=%s"):
            return dict(row)
        if "FROM static_analysis_runs WHERE id=%s" in sql:
            if "SELECT id, status" in sql:
                return dict(row)
            return dict(row)
        if sql.startswith("SELECT COUNT(*) FROM "):
            table = sql.split("FROM ", 1)[1].split(" WHERE", 1)[0]
            return (children.get(table, 0),)
        raise AssertionError(sql)

    def update(sql, params, **_kwargs):
        calls["updates"].append((sql, params))
        row.update(
            status="FAILED", ended_at_utc="2026-09-30 01:15:25", abort_reason="stale_finalize"
        )
        return 1

    def refresh(**kwargs):
        calls["refreshes"].append(kwargs)
        return True

    @contextmanager
    def transaction():
        original = dict(row)
        try:
            yield
        except Exception:
            row.clear()
            row.update(original)
            calls["rollbacks"] += 1
            raise
        else:
            calls["commits"] += 1

    calls.update(commits=0, rollbacks=0)

    kwargs = dict(
        run_id=8002,
        expect_database=None,
        expect_session=None,
        expect_started_at=None,
        expect_row_sha256=None,
        apply=False,
        run_sql=run_sql,
        run_sql_rowcount=update,
        refresh_summary=refresh,
        transaction=transaction,
        lock_path=tmp_path / "static_analysis.lock",
        receipt_root=tmp_path / "receipts",
    )
    return kwargs, calls, children


def test_dry_run_reports_exact_row_without_writes(tmp_path):
    kwargs, calls, _children = _fixture(tmp_path)
    report = reconcile_one(**kwargs)
    assert report["eligible_for_exact_close"] is True
    assert report["run"]["started_at_utc"] == "2026-09-29 22:18:56"
    assert calls == {"updates": [], "refreshes": [], "commits": 0, "rollbacks": 0}
    assert not kwargs["receipt_root"].exists()


def test_apply_closes_only_matching_empty_run_and_writes_receipt(tmp_path):
    kwargs, calls, _children = _fixture(tmp_path)
    digest = reconcile_one(**kwargs)["row_sha256"]
    kwargs.update(
        apply=True,
        expect_database="scytaledroid_core_prod",
        expect_session="20260929-all-full",
        expect_started_at="2026-09-29 22:18:56",
        expect_row_sha256=digest,
    )
    report = reconcile_one(**kwargs)
    assert report["applied"] is True
    assert report["transaction_outcome"] == "COMMITTED"
    assert report["run"]["status"] == "STARTED"
    assert report["after"]["status"] == "FAILED"
    assert report["updated_rows"] == 1
    assert calls["updates"][0][1] == (8002, "20260929-all-full", "2026-09-29 22:18:56")
    assert "status='STARTED' AND ended_at_utc IS NULL" in calls["updates"][0][0]
    assert calls["refreshes"] == [
        {"session_stamp": "20260929-all-full", "scope_label": "All harvested apps"}
    ]
    assert json.loads(next(kwargs["receipt_root"].glob("*.json")).read_text())["applied"] is True


@pytest.mark.parametrize(
    "blocker", ["child", "lock", "wrong_start", "wrong_database", "wrong_digest"]
)
def test_apply_refuses_unreviewed_or_changed_run(tmp_path, blocker):
    kwargs, calls, children = _fixture(tmp_path)
    digest = reconcile_one(**kwargs)["row_sha256"]
    kwargs.update(
        apply=True,
        expect_database="scytaledroid_core_prod",
        expect_session="20260929-all-full",
        expect_started_at="2026-09-29 22:18:56",
        expect_row_sha256=digest,
    )
    if blocker == "child":
        children["static_analysis_findings"] = 1
    elif blocker == "lock":
        kwargs["lock_path"].write_text("active")
    elif blocker == "wrong_start":
        kwargs["expect_started_at"] = "2026-09-29 22:18:57"
    elif blocker == "wrong_digest":
        kwargs["expect_row_sha256"] = "0" * 64
    else:
        kwargs["expect_database"] = "scytaledroid_core_dev"
    with pytest.raises(RuntimeError):
        reconcile_one(**kwargs)
    assert calls == {"updates": [], "refreshes": [], "commits": 0, "rollbacks": 0}


def test_apply_rolls_back_when_summary_refresh_fails(tmp_path):
    kwargs, calls, _children = _fixture(tmp_path)
    digest = reconcile_one(**kwargs)["row_sha256"]
    kwargs.update(
        apply=True,
        expect_database="scytaledroid_core_prod",
        expect_session="20260929-all-full",
        expect_started_at="2026-09-29 22:18:56",
        expect_row_sha256=digest,
        refresh_summary=lambda **_kwargs: False,
    )
    with pytest.raises(RuntimeError, match="rolled back"):
        reconcile_one(**kwargs)
    assert calls["rollbacks"] == 1
    assert calls["commits"] == 0
    receipt = json.loads(next(kwargs["receipt_root"].glob("*.json")).read_text())
    assert receipt["transaction_outcome"] == "FAILED_OR_UNCONFIRMED"


def test_apply_rolls_back_when_exact_update_matches_no_row(tmp_path):
    kwargs, calls, _children = _fixture(tmp_path)
    digest = reconcile_one(**kwargs)["row_sha256"]
    kwargs.update(
        apply=True,
        expect_database="scytaledroid_core_prod",
        expect_session="20260929-all-full",
        expect_started_at="2026-09-29 22:18:56",
        expect_row_sha256=digest,
        run_sql_rowcount=lambda *_args, **_kwargs: 0,
    )
    with pytest.raises(RuntimeError, match="rolled back"):
        reconcile_one(**kwargs)
    assert calls["rollbacks"] == 1
    assert calls["commits"] == 0


def test_apply_rechecks_lock_inside_transaction(tmp_path):
    kwargs, calls, _children = _fixture(tmp_path)
    digest = reconcile_one(**kwargs)["row_sha256"]

    @contextmanager
    def lock_during_transaction():
        kwargs["lock_path"].write_text("active")
        try:
            yield
        finally:
            calls["rollbacks"] += 1

    kwargs.update(
        apply=True,
        expect_database="scytaledroid_core_prod",
        expect_session="20260929-all-full",
        expect_started_at="2026-09-29 22:18:56",
        expect_row_sha256=digest,
        transaction=lock_during_transaction,
    )
    with pytest.raises(RuntimeError, match="changed since inspection"):
        reconcile_one(**kwargs)
    assert not calls["updates"]
    assert calls["rollbacks"] == 1
