from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime

from scytaledroid.Database.db_utils import permission_audit_cleanup as cleanup


class _FakeEngine:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[object, ...] | None]] = []

    def fetch_all(self, sql, params=None, *_args, **_kwargs):
        normalized = " ".join(str(sql).split()).lower()
        if "from permission_audit_snapshots s left join permission_audit_apps a" in normalized:
            return [
                (10, "perm-audit:app:session-a", "Alpha", 12, 10, 1, 1, 501, 501, "2026-04-20 00:00:00"),
                (11, "perm-audit:app:session-b", "Beta", 0, 0, 0, 0, None, None, "2026-04-01 00:00:00"),
            ]
        if "from permission_audit_apps where score_capped < 0" in normalized:
            return [
                (91, -0.5, -0.5),
            ]
        return []

    def fetch_one(self, sql, params=None, *_args, **_kwargs):
        normalized = " ".join(str(sql).split()).lower()
        if "from permission_audit_snapshots where snapshot_id=%s" in normalized:
            snapshot_id = int(params[0])
            if "select static_run_id, run_id" in normalized:
                if snapshot_id == 10:
                    return (None, None)
                return (None, None)
            if "select run_id, static_run_id, created_at" in normalized:
                if snapshot_id == 11:
                    return (None, None, datetime(2026, 4, 1, 0, 0, 0))
                return (None, None, datetime(2026, 4, 20, 0, 0, 0))
        if "select min(run_id) from permission_audit_apps" in normalized:
            return (701,)
        return None

    def execute(self, sql, params=None, *_args, **_kwargs):
        self.executed.append((" ".join(str(sql).split()), tuple(params) if params is not None else None))


def test_extract_session_label_from_snapshot_key():
    assert cleanup.extract_session_label_from_snapshot_key("perm-audit:app:20260429-all-full") == "20260429-all-full"
    assert cleanup.extract_session_label_from_snapshot_key("other-key") is None


def test_list_permission_audit_snapshot_issues(monkeypatch):
    engine = _FakeEngine()

    @contextmanager
    def _fake_session(**_kwargs):
        yield engine

    monkeypatch.setattr(cleanup, "database_session", _fake_session)

    issues = cleanup.list_permission_audit_snapshot_issues()
    assert len(issues) == 2
    assert issues[0].snapshot_id == 10
    assert issues[0].has_single_static_run_id is True
    assert issues[1].is_empty is True


def test_repair_permission_audit_integrity_updates_expected_rows(monkeypatch):
    engine = _FakeEngine()

    @contextmanager
    def _fake_session(**_kwargs):
        yield engine

    monkeypatch.setattr(cleanup, "database_session", _fake_session)

    outcome = cleanup.repair_permission_audit_integrity(
        older_than_for_empty_delete=datetime(2026, 4, 10, 0, 0, 0),
        dry_run=False,
    )

    assert outcome.updated_totals == 1
    assert outcome.updated_lineage == 1
    assert outcome.clamped_negative_scores == 1
    assert outcome.deleted_empty_snapshots == 1

    joined = "\n".join(sql for sql, _params in engine.executed)
    assert "UPDATE permission_audit_snapshots SET apps_total=%s WHERE snapshot_id=%s" in joined
    assert "UPDATE permission_audit_snapshots SET static_run_id=%s, run_id=%s WHERE snapshot_id=%s" in joined
    assert "UPDATE permission_audit_apps SET score_raw=%s, score_capped=%s, grade=%s WHERE audit_id=%s" in joined
    assert "DELETE FROM permission_audit_snapshots WHERE snapshot_id=%s" in joined


def test_repair_permission_audit_integrity_dry_run(monkeypatch):
    engine = _FakeEngine()

    @contextmanager
    def _fake_session(**_kwargs):
        yield engine

    monkeypatch.setattr(cleanup, "database_session", _fake_session)

    outcome = cleanup.repair_permission_audit_integrity(
        older_than_for_empty_delete=datetime(2026, 4, 10, 0, 0, 0),
        dry_run=True,
    )

    assert outcome.updated_totals == 1
    assert outcome.updated_lineage == 1
    assert outcome.clamped_negative_scores == 1
    assert outcome.deleted_empty_snapshots == 1
    assert engine.executed == []
