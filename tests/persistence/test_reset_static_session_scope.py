from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from scytaledroid.Database.db_utils import reset_static as reset_mod
from scytaledroid.Database.db_utils.reset_static import (
    classify_static_session_type,
    list_failed_static_session_candidates,
    list_static_session_candidates,
    purge_static_session_artifacts,
    prune_completed_static_sessions,
    prune_failed_static_sessions,
    prune_static_sessions,
    reset_static_analysis_data,
)


def test_reset_static_session_scoped_requires_session_label():
    outcome = reset_static_analysis_data(include_harvest=False, truncate_all=False, session_label=None)
    assert outcome.failed
    assert "session_label required" in outcome.failed[0][1]


def test_reset_static_session_scoped_clears_local_session_metadata(monkeypatch, tmp_path):
    session_dir = tmp_path / "sessions" / "sess-1"
    session_dir.mkdir(parents=True)
    (session_dir / "run_map.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(reset_mod.app_config, "DATA_DIR", str(tmp_path))

    class _FakeEngine:
        def fetch_all(self, *_args, **_kwargs):
            return []

        def fetch_one(self, *_args, **_kwargs):
            return None

        def execute(self, *_args, **_kwargs):
            return None

    @contextmanager
    def _fake_session(**_kwargs):
        yield _FakeEngine()

    monkeypatch.setattr(reset_mod, "database_session", _fake_session)
    monkeypatch.setattr(reset_mod, "_table_exists", lambda *_a, **_k: False)

    outcome = reset_static_analysis_data(
        include_harvest=False,
        truncate_all=False,
        session_label="sess-1",
    )

    assert not outcome.failed
    assert not session_dir.exists()


def test_reset_static_session_scoped_unlinks_dynamic_sessions_before_static_delete(monkeypatch):
    executed: list[tuple[str, tuple[object, ...] | None]] = []

    class _FakeEngine:
        def fetch_all(self, sql, params=None, *_args, **_kwargs):
            if "SELECT id FROM static_analysis_runs" in sql:
                return [(57,), (58,)]
            return []

        def fetch_one(self, sql, params=None, *_args, **_kwargs):
            if "information_schema.columns" in sql:
                table, column = params
                if table == "dynamic_sessions" and column == "static_run_id":
                    return (1,)
                if column in {"session_stamp", "session_label", "static_run_id", "run_id"}:
                    return (1,)
                return (0,)
            return None

        def execute(self, sql, params=None, *_args, **_kwargs):
            executed.append((" ".join(str(sql).split()), tuple(params) if params is not None else None))
            return None

    @contextmanager
    def _fake_session(**_kwargs):
        yield _FakeEngine()

    def _table_exists(_engine, table: str) -> bool:
        return table in {"dynamic_sessions", "static_analysis_runs", "runs", "findings"}

    monkeypatch.setattr(reset_mod, "database_session", _fake_session)
    monkeypatch.setattr(reset_mod, "_table_exists", _table_exists)
    monkeypatch.setattr(reset_mod, "_clear_local_session_metadata", lambda _session: None)

    outcome = reset_static_analysis_data(
        include_harvest=False,
        truncate_all=False,
        session_label="sess-57",
    )

    assert not outcome.failed
    assert executed[0] == (
        "UPDATE dynamic_sessions SET static_run_id=NULL WHERE static_run_id IN (%s,%s)",
        (57, 58),
    )
    assert (
        "DELETE FROM static_analysis_runs WHERE session_label=%s",
        ("sess-57",),
    ) in executed


def test_purge_static_session_artifacts_removes_session_archive_and_audits(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(reset_mod.app_config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(reset_mod.app_config, "OUTPUT_DIR", str(tmp_path / "output"))

    session_dir = tmp_path / "data" / "sessions" / "sess-1"
    archive_dir = tmp_path / "data" / "static_analysis" / "reports" / "archive" / "sess-1"
    audit_dir = tmp_path / "output" / "audit" / "persistence"
    select_dir = tmp_path / "output" / "audit" / "selection"
    legacy_evidence = tmp_path / "evidence" / "static_runs" / "11"
    output_evidence = tmp_path / "output" / "evidence" / "static_runs" / "11"
    for path in (session_dir, archive_dir, legacy_evidence, output_evidence, audit_dir, select_dir):
        path.mkdir(parents=True, exist_ok=True)
    (session_dir / "run_map.json").write_text("{}", encoding="utf-8")
    (archive_dir / "a.json").write_text("{}", encoding="utf-8")
    (audit_dir / "sess-1_persistence_audit.json").write_text("{}", encoding="utf-8")
    (audit_dir / "sess-1_reconcile_audit.json").write_text("{}", encoding="utf-8")
    (select_dir / "sess-1_selected_artifacts.json").write_text("{}", encoding="utf-8")
    (legacy_evidence / "static_handoff.json").write_text("{}", encoding="utf-8")
    (output_evidence / "static_handoff.json").write_text("{}", encoding="utf-8")

    class _FakeEngine:
        def fetch_all(self, sql, params=None, *_args, **_kwargs):
            if "SELECT id FROM static_analysis_runs" in sql:
                return [(11,)]
            return []

    @contextmanager
    def _fake_session(**_kwargs):
        yield _FakeEngine()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(reset_mod, "database_session", _fake_session)

    outcome = purge_static_session_artifacts("sess-1")

    assert not outcome.failed
    assert not session_dir.exists()
    assert not archive_dir.exists()
    assert not legacy_evidence.exists()
    assert not output_evidence.exists()
    assert any("sess-1_persistence_audit.json" in path for path in outcome.removed)
    assert any("sess-1_reconcile_audit.json" in path for path in outcome.removed)


def test_classify_static_session_type_marks_hidden_defaults():
    assert classify_static_session_type("qa-risk-facebook-rerun-2") == ("qa", True)
    assert classify_static_session_type("interrupt-smoke-4") == ("qa", True)
    assert classify_static_session_type("static-batch-v3-20260228T062654Z-com.facebook.katana") == ("qa", True)
    assert classify_static_session_type("masvs-facebook-fast-20260428") == ("fast", False)
    assert classify_static_session_type("20260429-all-full") == ("full", False)


def test_list_static_session_candidates_can_filter_hidden(monkeypatch):
    class _FakeEngine:
        def fetch_all(self, sql, params=None, *_args, **_kwargs):
            normalized = " ".join(str(sql).split())
            if "FROM static_analysis_runs sar" in normalized:
                return [
                    ("qa-risk-facebook-rerun-2", 1, 1, "2026-04-28 09:16:49"),
                    ("20260429-all-full", 120, 1, "2026-04-29 03:28:44"),
                ]
            if "FROM permission_audit_snapshots" in normalized:
                return [
                    ("perm-audit:app:qa-risk-facebook-rerun-2", 1, "2026-04-28 09:19:23"),
                    ("perm-audit:app:20260429-all-full", 120, "2026-04-29 03:34:39"),
                ]
            return []

    @contextmanager
    def _fake_session(**_kwargs):
        yield _FakeEngine()

    monkeypatch.setattr(reset_mod, "database_session", _fake_session)

    hidden = list_static_session_candidates(include_hidden_only=True)
    assert len(hidden) == 1
    assert hidden[0].session_label == "qa-risk-facebook-rerun-2"
    assert hidden[0].snapshot_apps_total == 1


def test_prune_static_sessions_calls_reset_and_artifact_purge(monkeypatch):
    seen_reset: list[str] = []
    seen_artifacts: list[str] = []

    monkeypatch.setattr(
        reset_mod,
        "reset_static_analysis_data",
        lambda **kwargs: (
            seen_reset.append(str(kwargs["session_label"])) or reset_mod.ResetOutcome([], ["static_analysis_runs"], [], [], [])
        ),
    )
    monkeypatch.setattr(
        reset_mod,
        "purge_static_session_artifacts",
        lambda session_label: (
            seen_artifacts.append(str(session_label))
            or reset_mod.ArtifactPurgeOutcome([f"/tmp/{session_label}"], [], [])
        ),
    )

    outcome = prune_static_sessions(["qa-risk-facebook-rerun-2", "qa-risk-facebook-rerun-2", ""])

    assert seen_reset == ["qa-risk-facebook-rerun-2"]
    assert seen_artifacts == ["qa-risk-facebook-rerun-2"]
    assert outcome.removed_sessions == ["qa-risk-facebook-rerun-2"]
    assert outcome.failed_sessions == []


def test_list_failed_static_session_candidates(monkeypatch):
    class _FakeEngine:
        def fetch_all(self, sql, params=None, *_args, **_kwargs):
            normalized = " ".join(str(sql).split())
            if "HAVING failed_runs > 0" in normalized:
                return [
                    ("20260427-sots-full", 1, 0, 0, "2026-04-27 22:20:32"),
                    ("20260219-1", 12, 0, 0, "2026-02-19 23:35:15"),
                ]
            return []

    @contextmanager
    def _fake_session(**_kwargs):
        yield _FakeEngine()

    monkeypatch.setattr(reset_mod, "database_session", _fake_session)

    rows = list_failed_static_session_candidates()
    assert [row.session_label for row in rows] == ["20260427-sots-full", "20260219-1"]
    assert rows[0].failed_runs == 1


def test_prune_failed_static_sessions(monkeypatch):
    monkeypatch.setattr(
        reset_mod,
        "list_failed_static_session_candidates",
        lambda older_than=None: [
            reset_mod.FailedStaticSessionCandidate("20260427-sots-full", 1, "2026-04-27 22:20:32"),
            reset_mod.FailedStaticSessionCandidate("20260219-1", 12, "2026-02-19 23:35:15"),
        ],
    )
    monkeypatch.setattr(
        reset_mod,
        "prune_static_sessions",
        lambda session_labels, purge_artifacts=True, include_harvest=False: reset_mod.SessionPruneOutcome(
            removed_sessions=list(session_labels),
            skipped_sessions=[],
            failed_sessions=[],
            removed_artifacts=[],
            missing_artifacts=[],
        ),
    )

    outcome = prune_failed_static_sessions()
    assert outcome.removed_sessions == ["20260427-sots-full", "20260219-1"]


def test_prune_completed_static_sessions_keeps_latest_and_protected(monkeypatch):
    monkeypatch.setattr(
        reset_mod,
        "list_static_session_candidates",
        lambda include_hidden_only=False, older_than=None: [
            reset_mod.StaticSessionCandidate("20260429-all-full", "2026-04-29 08:28:44", 120, 120, "full", False),
            reset_mod.StaticSessionCandidate("20260428-all-full", "2026-04-28 07:28:44", 120, 120, "full", False),
            reset_mod.StaticSessionCandidate("20260427-all-full", "2026-04-27 06:28:44", 120, 120, "full", False),
            reset_mod.StaticSessionCandidate("phase4a-closeout-smoke", "2026-04-26 05:28:44", 1, 1, "smoke", True),
            reset_mod.StaticSessionCandidate("20260426-rda-full", "2026-04-26 04:28:44", 12, 12, "full", False),
        ],
    )
    captured: dict[str, object] = {}

    def _prune(session_labels, purge_artifacts=True, include_harvest=False):
        captured["labels"] = list(session_labels)
        return reset_mod.SessionPruneOutcome(list(session_labels), [], [], [], [])

    monkeypatch.setattr(reset_mod, "prune_static_sessions", _prune)

    prune_completed_static_sessions(
        keep_latest=2,
        include_hidden=False,
        protected_sessions=["20260427-all-full"],
    )

    assert captured["labels"] == ["20260426-rda-full"]
