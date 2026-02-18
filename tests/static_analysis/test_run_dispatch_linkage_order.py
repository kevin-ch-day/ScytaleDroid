from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult, RunOutcome, RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.cli.flows import run_dispatch


def test_launch_scan_flow_builds_run_map_after_render_persistence(monkeypatch) -> None:
    now = datetime.now(UTC)
    result = AppRunResult(package_name="com.example.app", category="Test", static_run_id=None)
    outcome = RunOutcome(
        results=[result],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        base_dir=Path("."),
    )

    calls: dict[str, object] = {
        "missing_packages_seen": None,
        "run_map_built": False,
    }

    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok"))
    monkeypatch.setattr(run_dispatch.canonical_ingest, "ensure_provider_plumbing", lambda: None)
    monkeypatch.setattr(run_dispatch.canonical_ingest, "build_session_string_view", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "execute_scan", lambda *_a, **_k: outcome)

    def _render_and_persist(_outcome, *_a, **_k):
        # Simulate persist_run_summary assigning static_run_id during render.
        _outcome.results[0].static_run_id = 777

    monkeypatch.setattr(run_dispatch, "render_run_results", _render_and_persist)

    def _build_run_map(_outcome, *_a, **_k):
        calls["run_map_built"] = True
        return {
            "session_stamp": "sess-1",
            "apps": [
                {
                    "package": "com.example.app",
                    "static_run_id": 777,
                    "pipeline_version": "2.0.0-alpha",
                    "run_signature": "sig",
                    "run_signature_version": "v1",
                    "base_apk_sha256": "aa" * 32,
                    "artifact_set_hash": "bb" * 32,
                }
            ],
            "by_package": {"com.example.app": {"static_run_id": 777}},
        }

    monkeypatch.setattr(run_dispatch, "_build_session_run_map", _build_run_map)
    monkeypatch.setattr(run_dispatch, "validate_run_map", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_persist_session_run_links", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "execute_permission_scan", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "finalize_open_runs", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_selection_manifest", lambda *_a, **_k: None)

    def _capture_missing(*, missing_id_packages, **_kwargs):
        calls["missing_packages_seen"] = list(missing_id_packages)

    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", _capture_missing)

    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="sess-1",
        dry_run=False,
        persistence_ready=True,
        permission_snapshot_refresh=False,
        paper_grade_requested=False,
    )
    selection = ScopeSelection(scope="all", label="All apps", groups=tuple())

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    assert calls["run_map_built"] is True
    assert calls["missing_packages_seen"] == []


def test_resolve_unique_session_stamp_uses_db_attempts_without_local_run_map(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(run_dispatch.app_config, "DATA_DIR", str(tmp_path))

    from scytaledroid.Database.db_core import db_queries as core_q

    def _fake_run_sql(query, params=(), **_kwargs):
        if "SELECT COUNT(*)" in query:
            return (3,)
        if "SELECT id" in query:
            return None
        raise AssertionError(f"Unexpected query: {query}")

    monkeypatch.setattr(core_q, "run_sql", _fake_run_sql)

    stamp, label, action = run_dispatch._resolve_unique_session_stamp(
        "20260217",
        run_mode="interactive",
        noninteractive=False,
        quiet=True,
        canonical_action=None,
    )

    assert stamp == "20260217-4"
    assert label == "20260217-4"
    assert action == "auto_suffix"


def test_resolve_unique_session_stamp_first_run_when_db_and_local_absent(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(run_dispatch.app_config, "DATA_DIR", str(tmp_path))

    from scytaledroid.Database.db_core import db_queries as core_q

    def _fake_run_sql(query, params=(), **_kwargs):
        if "SELECT COUNT(*)" in query:
            return (0,)
        if "SELECT id" in query:
            return None
        raise AssertionError(f"Unexpected query: {query}")

    monkeypatch.setattr(core_q, "run_sql", _fake_run_sql)

    stamp, label, action = run_dispatch._resolve_unique_session_stamp(
        "20260217",
        run_mode="interactive",
        noninteractive=False,
        quiet=True,
        canonical_action=None,
    )

    assert stamp == "20260217"
    assert label == "20260217"
    assert action == "first_run"


def test_launch_scan_flow_finalizes_lingering_started_rows_for_session(monkeypatch) -> None:
    now = datetime.now(UTC)
    result = AppRunResult(package_name="com.example.app", category="Test", static_run_id=None)
    outcome = RunOutcome(
        results=[result],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        base_dir=Path("."),
    )

    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok"))
    monkeypatch.setattr(run_dispatch.canonical_ingest, "ensure_provider_plumbing", lambda: None)
    monkeypatch.setattr(run_dispatch.canonical_ingest, "build_session_string_view", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "execute_scan", lambda *_a, **_k: outcome)
    monkeypatch.setattr(run_dispatch, "render_run_results", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_selection_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_build_session_run_map", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "execute_permission_scan", lambda *_a, **_k: None)

    captured_ids: list[int] = []

    def _capture_finalize(ids, **_kwargs):
        captured_ids.extend(list(ids))

    monkeypatch.setattr(run_dispatch, "finalize_open_runs", _capture_finalize)

    from scytaledroid.Database.db_core import db_queries as core_q

    def _fake_run_sql(query, params=(), fetch="none", **_kwargs):
        if "SELECT id" in query and "status='STARTED'" in query:
            return [(101,), (102,)]
        if "SELECT COUNT(*)" in query:
            return (0,)
        return []

    monkeypatch.setattr(core_q, "run_sql", _fake_run_sql)

    params = RunParameters(
        profile="full",
        scope="all",
        scope_label="All apps",
        session_stamp="sess-1",
        dry_run=False,
        persistence_ready=True,
        permission_snapshot_refresh=False,
        paper_grade_requested=False,
    )
    selection = ScopeSelection(scope="all", label="All apps", groups=tuple())

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    assert sorted(set(captured_ids)) == [101, 102]
