from __future__ import annotations

from pathlib import Path

import pytest
from scytaledroid.StaticAnalysis.cli.core.models import AppRunResult
from scytaledroid.StaticAnalysis.cli.flows import run_dispatch
from tests.static_analysis._run_dispatch_support import (
    make_outcome,
    make_params,
    make_selection,
    patch_execute_run_spec_defaults,
    patch_launch_scan_flow_defaults,
    patch_static_run_lock,
)

pytestmark = [pytest.mark.contract, pytest.mark.report_contract]


@pytest.fixture(autouse=True)
def _disable_static_run_lock(monkeypatch):
    patch_static_run_lock(monkeypatch, Path("/tmp"))
    monkeypatch.setattr(run_dispatch, "_emit_db_preflight_lock_warning", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_emit_static_run_preflight_summary", lambda *_a, **_k: None)


def test_launch_scan_flow_builds_run_map_after_render_persistence(monkeypatch) -> None:
    outcome = make_outcome(
        results=[AppRunResult(package_name="com.example.app", category="Test", static_run_id=None)]
    )

    calls: dict[str, object] = {
        "missing_packages_seen": None,
        "run_map_built": False,
    }

    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)

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
    def _capture_missing(*, missing_id_packages, **_kwargs):
        calls["missing_packages_seen"] = list(missing_id_packages)

    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", _capture_missing)

    params = make_params(scope="all", scope_label="All apps", session_stamp="sess-1")
    selection = make_selection(scope="all", label="All apps")

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    assert calls["run_map_built"] is True
    assert calls["missing_packages_seen"] == []


def test_detect_duplicate_packages_normalizes_case() -> None:
    results = [
        AppRunResult(package_name="mnn.Android", category="Test"),
        AppRunResult(package_name="mnn.android", category="Test"),
    ]

    duplicates = run_dispatch._detect_duplicate_packages(results)

    assert duplicates == {"mnn.android"}


def test_resolve_unique_session_stamp_uses_db_attempts_without_local_run_map(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(run_dispatch.app_config, "DATA_DIR", str(tmp_path))

    from scytaledroid.Database.db_core import db_queries as core_q

    def _fake_run_sql(query, params=(), **_kwargs):
        if "SELECT DISTINCT COALESCE" in query:
            return [("20260217",)]
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

    assert stamp == "20260217-2"
    assert label == "20260217-2"
    assert action == "auto_suffix"


def test_resolve_unique_session_stamp_uses_next_numeric_suffix(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(run_dispatch.app_config, "DATA_DIR", str(tmp_path))

    from scytaledroid.Database.db_core import db_queries as core_q

    def _fake_run_sql(query, params=(), **_kwargs):
        if "SELECT DISTINCT COALESCE" in query:
            return [("20260217",), ("20260217-2",), ("20260217-3",)]
        if "SELECT COUNT(*)" in query:
            return (12,)
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
    outcome = make_outcome(
        results=[AppRunResult(package_name="com.example.app", category="Test", static_run_id=None)]
    )
    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)

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

    params = make_params(scope="all", scope_label="All apps", session_stamp="sess-1")
    selection = make_selection(scope="all", label="All apps")

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    assert sorted(set(captured_ids)) == [101, 102]


def test_launch_scan_flow_skips_run_map_and_permission_refresh_when_no_results(monkeypatch) -> None:
    outcome = make_outcome(scope="app", label="Example")
    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)

    calls = {"run_map": 0, "perm_refresh": 0, "blocked_reason": None}

    def _build_run_map(*_a, **_k):
        calls["run_map"] += 1
        return {}

    def _execute_permission_scan(*_a, **_k):
        calls["perm_refresh"] += 1

    def _emit_missing(*_a, **kwargs):
        calls["blocked_reason"] = kwargs.get("linkage_blocked_reason")

    monkeypatch.setattr(run_dispatch, "_build_session_run_map", _build_run_map)
    monkeypatch.setattr(run_dispatch, "execute_permission_scan", _execute_permission_scan)
    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", _emit_missing)

    params = make_params(scope="app", scope_label="Example", session_stamp="sess-empty", permission_snapshot_refresh=True)
    selection = make_selection(scope="app", label="Example")

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    assert calls["run_map"] == 0
    assert calls["perm_refresh"] == 0
    assert calls["blocked_reason"] == "No analyzable artifacts; skipping run_map and permission refresh."


def test_launch_scan_flow_aborted_skips_linkage_and_permission_refresh(monkeypatch) -> None:
    outcome = make_outcome(
        results=[AppRunResult(package_name="com.example.app", category="Test", static_run_id=777)],
        scope="app",
        label="Example",
        aborted=True,
        abort_reason="SIGINT",
        abort_signal="SIGINT",
    )

    calls = {"run_map": 0, "perm_refresh": 0, "blocked_reason": None, "footer": 0, "rollup": 0}
    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)
    monkeypatch.setattr(run_dispatch, "_render_persistence_footer", lambda *_a, **_k: calls.__setitem__("footer", calls["footer"] + 1))
    monkeypatch.setattr(run_dispatch, "_persist_cohort_rollup", lambda *_a, **_k: calls.__setitem__("rollup", calls["rollup"] + 1))

    monkeypatch.setattr(run_dispatch, "_build_session_run_map", lambda *_a, **_k: calls.__setitem__("run_map", calls["run_map"] + 1))
    monkeypatch.setattr(run_dispatch, "execute_permission_scan", lambda *_a, **_k: calls.__setitem__("perm_refresh", calls["perm_refresh"] + 1))

    def _emit_missing(*_a, **kwargs):
        calls["blocked_reason"] = kwargs.get("linkage_blocked_reason")

    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", _emit_missing)

    params = make_params(scope="app", scope_label="Example", session_stamp="sess-aborted", permission_snapshot_refresh=True)
    selection = make_selection(scope="app", label="Example")

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    assert calls["run_map"] == 0
    assert calls["perm_refresh"] == 0
    assert calls["blocked_reason"] == "Run interrupted; skipping run_map and permission refresh."
    assert calls["footer"] == 0
    assert calls["rollup"] == 0


def test_launch_scan_flow_records_render_failure_and_skips_follow_on_postprocessing(monkeypatch) -> None:
    class _SilentLogger:
        def exception(self, *_args, **_kwargs):
            return None

    outcome = make_outcome(
        results=[AppRunResult(package_name="com.example.app", category="Test", static_run_id=501)],
        scope="app",
        label="Example",
    )

    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)
    monkeypatch.setattr(run_dispatch.logging_engine, "get_error_logger", lambda: _SilentLogger())

    calls = {"run_map": 0, "perm_refresh": 0, "blocked_reason": None}

    def _raise_render(*_a, **_k):
        raise ValueError("bad summary payload")

    def _build_run_map(*_a, **_k):
        calls["run_map"] += 1
        return {}

    def _execute_permission_scan(*_a, **_k):
        calls["perm_refresh"] += 1

    def _emit_missing(*_a, **kwargs):
        calls["blocked_reason"] = kwargs.get("linkage_blocked_reason")

    monkeypatch.setattr(run_dispatch, "render_run_results", _raise_render)
    monkeypatch.setattr(run_dispatch, "_build_session_run_map", _build_run_map)
    monkeypatch.setattr(run_dispatch, "execute_permission_scan", _execute_permission_scan)
    monkeypatch.setattr(run_dispatch, "_emit_missing_run_ids_artifact", _emit_missing)

    params = make_params(scope="app", scope_label="Example", session_stamp="sess-render-fail", permission_snapshot_refresh=True)
    selection = make_selection(scope="app", label="Example")

    result = run_dispatch.launch_scan_flow(selection, params, Path("."))

    assert result is outcome
    assert "run_summary_render_failed:ValueError" in outcome.failures
    assert calls["run_map"] == 0
    assert calls["perm_refresh"] == 0
    assert calls["blocked_reason"] == "Run summary finalization failed; skipping run_map and permission refresh."


def test_launch_scan_flow_run_map_failure_raises_in_strict_mode(monkeypatch) -> None:
    outcome = make_outcome(
        results=[AppRunResult(package_name="com.example.app", category="Test", static_run_id=501)],
        scope="app",
        label="Example",
    )

    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)
    monkeypatch.setattr(run_dispatch, "_build_session_run_map", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")))

    params = make_params(
        scope="app",
        scope_label="Example",
        session_stamp="sess-strict",
        permission_snapshot_refresh=True,
        strict_persistence=True,
    )
    selection = make_selection(scope="app", label="Example")

    with pytest.raises(RuntimeError, match="Failed to build run map"):
        run_dispatch.launch_scan_flow(selection, params, Path("."))


def test_launch_scan_flow_passes_fail_on_persist_error_for_permission_refresh(monkeypatch) -> None:
    outcome = make_outcome(
        results=[AppRunResult(package_name="com.example.app", category="Test", static_run_id=777)],
        scope="app",
        label="Example",
    )

    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)
    monkeypatch.setattr(
        run_dispatch,
        "_build_session_run_map",
        lambda *_a, **_k: {
            "session_stamp": "sess-perm",
            "apps": [{"package": "com.example.app", "static_run_id": 777}],
            "by_package": {"com.example.app": {"static_run_id": 777}},
        },
    )
    monkeypatch.setattr(run_dispatch, "validate_run_map", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_persist_session_run_links", lambda *_a, **_k: None)

    seen: dict[str, object] = {}

    def _capture_permission_scan(*_a, **kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(run_dispatch, "execute_permission_scan", _capture_permission_scan)

    params = make_params(scope="app", scope_label="Example", session_stamp="sess-perm", permission_snapshot_refresh=True)
    selection = make_selection(scope="app", label="Example")

    run_dispatch.launch_scan_flow(selection, params, Path("."))
    assert seen.get("fail_on_persist_error") is True
    assert seen.get("compact_output") is True
    assert seen.get("silent_output") is True


def test_launch_scan_flow_defers_persistence_footer_until_after_permission_refresh(monkeypatch) -> None:
    outcome = make_outcome(
        results=[AppRunResult(package_name="com.example.app", category="Test", static_run_id=None)],
        scope="app",
        label="Example",
    )

    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)

    calls: list[tuple[str, object]] = []

    def _render_and_persist(_outcome, *_a, **kwargs):
        calls.append(("render", kwargs.get("defer_persistence_footer")))
        _outcome.results[0].static_run_id = 777
        _outcome.persistence_failed = False
        _outcome.audit_notes = [{"code": "canonical_error", "message": "canon gap"}]

    monkeypatch.setattr(run_dispatch, "render_run_results", _render_and_persist)
    monkeypatch.setattr(
        run_dispatch,
        "_build_session_run_map",
        lambda *_a, **_k: {
            "session_stamp": "sess-ordered",
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
        },
    )
    monkeypatch.setattr(run_dispatch, "validate_run_map", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "_persist_session_run_links", lambda *_a, **_k: None)
    monkeypatch.setattr(run_dispatch, "execute_permission_scan", lambda *_a, **_k: calls.append(("perm", None)))
    monkeypatch.setattr(
        run_dispatch.persistence_runtime,
        "refresh_session_views",
        lambda **_k: calls.append(("refresh", None)),
    )
    monkeypatch.setattr(
        run_dispatch,
        "_render_persistence_footer",
        lambda *_a, **kwargs: calls.append(("footer", kwargs)),
    )
    monkeypatch.setattr(
        run_dispatch,
        "_persist_cohort_rollup",
        lambda session_stamp, scope_label: calls.append(("rollup", (session_stamp, scope_label))),
    )

    params = make_params(scope="app", scope_label="Example", session_stamp="sess-ordered", permission_snapshot_refresh=True)
    selection = make_selection(scope="app", label="Example")

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    assert calls[0] == ("render", True)
    assert [name for name, _ in calls[-4:]] == ["perm", "refresh", "footer", "rollup"]
    footer_kwargs = calls[-2][1]
    assert isinstance(footer_kwargs, dict)
    assert footer_kwargs.get("had_errors") is False
    assert footer_kwargs.get("canonical_failures") == ["canon gap"]
    assert calls[-1][1] == ("sess-ordered", "Example")


def test_launch_scan_flow_return_to_main_menu_still_runs_required_postprocessing(monkeypatch) -> None:
    outcome = make_outcome(
        results=[AppRunResult(package_name="com.example.app", category="Test", static_run_id=777)],
        scope="app",
        label="Example",
    )

    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)
    monkeypatch.setattr(
        run_dispatch.persistence_runtime,
        "refresh_session_views",
        lambda **_k: None,
    )

    calls = {"run_map": 0, "perm_refresh": 0, "footer": 0}

    def _render_and_return(_outcome, *_a, **_k):
        _outcome.return_to_main_menu = True

    monkeypatch.setattr(run_dispatch, "render_run_results", _render_and_return)
    monkeypatch.setattr(
        run_dispatch,
        "run_post_summary_postprocessing",
        lambda **_k: calls.__setitem__("run_map", calls["run_map"] + 1)
        or calls.__setitem__("perm_refresh", calls["perm_refresh"] + 1)
        or type("PostSummary", (), {"permission_refresh_error": None, "linkage_blocked_reason": None, "run_map_built": True})(),
    )
    monkeypatch.setattr(
        run_dispatch,
        "_render_persistence_footer",
        lambda *_a, **_k: calls.__setitem__("footer", calls["footer"] + 1),
    )

    params = make_params(scope="app", scope_label="Example", session_stamp="sess-return", permission_snapshot_refresh=True)
    selection = make_selection(scope="app", label="Example")

    run_dispatch.launch_scan_flow(selection, params, Path("."))

    assert calls == {"run_map": 1, "perm_refresh": 1, "footer": 1}


def test_execute_run_spec_detailed_refreshes_summary_cache_after_success(monkeypatch, tmp_path) -> None:
    params = make_params(
        profile="lightweight",
        scope="app",
        scope_label="com.example.app",
        session_stamp="dispatch-cache-ok",
        session_label="dispatch-cache-ok",
    )
    spec = run_dispatch.StaticRunSpec(
        selection=make_selection(scope="app", label="com.example.app"),
        params=params,
        base_dir=tmp_path,
        run_mode="batch",
        quiet=True,
        noninteractive=True,
    )

    patch_execute_run_spec_defaults(monkeypatch, params=params, launch_result=object())

    calls: list[bool] = []
    monkeypatch.setattr(
        run_dispatch,
        "refresh_static_dynamic_summary_cache",
        lambda: (calls.append(True) or (547, "2026-04-28 06:30:00")),
    )

    result = run_dispatch.execute_run_spec_detailed(spec)

    assert result.completed is True
    assert calls == [True]


def test_execute_run_spec_detailed_ignores_summary_cache_refresh_failure(monkeypatch, tmp_path) -> None:
    params = make_params(
        profile="lightweight",
        scope="app",
        scope_label="com.example.app",
        session_stamp="dispatch-cache-warn",
        session_label="dispatch-cache-warn",
    )
    spec = run_dispatch.StaticRunSpec(
        selection=make_selection(scope="app", label="com.example.app"),
        params=params,
        base_dir=tmp_path,
        run_mode="batch",
        quiet=True,
        noninteractive=True,
    )

    patch_execute_run_spec_defaults(monkeypatch, params=params, launch_result=object())

    warnings: list[str] = []
    monkeypatch.setattr(
        run_dispatch,
        "refresh_static_dynamic_summary_cache",
        lambda: (_ for _ in ()).throw(RuntimeError("cache boom")),
    )
    monkeypatch.setattr(run_dispatch.log, "warning", lambda message, **_k: warnings.append(str(message)))

    result = run_dispatch.execute_run_spec_detailed(spec)

    assert result.completed is True
    assert any("summary cache refresh failed" in message for message in warnings)
