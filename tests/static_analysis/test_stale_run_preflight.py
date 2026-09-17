"""Known-answer coverage for the fail-closed unresolved static-run interlock."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest
from scytaledroid.StaticAnalysis.cli.execution import scan_flow
from scytaledroid.StaticAnalysis.cli.flows import run_dispatch
from scytaledroid.StaticAnalysis.cli.persistence import run_writers
from scytaledroid.StaticAnalysis.cli.persistence.run_writers import (
    OpenStaticRun,
    OpenStaticRunsInspection,
)
from tests.static_analysis._run_dispatch_support import (
    make_outcome,
    make_params,
    make_selection,
    patch_launch_scan_flow_defaults,
    patch_static_run_lock,
)


@pytest.fixture(autouse=True)
def _bypass_session_collision_resolution(monkeypatch):
    monkeypatch.setattr(run_dispatch, "_resolve_unique_session_stamp", lambda stamp, **_k: (stamp, stamp, "first_run"))


def _open_runs() -> OpenStaticRunsInspection:
    return OpenStaticRunsInspection(
        runs=(
            OpenStaticRun(
                static_run_id=41,
                session_stamp="historical-session",
                static_session_id=7,
                started_at_utc="2026-09-17 15:40:45",
                status="STARTED",
                package_name="com.example.historical",
                build_identity="a" * 64,
            ),
        )
    )


def test_inspect_open_static_runs_is_select_only(monkeypatch: pytest.MonkeyPatch) -> None:
    queries: list[str] = []

    def _run_sql(query: str, _params: tuple[object, ...], *, fetch: str):
        queries.append(query)
        assert fetch == "all"
        return [
            (
                41,
                "historical-session",
                7,
                "2026-09-17 15:40:45",
                "STARTED",
                "com.example.historical",
                "a" * 64,
            )
        ]

    monkeypatch.setattr(run_writers.core_q, "run_sql", _run_sql)

    inspection = run_writers.inspect_open_static_runs()

    assert inspection.count == 1
    assert inspection.run_ids == (41,)
    assert inspection.session_stamps == ("historical-session",)
    assert inspection.oldest_started_at_utc == "2026-09-17 15:40:45"
    assert inspection.newest_started_at_utc == "2026-09-17 15:40:45"
    assert inspection.runs[0].package_name == "com.example.historical"
    assert queries and all("SELECT" in query.upper() for query in queries)
    assert all(token not in " ".join(queries).upper() for token in ("UPDATE", "DELETE", "INSERT"))


def test_open_rows_block_before_persistent_startup_writes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    patch_static_run_lock(monkeypatch, tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok", ""))
    monkeypatch.setattr(run_dispatch, "inspect_open_static_runs", _open_runs)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "bootstrap_runtime_persistence", lambda **_k: calls.append("bootstrap"))
    monkeypatch.setattr(run_dispatch, "_emit_selection_manifest", lambda *_a, **_k: calls.append("selection_manifest"))
    monkeypatch.setattr(run_dispatch, "_write_execution_marker", lambda *_a, **_k: calls.append("execution_marker"))
    monkeypatch.setattr(run_dispatch, "execute_scan", lambda *_a, **_k: calls.append("scan"))

    outcome = run_dispatch.launch_scan_flow(
        make_selection(),
        make_params(session_stamp="new-session"),
        Path("."),
    )

    assert outcome is None
    assert calls == []
    output = capsys.readouterr().out
    assert "count=1" in output
    assert "historical-session" in output
    assert "Explicit reconciliation is required" in output


def test_clean_open_run_preflight_reaches_next_lifecycle_step(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    patch_static_run_lock(monkeypatch, tmp_path)
    outcome = make_outcome()
    calls: list[str] = []
    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome)
    monkeypatch.setattr(run_dispatch, "inspect_open_static_runs", lambda: OpenStaticRunsInspection(runs=tuple()))
    monkeypatch.setattr(run_dispatch, "execute_scan", lambda *_a, **_k: calls.append("scan") or outcome)

    actual = run_dispatch.launch_scan_flow(make_selection(), make_params(), Path("."))

    assert actual is outcome
    assert calls == ["scan"]


def test_preflight_failure_blocks_persistent_startup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    patch_static_run_lock(monkeypatch, tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(run_dispatch, "_check_static_persistence_readiness", lambda *_a, **_k: (True, "ok", ""))
    monkeypatch.setattr(
        run_dispatch,
        "inspect_open_static_runs",
        lambda: (_ for _ in ()).throw(RuntimeError("database unavailable")),
    )
    monkeypatch.setattr(run_dispatch.persistence_runtime, "bootstrap_runtime_persistence", lambda **_k: calls.append("bootstrap"))
    monkeypatch.setattr(run_dispatch, "execute_scan", lambda *_a, **_k: calls.append("scan"))

    outcome = run_dispatch.launch_scan_flow(make_selection(), make_params(), Path("."))

    assert outcome is None
    assert calls == []
    assert "preflight failed" in capsys.readouterr().out


def test_dry_run_warns_but_keeps_database_write_free(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys) -> None:
    patch_static_run_lock(monkeypatch, tmp_path)
    outcome = make_outcome()
    calls: list[str] = []
    patch_launch_scan_flow_defaults(monkeypatch, outcome=outcome, persistence_enabled=False)
    monkeypatch.setattr(run_dispatch, "inspect_open_static_runs", _open_runs)
    monkeypatch.setattr(run_dispatch.persistence_runtime, "bootstrap_runtime_persistence", lambda **_k: calls.append("bootstrap"))
    monkeypatch.setattr(run_dispatch.persistence_runtime, "refresh_session_views", lambda **_k: calls.append("refresh"))
    monkeypatch.setattr(run_dispatch, "execute_scan", lambda *_a, **_k: calls.append("scan") or outcome)

    actual = run_dispatch.launch_scan_flow(
        make_selection(),
        make_params(session_stamp="dry-session", dry_run=True),
        Path("."),
    )

    assert actual is outcome
    assert calls == ["scan"]
    assert "Dry run continues database-write-free" in capsys.readouterr().out


def test_permission_profile_dry_run_is_blocked_before_write_capable_workflow(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys,
) -> None:
    patch_static_run_lock(monkeypatch, tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(
        run_dispatch,
        "_check_static_persistence_readiness",
        lambda *_a, **_k: (True, "ok", ""),
    )
    monkeypatch.setattr(
        run_dispatch,
        "inspect_open_static_runs",
        lambda: calls.append("open-run-inspection") or OpenStaticRunsInspection(runs=tuple()),
    )
    monkeypatch.setattr(
        run_dispatch,
        "execute_permission_scan",
        lambda *_a, **_k: calls.append("permission-scan"),
    )
    monkeypatch.setattr(
        run_dispatch.persistence_runtime,
        "bootstrap_runtime_persistence",
        lambda **_k: calls.append("bootstrap"),
    )

    outcome = run_dispatch.launch_scan_flow(
        make_selection(),
        make_params(profile="permissions", session_stamp="permission-dry", dry_run=True),
        Path("."),
    )

    assert outcome is None
    assert calls == []
    assert "Permission-profile dry run is blocked" in capsys.readouterr().out


def test_normal_startup_has_no_global_finalization_call() -> None:
    source = inspect.getsource(scan_flow)

    assert "finalize_open_static_runs" not in source
