from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.core.models import RunParameters, ScopeSelection
from scytaledroid.StaticAnalysis.services import static_service


def test_run_scan_refreshes_summary_cache_after_success(monkeypatch, tmp_path: Path):
    params = RunParameters(
        profile="lightweight",
        scope="app",
        scope_label="Example | com.example.app",
        session_stamp="svc-cache-ok",
        session_label="svc-cache-ok",
        dry_run=False,
    )
    selection = ScopeSelection(scope="app", label="Example | com.example.app", groups=tuple())

    monkeypatch.setattr(static_service, "check_session_uniqueness", lambda *_a, **_k: None)
    monkeypatch.setattr(static_service, "build_static_run_spec", lambda **kwargs: SimpleNamespace(**kwargs))
    monkeypatch.setattr(
        static_service,
        "execute_run_spec_detailed",
        lambda spec: SimpleNamespace(
            outcome=None,
            params=replace(spec.params, session_stamp="svc-cache-ok", session_label="svc-cache-ok"),
            completed=True,
            detail=None,
        ),
    )
    result = static_service.run_scan(selection, params, tmp_path, allow_session_reuse=True)

    assert result.completed is True
    assert result.session_stamp == "svc-cache-ok"


def test_run_scan_returns_success_when_dispatch_completes(monkeypatch, tmp_path: Path):
    params = RunParameters(
        profile="lightweight",
        scope="app",
        scope_label="Example | com.example.app",
        session_stamp="svc-cache-warn",
        session_label="svc-cache-warn",
        dry_run=False,
    )
    selection = ScopeSelection(scope="app", label="Example | com.example.app", groups=tuple())

    monkeypatch.setattr(static_service, "check_session_uniqueness", lambda *_a, **_k: None)
    monkeypatch.setattr(static_service, "build_static_run_spec", lambda **kwargs: SimpleNamespace(**kwargs))
    monkeypatch.setattr(
        static_service,
        "execute_run_spec_detailed",
        lambda spec: SimpleNamespace(
            outcome=None,
            params=replace(spec.params, session_stamp="svc-cache-warn", session_label="svc-cache-warn"),
            completed=True,
            detail=None,
        ),
    )
    result = static_service.run_scan(selection, params, tmp_path, allow_session_reuse=True)

    assert result.completed is True
    assert result.session_label == "svc-cache-warn"
