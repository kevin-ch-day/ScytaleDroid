"""The scan path must call the real public ledger wrapper, not only the writer."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.execution import scan_flow
from scytaledroid.StaticAnalysis.cli.persistence import run_summary
from scytaledroid.StaticAnalysis.cli.persistence.run_summary import create_static_run_ledger


def _create_static_run_ledger_keywords(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "create_static_run_ledger":
            names.update(keyword.arg for keyword in node.keywords if keyword.arg)
    return names


def test_scan_flow_ledger_kwargs_are_accepted_by_the_real_wrapper() -> None:
    kwargs = _create_static_run_ledger_keywords(Path(scan_flow.__file__))
    assert "artifact_set_hash_version" in kwargs
    signature = inspect.signature(create_static_run_ledger)
    accepted = {
        name
        for name, parameter in signature.parameters.items()
        if parameter.kind in (parameter.KEYWORD_ONLY, parameter.POSITIONAL_OR_KEYWORD)
    }
    unexpected = sorted(kwargs - accepted)
    assert not unexpected, unexpected


def test_wrapper_forwards_artifact_set_hash_version_to_writer(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _capture(**kwargs):
        captured.update(kwargs)
        return 42

    monkeypatch.setattr(run_summary, "get_git_commit", lambda: "deadbeef")
    monkeypatch.setattr(
        run_summary,
        "db_diagnostics",
        SimpleNamespace(get_schema_version=lambda: "0.3.16"),
    )
    monkeypatch.setattr(run_summary._run_writers, "create_static_run_ledger", _capture)

    run_id = create_static_run_ledger(
        package_name="com.example.app",
        session_stamp="20260918T000000Z",
        session_label="lab",
        scope_label="all",
        profile="full",
        sha256="a" * 64,
        base_apk_sha256="a" * 64,
        artifact_set_hash="b" * 64,
        artifact_set_hash_version="v1",
        apk_set_id=12,
        identity_valid=True,
        static_session_id=3,
    )

    assert run_id == 42
    assert captured["artifact_set_hash_version"] == "v1"
    assert captured["artifact_set_hash"] == "b" * 64
    assert captured["apk_set_id"] == 12
