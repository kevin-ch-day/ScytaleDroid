"""Tests for Phase 1 session ``evidence_manifest.json`` (best-effort)."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from scytaledroid.Config import app_config
from scytaledroid.StaticAnalysis.cli.core.models import (
    AppRunResult,
    ArtifactOutcome,
    RunOutcome,
    ScopeSelection,
)
from scytaledroid.StaticAnalysis.cli.persistence import evidence_manifest_writer as emw


def _outcome_with_report(tmp_path: Path, *, pkg: str = "com.example.app", sid: int = 42) -> RunOutcome:
    now = datetime.now(UTC)
    report = SimpleNamespace(
        manifest=SimpleNamespace(app_label="Ex", package_name=pkg),
        exported_components=SimpleNamespace(providers=[]),
        detector_results=[],
        file_path="/tmp/x.apk",
        metadata={"duration_seconds": 0.1},
    )
    rp = tmp_path / "detector.json"
    rp.write_text('{"ok": true}', encoding="utf-8")
    artifact = ArtifactOutcome(
        label="base.apk",
        report=report,
        severity=Counter(),
        duration_seconds=0.1,
        saved_path=str(rp),
        started_at=now,
        finished_at=now,
        metadata={},
    )
    return RunOutcome(
        results=[
            AppRunResult(
                package_name=pkg,
                category="Test",
                artifacts=[artifact],
                static_run_id=sid,
            )
        ],
        started_at=now,
        finished_at=now,
        scope=ScopeSelection(scope="all", label="All apps", groups=tuple()),
        base_dir=tmp_path,
    )


def test_build_session_evidence_manifest_payload_core_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path))
    stamp = "sess-evidence-1"
    session_dir = tmp_path / "sessions" / stamp
    session_dir.mkdir(parents=True)
    (session_dir / "run_map.json").write_text('{"session_stamp":"sess-evidence-1"}', encoding="utf-8")

    monkeypatch.setattr(emw, "_fetch_handoff_by_run_id", lambda _ids: {})
    monkeypatch.setattr(emw.db_diagnostics, "get_schema_version", lambda: "schema-test")
    monkeypatch.setattr(emw, "get_git_commit", lambda: "abc1234")
    monkeypatch.setattr(emw, "_safe_db_catalog", lambda: "testdb")

    run_map = {
        "session_stamp": stamp,
        "apps": [{"package": "com.example.app", "static_run_id": 42}],
    }
    outcome = _outcome_with_report(tmp_path)
    payload = emw.build_session_evidence_manifest_payload(
        session_stamp=stamp,
        session_label="label-1",
        run_map=run_map,
        outcome=outcome,
    )

    assert payload["manifest_schema_version"] == "1"
    assert payload["manifest_scope"] == "session"
    assert payload["session_stamp"] == stamp
    assert payload["session_label"] == "label-1"
    assert payload["static_run_id"] == 42
    assert payload["static_run_ids"] == [42]
    assert payload["db_catalog"] == "testdb"
    assert payload["schema_version"] == "schema-test"
    assert payload["git_commit"] == "abc1234"
    assert "environment_fingerprint" in payload
    roles = {a.get("role") for a in payload["canonical_artifacts"]}
    assert "run_map" in roles
    assert "detector_report" in roles
    det_runs = payload["detector_report"]["runs"]
    assert len(det_runs) == 1
    assert det_runs[0]["package_name"] == "com.example.app"
    assert det_runs[0]["static_run_id"] == 42
    assert det_runs[0].get("sha256")


def test_write_session_evidence_manifest_respects_disable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SCYTALEDROID_EVIDENCE_MANIFEST", "0")
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path))
    out = emw.write_session_evidence_manifest_phase1(
        session_stamp="s1",
        session_label=None,
        run_map={"apps": []},
        outcome=_outcome_with_report(tmp_path),
    )
    assert out is None


def test_build_id_picked_from_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GITHUB_SHA", "deadbeefcafe")
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path))
    stamp = "sess-buildid"
    session_dir = tmp_path / "sessions" / stamp
    session_dir.mkdir(parents=True)
    (session_dir / "run_map.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(emw, "_fetch_handoff_by_run_id", lambda _ids: {})
    monkeypatch.setattr(emw.db_diagnostics, "get_schema_version", lambda: "x")
    monkeypatch.setattr(emw, "get_git_commit", lambda: "abc")
    payload = emw.build_session_evidence_manifest_payload(
        session_stamp=stamp,
        session_label=None,
        run_map={"session_stamp": stamp, "apps": [{"package": "com.example.app", "static_run_id": 1}]},
        outcome=_outcome_with_report(tmp_path, sid=1),
    )
    assert payload.get("build_id") == "deadbeefcafe"


def test_write_session_evidence_manifest_writes_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("SCYTALEDROID_EVIDENCE_MANIFEST", raising=False)
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path))
    stamp = "sess-write-1"
    session_dir = tmp_path / "sessions" / stamp
    session_dir.mkdir(parents=True)
    (session_dir / "run_map.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(emw, "_fetch_handoff_by_run_id", lambda _ids: {})
    monkeypatch.setattr(emw.db_diagnostics, "get_schema_version", lambda: "x")
    monkeypatch.setattr(emw, "get_git_commit", lambda: "deadbeef")

    path = emw.write_session_evidence_manifest_phase1(
        session_stamp=stamp,
        session_label=None,
        run_map={"session_stamp": stamp, "apps": [{"package": "com.example.app", "static_run_id": 1}]},
        outcome=_outcome_with_report(tmp_path, sid=1),
    )
    assert path is not None
    assert path.name == "evidence_manifest.json"
    data = path.read_text(encoding="utf-8")
    assert "manifest_schema_version" in data
