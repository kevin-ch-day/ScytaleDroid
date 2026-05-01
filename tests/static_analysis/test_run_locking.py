from __future__ import annotations

import json
import os
import sys

import pytest

from scytaledroid.Config import app_config
from scytaledroid.StaticAnalysis.cli.core.models import RunParameters
from scytaledroid.StaticAnalysis.cli.flows import run_locking


@pytest.fixture
def params() -> RunParameters:
    return RunParameters(
        profile="full",
        scope="profile",
        scope_label="Test",
        session_stamp="20990101-lock-test",
        session_label="20990101-lock-test",
        execution_id="test-exec",
    )


@pytest.mark.skipif(sys.platform.startswith("win"), reason="stale lock reclaim uses Unix PID liveness")
def test_acquire_reclaims_stale_lock_when_pid_dead(
    monkeypatch, tmp_path, params: RunParameters, capsys,
) -> None:
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path))
    lock_path = tmp_path / "locks" / "static_analysis.lock"
    lock_path.parent.mkdir(parents=True)
    lock_path.write_text(
        json.dumps(
            {
                "pid": 9_999_001,
                "session_label": "older-session",
                "session_stamp": "older-stamp",
                "execution_id": "old",
            }
        ),
        encoding="utf-8",
    )

    acquired = run_locking._acquire_static_run_lock(params)
    assert acquired.resolve() == lock_path.resolve()

    data = json.loads(lock_path.read_text(encoding="utf-8"))
    assert data["session_stamp"] == params.session_stamp
    assert data["pid"] == os.getpid()

    cap = capsys.readouterr()
    assert "Stale static-analysis lock removed" in cap.out + cap.err


@pytest.mark.skipif(sys.platform.startswith("win"), reason="stale lock reclaim uses Unix PID liveness")
def test_acquire_reclaims_corrupt_lock(monkeypatch, tmp_path, params: RunParameters) -> None:
    monkeypatch.setattr(app_config, "DATA_DIR", str(tmp_path))
    lock_path = tmp_path / "locks" / "static_analysis.lock"
    lock_path.parent.mkdir(parents=True)
    lock_path.write_text("not-json", encoding="utf-8")

    run_locking._acquire_static_run_lock(params)
    data = json.loads(lock_path.read_text(encoding="utf-8"))
    assert data["session_stamp"] == params.session_stamp
