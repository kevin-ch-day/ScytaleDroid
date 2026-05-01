from __future__ import annotations

import pytest

from scytaledroid.Database.db_core import db_engine
from scytaledroid.Persistence import db_writer
from scytaledroid.StaticAnalysis.cli.persistence import run_writers


def test_write_buckets_raises_transient_db_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(db_writer, "_has_column", lambda *_args, **_kwargs: False)

    def _boom(*_args, **_kwargs):
        raise RuntimeError("Lost connection to MySQL server during query (2013)")

    monkeypatch.setattr(db_writer.core_q, "run_sql", _boom)

    with pytest.raises(db_engine.TransientDbError):
        db_writer.write_buckets(1, {"permissions": (1.0, 20.0)}, static_run_id=1)


def test_create_static_run_rethrows_transient_db_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_args, **_kwargs):
        raise RuntimeError("Lost connection to MySQL server during query (2013)")

    monkeypatch.setattr(run_writers.core_q, "run_sql", _boom)

    with pytest.raises(db_engine.TransientDbError):
        run_writers._create_static_run(
            app_version_id=1,
            session_stamp="20260217",
            session_label="20260217",
            scope_label="All apps",
            category=None,
            profile="Full",
            profile_key="Full",
            scenario_id="static_default",
            device_serial=None,
            tool_semver="2.0.1",
            tool_git_commit=None,
            schema_version="0.2.6",
            findings_total=0,
            run_started_utc=None,
            status="STARTED",
        )
