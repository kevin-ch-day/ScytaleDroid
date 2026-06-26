from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scytaledroid.Database.db_utils.artifact_registry_session_stamp import (
    backfill_artifact_registry_session_stamp,
)


def test_backfill_session_stamp_read_only_reports_planned_updates() -> None:
    def fake_run_sql(sql: str, params=(), **kwargs):
        del params, kwargs
        if "information_schema.columns" in sql:
            return {"n": 0}
        return {
            "total_rows": 10,
            "static_rows": 8,
            "dynamic_rows": 2,
            "rows_with_session_stamp": 1,
            "static_rows_with_session_stamp": 1,
            "typed_static_rows_missing_session_stamp": 4,
            "typed_static_rows_joinable": 4,
            "legacy_static_rows_missing_session_stamp": 3,
            "legacy_static_rows_joinable": 3,
            "dynamic_rows_with_session_stamp": 0,
        }

    def fake_run_sql_rowcount(sql: str, params=(), **kwargs) -> int:
        raise AssertionError(f"read-only mode should not execute UPDATE: {sql} {params} {kwargs}")

    result = backfill_artifact_registry_session_stamp(
        fake_run_sql,
        fake_run_sql_rowcount,
        apply=False,
    )

    assert result.applied is False
    assert result.ddl_applied is False
    assert result.typed_static_rows_updated == 4
    assert result.legacy_static_rows_updated == 3
    assert result.rows_with_session_stamp_before == 1
    assert result.rows_with_session_stamp_after == 8


def test_backfill_session_stamp_apply_uses_update_only() -> None:
    queries: list[str] = []
    audit_rows = iter(
        (
            {
                "total_rows": 12,
                "static_rows": 10,
                "dynamic_rows": 2,
                "rows_with_session_stamp": 2,
                "static_rows_with_session_stamp": 2,
                "typed_static_rows_missing_session_stamp": 5,
                "typed_static_rows_joinable": 5,
                "legacy_static_rows_missing_session_stamp": 3,
                "legacy_static_rows_joinable": 3,
                "dynamic_rows_with_session_stamp": 0,
            },
            {
                "total_rows": 12,
                "static_rows": 10,
                "dynamic_rows": 2,
                "rows_with_session_stamp": 10,
                "static_rows_with_session_stamp": 10,
                "typed_static_rows_missing_session_stamp": 0,
                "typed_static_rows_joinable": 0,
                "legacy_static_rows_missing_session_stamp": 0,
                "legacy_static_rows_joinable": 0,
                "dynamic_rows_with_session_stamp": 0,
            },
        )
    )

    def fake_run_sql(sql: str, params=(), **kwargs):
        queries.append(sql)
        if "FROM schema_migrations" in sql:
            return None
        if "information_schema.columns" in sql:
            return {"n": 1}
        if "FROM artifact_registry" in sql and "rows_with_session_stamp" in sql:
            return next(audit_rows)
        return None

    def fake_run_sql_rowcount(sql: str, params=(), **kwargs) -> int:
        queries.append(sql)
        lowered = sql.lower()
        assert "update artifact_registry" in lowered
        assert "delete " not in lowered
        if "ar.static_run_id is not null" in lowered:
            return 5
        return 3

    result = backfill_artifact_registry_session_stamp(
        fake_run_sql,
        fake_run_sql_rowcount,
        apply=True,
    )

    assert result.applied is True
    assert result.typed_static_rows_updated == 5
    assert result.legacy_static_rows_updated == 3
    assert any("alter table artifact_registry" in query.lower() for query in queries)
    assert any("update artifact_registry ar" in query.lower() for query in queries)


def test_backfill_session_stamp_script_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "backfill_artifact_registry_session_stamp.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = (proc.stdout or proc.stderr).strip().lower()
    assert out.startswith("usage:")
    assert "--apply" in out
    assert "--json" in out
