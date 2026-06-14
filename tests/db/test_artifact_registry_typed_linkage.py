from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from scytaledroid.Database.db_queries import views_admin
from scytaledroid.Database.db_utils import artifact_registry as reg
from scytaledroid.Database.db_utils.artifact_registry_typed_linkage import (
    backfill_artifact_registry_typed_linkage,
)


def test_resolve_typed_linkage_static_numeric_prefers_typed_static() -> None:
    static_run_id, dynamic_run_id, status = reg.resolve_typed_linkage(
        run_id="123",
        run_type="static",
    )
    assert static_run_id == 123
    assert dynamic_run_id is None
    assert status == "typed_static_writer"


def test_resolve_typed_linkage_malformed_static_remains_legacy() -> None:
    static_run_id, dynamic_run_id, status = reg.resolve_typed_linkage(
        run_id="bad-run",
        run_type="static",
    )
    assert static_run_id is None
    assert dynamic_run_id is None
    assert status == "legacy_unclassified"


def test_resolve_typed_linkage_dynamic_backfills_dynamic_run_id() -> None:
    static_run_id, dynamic_run_id, status = reg.resolve_typed_linkage(
        run_id="dyn-123",
        run_type="dynamic",
    )
    assert static_run_id is None
    assert dynamic_run_id == "dyn-123"
    assert status == "typed_dynamic_writer"


def test_record_artifacts_populates_typed_columns(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_run_sql_many(query: str, rows: list[tuple[object, ...]], **_kwargs) -> None:
        captured["query"] = query
        captured["rows"] = rows

    monkeypatch.setattr(reg.core_q, "run_sql_many", fake_run_sql_many)
    artifact_path = tmp_path / "report.json"
    artifact_path.write_text("{}", encoding="utf-8")

    reg.record_artifacts(
        run_id="501",
        run_type="static",
        artifacts=[
            {
                "path": str(artifact_path),
                "type": "static_report",
                "created_at_utc": "2026-06-14T00:00:00Z",
            }
        ],
    )

    query = str(captured["query"])
    row = list(captured["rows"])[0]
    match = re.search(r"INSERT INTO artifact_registry\s*\((.*?)\)\s*VALUES", query, flags=re.IGNORECASE | re.DOTALL)
    assert match is not None
    columns = [part.strip() for part in match.group(1).replace("\n", " ").split(",")]
    row_by_column = dict(zip(columns, row, strict=True))
    assert "static_run_id" in query
    assert "dynamic_run_id" in query
    assert "dynamic_run_uuid" in query
    assert "linkage_migration_status" in query
    assert row_by_column["static_run_id"] == 501
    assert row_by_column["dynamic_run_id"] is None
    assert row_by_column["dynamic_run_uuid"] is None
    assert row_by_column["linkage_migration_status"] == "typed_static_writer"


def test_backfill_typed_linkage_uses_updates_only() -> None:
    queries: list[str] = []

    def fake_rowcount(query: str, *_args, **_kwargs) -> int:
        queries.append(query)
        return 1

    out = backfill_artifact_registry_typed_linkage(fake_rowcount, apply=True)
    assert out.applied is True
    assert out.static_rows_updated == 1
    assert out.dynamic_rows_updated == 1
    assert all("update artifact_registry" in q.lower() for q in queries)
    assert all("delete " not in q.lower() for q in queries)


def test_integrity_view_prefers_typed_joins_with_legacy_fallback() -> None:
    sql = views_admin.CREATE_V_ARTIFACT_REGISTRY_INTEGRITY.lower()
    assert "ar.static_run_id is not null" in sql
    assert "ar.static_run_id is null" in sql
    assert "ar.dynamic_run_id is not null" in sql
    assert "ar.dynamic_run_id is null" in sql
    assert "linkage_resolution_path" in sql
    assert "resolved_static_run_id" in sql
    assert "resolved_dynamic_run_id" in sql


def test_backfill_script_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "backfill_artifact_registry_typed_linkage.py"
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


def test_typed_linkage_audit_script_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "report_artifact_registry_typed_linkage_audit.py"
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
    assert "--json" in out
