from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.StaticAnalysis.cli.persistence import dep_export


def test_replace_existing_dep_snapshot_registry_rows_uses_scoped_delete(
    monkeypatch,
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, tuple[object, ...], str | None]] = []
    dep_path = tmp_path / "dep.json"
    dep_path.write_text("{}", encoding="utf-8")

    def fake_run_sql_rowcount(sql: str, params=(), *, query_name=None, **_kwargs) -> int:
        calls.append((sql, tuple(params), query_name))
        return 2

    monkeypatch.setattr(dep_export.core_q, "run_sql_rowcount", fake_run_sql_rowcount)

    deleted = dep_export._replace_existing_dep_snapshot_registry_rows(321, dep_path)

    assert deleted == 2
    assert calls
    sql, params, query_name = calls[0]
    assert "DELETE FROM artifact_registry" in sql
    assert "artifact_type = 'dep_snapshot'" in sql
    assert params == (str(dep_path.resolve()), 321, "321")
    assert query_name == "artifact_registry.replace_static_dep_snapshot"


def test_upsert_artifact_entry_replaces_existing_type_and_path() -> None:
    original = [
        {"path": "/tmp/one.json", "type": "static_report", "sha256": "a"},
        {"path": "/tmp/dep.json", "type": "dep_snapshot", "sha256": "old"},
    ]
    replacement = {"path": "/tmp/dep.json", "type": "dep_snapshot", "sha256": "new"}

    merged = dep_export._upsert_artifact_entry(original, replacement)

    dep_entries = [row for row in merged if row.get("type") == "dep_snapshot"]
    assert len(dep_entries) == 1
    assert dep_entries[0]["sha256"] == "new"
    assert any(row.get("type") == "static_report" for row in merged)


def test_update_static_manifest_dedupes_dep_snapshot_entries(tmp_path: Path) -> None:
    run_dir = tmp_path / "evidence" / "static_runs" / "123"
    run_dir.mkdir(parents=True)
    manifest_path = run_dir / "run_manifest.json"
    dep_path = run_dir / "dep.json"
    dep_path.write_text("{}", encoding="utf-8")
    manifest_path.write_text(
        json.dumps(
            {
                "package_name": "com.example.app",
                "artifacts": [
                    {"path": str(dep_path), "type": "dep_snapshot", "sha256": "old", "size_bytes": 1}
                ],
            }
        ),
        encoding="utf-8",
    )

    old_cwd = Path.cwd()
    try:
        import os

        os.chdir(tmp_path)
        dep_export._update_static_manifest(
            123,
            dep_path,
            {"package_name": "com.example.app"},
        )
    finally:
        os.chdir(old_cwd)

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    dep_entries = [row for row in payload["artifacts"] if row.get("type") == "dep_snapshot"]
    assert len(dep_entries) == 1
