from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from scytaledroid.Database.db_utils import static_session_run_links_schema as schema_mod


def _latin1_column_rows() -> list[dict[str, object]]:
    return [
        {
            "column_name": "run_origin",
            "column_type": "varchar(16)",
            "is_nullable": "NO",
            "column_default": "'created'",
            "character_set_name": "latin1",
            "collation_name": "latin1_swedish_ci",
        },
        {
            "column_name": "origin_session_stamp",
            "column_type": "varchar(128)",
            "is_nullable": "YES",
            "column_default": "NULL",
            "character_set_name": "latin1",
            "collation_name": "latin1_swedish_ci",
        },
        {
            "column_name": "pipeline_version",
            "column_type": "varchar(32)",
            "is_nullable": "NO",
            "column_default": None,
            "character_set_name": "latin1",
            "collation_name": "latin1_swedish_ci",
        },
        {
            "column_name": "base_apk_sha256",
            "column_type": "char(64)",
            "is_nullable": "NO",
            "column_default": None,
            "character_set_name": "latin1",
            "collation_name": "latin1_swedish_ci",
        },
        {
            "column_name": "artifact_set_hash",
            "column_type": "char(64)",
            "is_nullable": "NO",
            "column_default": None,
            "character_set_name": "latin1",
            "collation_name": "latin1_swedish_ci",
        },
        {
            "column_name": "run_signature",
            "column_type": "char(64)",
            "is_nullable": "NO",
            "column_default": None,
            "character_set_name": "latin1",
            "collation_name": "latin1_swedish_ci",
        },
        {
            "column_name": "run_signature_version",
            "column_type": "varchar(16)",
            "is_nullable": "NO",
            "column_default": None,
            "character_set_name": "latin1",
            "collation_name": "latin1_swedish_ci",
        },
        {
            "column_name": "identity_error_reason",
            "column_type": "varchar(128)",
            "is_nullable": "YES",
            "column_default": "NULL",
            "character_set_name": "latin1",
            "collation_name": "latin1_swedish_ci",
        },
    ]


def _utf8_column_rows() -> list[dict[str, object]]:
    rows = _latin1_column_rows()
    for row in rows:
        row["character_set_name"] = "utf8mb4"
        row["collation_name"] = "utf8mb4_unicode_ci"
    return rows


def test_collect_schema_audit_flags_live_drift_shape() -> None:
    def fake_run_sql(_sql: str, _params=(), *, query_name=None, **_kwargs):
        if query_name == "static_session_run_links_schema.table_collation":
            return {"table_collation": "latin1_swedish_ci"}
        if query_name == "static_session_run_links_schema.columns":
            return _latin1_column_rows()
        if query_name == "static_session_run_links_schema.indexes":
            return [
                {"index_name": "PRIMARY", "column_name": "link_id", "seq_in_index": 1},
                {
                    "index_name": "uniq_session_package",
                    "column_name": "session_stamp",
                    "seq_in_index": 1,
                },
                {
                    "index_name": "uniq_session_package",
                    "column_name": "package_name",
                    "seq_in_index": 2,
                },
                {
                    "index_name": "ix_ssrl_static_run",
                    "column_name": "static_run_id",
                    "seq_in_index": 1,
                },
            ]
        if query_name == "static_session_run_links_schema.foreign_keys":
            return []
        if query_name == "static_session_run_links_schema.unlinked_static_runs":
            return {"n": 0}
        raise AssertionError(query_name)

    audit = schema_mod.collect_static_session_run_links_schema_audit(fake_run_sql)

    assert audit["table_default_collation"] == "latin1_swedish_ci"
    assert audit["table_default_needs_change"] is True
    assert audit["text_columns_needing_normalization"] == 8
    assert audit["missing_origin_session_stamp_index"] is True
    assert audit["missing_static_run_fk"] is True
    assert audit["unlinked_static_run_rows"] == 0
    assert audit["apply_safe"] is True
    assert audit["required_statement_count"] == 4


def test_build_required_schema_statements_is_bounded() -> None:
    audit = {
        "table_default_needs_change": True,
        "missing_origin_session_stamp_index": True,
        "missing_static_run_fk": True,
        "columns": [
            {"column": "run_origin", "present": True, "needs_change": True},
            {"column": "origin_session_stamp", "present": True, "needs_change": True},
            {"column": "pipeline_version", "present": True, "needs_change": False},
            {"column": "base_apk_sha256", "present": True, "needs_change": False},
            {"column": "artifact_set_hash", "present": True, "needs_change": False},
            {"column": "run_signature", "present": True, "needs_change": False},
            {"column": "run_signature_version", "present": True, "needs_change": False},
            {"column": "identity_error_reason", "present": True, "needs_change": False},
        ],
    }

    statements = schema_mod.build_required_static_session_run_links_schema_statements(audit)

    assert len(statements) == 4
    assert statements[0].startswith(
        "ALTER TABLE static_session_run_links DEFAULT CHARACTER SET utf8mb4"
    )
    assert "MODIFY COLUMN run_origin" in statements[1]
    assert "MODIFY COLUMN origin_session_stamp" in statements[1]
    assert (
        statements[2]
        == "CREATE INDEX IF NOT EXISTS ix_static_session_run_origin ON static_session_run_links (origin_session_stamp)"
    )
    assert "ADD CONSTRAINT fk_static_session_run_static" in statements[3]


def test_apply_schema_normalization_executes_only_required_ddl(monkeypatch, tmp_path: Path) -> None:
    executions: list[str] = []
    table_collations = iter(("latin1_swedish_ci", "utf8mb4_unicode_ci"))
    column_rows = iter((_latin1_column_rows(), _utf8_column_rows()))
    index_rows = iter(
        (
            [
                {"index_name": "PRIMARY", "column_name": "link_id", "seq_in_index": 1},
                {
                    "index_name": "uniq_session_package",
                    "column_name": "session_stamp",
                    "seq_in_index": 1,
                },
                {
                    "index_name": "uniq_session_package",
                    "column_name": "package_name",
                    "seq_in_index": 2,
                },
                {
                    "index_name": "ix_ssrl_static_run",
                    "column_name": "static_run_id",
                    "seq_in_index": 1,
                },
            ],
            [
                {"index_name": "PRIMARY", "column_name": "link_id", "seq_in_index": 1},
                {
                    "index_name": "uniq_session_package",
                    "column_name": "session_stamp",
                    "seq_in_index": 1,
                },
                {
                    "index_name": "uniq_session_package",
                    "column_name": "package_name",
                    "seq_in_index": 2,
                },
                {
                    "index_name": "ix_ssrl_static_run",
                    "column_name": "static_run_id",
                    "seq_in_index": 1,
                },
                {
                    "index_name": "ix_static_session_run_origin",
                    "column_name": "origin_session_stamp",
                    "seq_in_index": 1,
                },
            ],
        )
    )
    fk_rows = iter(
        (
            [],
            [
                {
                    "constraint_name": "fk_static_session_run_static",
                    "column_name": "static_run_id",
                    "referenced_table_name": "static_analysis_runs",
                    "referenced_column_name": "id",
                    "delete_rule": "CASCADE",
                }
            ],
        )
    )
    receipt_path = tmp_path / "receipt.json"
    recorded: list[tuple[str, str | None, str | None]] = []

    def fake_run_sql(sql: str, params=(), *, query_name=None, **_kwargs):
        if query_name == "static_session_run_links_schema.table_collation":
            return {"table_collation": next(table_collations)}
        if query_name == "static_session_run_links_schema.columns":
            return next(column_rows)
        if query_name == "static_session_run_links_schema.indexes":
            return next(index_rows)
        if query_name == "static_session_run_links_schema.foreign_keys":
            return next(fk_rows)
        if query_name == "static_session_run_links_schema.unlinked_static_runs":
            return {"n": 0}
        if query_name and query_name.startswith("schema_migrations.apply."):
            executions.append(sql)
            return None
        if query_name == "schema_migrations.insert":
            recorded.append(("insert", None, None))
            return None
        if query_name == "schema_migrations.append_schema_version":
            recorded.append(("append_schema_version", params[0] if params else None, None))
            return None
        raise AssertionError(query_name)

    monkeypatch.setattr(
        schema_mod,
        "latest_schema_version",
        lambda _run_sql: "0.3.12-artifact-registry-session-stamp",
    )
    monkeypatch.setattr(
        schema_mod,
        "write_static_session_run_links_schema_receipt",
        lambda payload, _out: str(receipt_path),
    )
    monkeypatch.setattr(
        schema_mod,
        "record_schema_migration",
        lambda run_sql, **kwargs: recorded.append(
            ("record_schema_migration", kwargs.get("schema_version_after"), kwargs.get("notes"))
        ),
    )
    monkeypatch.setattr(
        schema_mod,
        "append_schema_version",
        lambda run_sql, version: recorded.append(("append_schema_version", version, None)),
    )

    result = schema_mod.apply_static_session_run_links_schema_normalization(fake_run_sql)

    assert result.applied is True
    assert result.statement_count == 4
    assert result.table_default_updated is True
    assert result.text_columns_updated == 8
    assert result.index_added is True
    assert result.foreign_key_added is True
    assert result.receipt_path == str(receipt_path)
    assert any(
        "DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci" in sql for sql in executions
    )
    assert any("MODIFY COLUMN run_origin" in sql for sql in executions)
    assert any(
        "CREATE INDEX IF NOT EXISTS ix_static_session_run_origin" in sql for sql in executions
    )
    assert any("ADD CONSTRAINT fk_static_session_run_static" in sql for sql in executions)
    assert any(kind == "record_schema_migration" for kind, _, _ in recorded)
    assert any(
        kind == "append_schema_version" and value == schema_mod.SCHEMA_VERSION_AFTER
        for kind, value, _ in recorded
    )


def test_apply_schema_normalization_records_converged_live_state(
    monkeypatch, tmp_path: Path
) -> None:
    recorded: list[tuple[str, str | None, str | None]] = []
    receipt_path = tmp_path / "receipt.json"

    def fake_run_sql(_sql: str, _params=(), *, query_name=None, **_kwargs):
        if query_name == "static_session_run_links_schema.table_collation":
            return {"table_collation": "utf8mb4_unicode_ci"}
        if query_name == "static_session_run_links_schema.columns":
            return _utf8_column_rows()
        if query_name == "static_session_run_links_schema.indexes":
            return [
                {"index_name": "PRIMARY", "column_name": "link_id", "seq_in_index": 1},
                {
                    "index_name": "uniq_session_package",
                    "column_name": "session_stamp",
                    "seq_in_index": 1,
                },
                {
                    "index_name": "uniq_session_package",
                    "column_name": "package_name",
                    "seq_in_index": 2,
                },
                {
                    "index_name": "ix_ssrl_static_run",
                    "column_name": "static_run_id",
                    "seq_in_index": 1,
                },
                {
                    "index_name": "ix_static_session_run_origin",
                    "column_name": "origin_session_stamp",
                    "seq_in_index": 1,
                },
            ]
        if query_name == "static_session_run_links_schema.foreign_keys":
            return [
                {
                    "constraint_name": "fk_static_session_run_static",
                    "column_name": "static_run_id",
                    "referenced_table_name": "static_analysis_runs",
                    "referenced_column_name": "id",
                    "delete_rule": "CASCADE",
                }
            ]
        if query_name == "static_session_run_links_schema.unlinked_static_runs":
            return {"n": 0}
        raise AssertionError(query_name)

    monkeypatch.setattr(
        schema_mod,
        "latest_schema_version",
        lambda _run_sql: "0.3.12-artifact-registry-session-stamp",
    )
    monkeypatch.setattr(schema_mod, "_migration_already_recorded", lambda _run_sql: False)
    monkeypatch.setattr(
        schema_mod,
        "write_static_session_run_links_schema_receipt",
        lambda payload, _out: str(receipt_path),
    )
    monkeypatch.setattr(
        schema_mod,
        "record_schema_migration",
        lambda run_sql, **kwargs: recorded.append(
            ("record_schema_migration", kwargs.get("schema_version_after"), kwargs.get("notes"))
        ),
    )
    monkeypatch.setattr(
        schema_mod,
        "append_schema_version",
        lambda run_sql, version: recorded.append(("append_schema_version", version, None)),
    )

    result = schema_mod.apply_static_session_run_links_schema_normalization(fake_run_sql)

    assert result.applied is True
    assert result.statement_count == 0
    assert result.receipt_path == str(receipt_path)
    assert any(kind == "record_schema_migration" for kind, _, _ in recorded)
    assert any(
        kind == "append_schema_version" and value == schema_mod.SCHEMA_VERSION_AFTER
        for kind, value, _ in recorded
    )


def test_apply_schema_normalization_refuses_unlinked_static_runs() -> None:
    def fake_run_sql(_sql: str, _params=(), *, query_name=None, **_kwargs):
        if query_name == "static_session_run_links_schema.table_collation":
            return {"table_collation": "latin1_swedish_ci"}
        if query_name == "static_session_run_links_schema.columns":
            return _latin1_column_rows()
        if query_name == "static_session_run_links_schema.indexes":
            return []
        if query_name == "static_session_run_links_schema.foreign_keys":
            return []
        if query_name == "static_session_run_links_schema.unlinked_static_runs":
            return {"n": 3}
        raise AssertionError(query_name)

    with pytest.raises(RuntimeError, match="unlinked_static_run_rows=3"):
        schema_mod.apply_static_session_run_links_schema_normalization(fake_run_sql)


def test_static_session_run_links_schema_script_help() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "normalize_static_session_run_links_schema.py"
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
