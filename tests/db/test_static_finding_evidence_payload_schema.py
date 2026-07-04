from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
from scytaledroid.Database.db_utils import static_finding_evidence_payload_schema as schema_mod


def _latin1_column_rows() -> list[dict[str, object]]:
    return [
        {
            "column_name": "evidence_json",
            "data_type": "longtext",
            "column_type": "longtext",
            "character_set_name": "latin1",
            "collation_name": "latin1_swedish_ci",
            "is_nullable": "NO",
            "column_default": None,
        },
        {
            "column_name": "evidence_chars",
            "data_type": "int",
            "column_type": "int(11)",
            "character_set_name": None,
            "collation_name": None,
            "is_nullable": "NO",
            "column_default": None,
        },
        {
            "column_name": "first_seen_at",
            "data_type": "timestamp",
            "column_type": "timestamp",
            "character_set_name": None,
            "collation_name": None,
            "is_nullable": "YES",
            "column_default": "current_timestamp()",
        },
    ]


def _utf8_column_rows() -> list[dict[str, object]]:
    return [
        {
            "column_name": "evidence_json",
            "data_type": "longtext",
            "column_type": "longtext",
            "character_set_name": "utf8mb4",
            "collation_name": "utf8mb4_unicode_ci",
            "is_nullable": "NO",
            "column_default": None,
        },
        {
            "column_name": "evidence_chars",
            "data_type": "int",
            "column_type": "int(10) unsigned",
            "character_set_name": None,
            "collation_name": None,
            "is_nullable": "NO",
            "column_default": None,
        },
        {
            "column_name": "first_seen_at",
            "data_type": "timestamp",
            "column_type": "timestamp",
            "character_set_name": None,
            "collation_name": None,
            "is_nullable": "NO",
            "column_default": "current_timestamp()",
        },
    ]


def _load_static_schema_audit_module():
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts" / "db" / "static_schema_audit.py"
    spec = importlib.util.spec_from_file_location("static_schema_audit", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_static_schema_audit_catalogues_finding_evidence_payloads() -> None:
    module = _load_static_schema_audit_module()
    profile = module.AUDIT_PROFILES["static_finding_evidence_payloads"]
    assert profile["classification"] == "canonical_keep"
    assert "StaticAnalysis/cli/persistence/run_summary.py" in profile["writers_hint"]
    assert "evidence_hash" in profile["notes"]


def test_collect_schema_audit_flags_live_drift_shape() -> None:
    def fake_run_sql(_sql: str, _params=(), *, query_name=None, **_kwargs):
        if query_name == "static_finding_evidence_payload_schema.table_collation":
            return {"table_collation": "latin1_swedish_ci"}
        if query_name == "static_finding_evidence_payload_schema.columns":
            return _latin1_column_rows()
        if query_name == "static_finding_evidence_payload_schema.stats":
            return {
                "rows_n": 12205,
                "negative_chars": 0,
                "null_first_seen": 0,
                "max_chars": 2078,
                "non_ascii_rows": 11,
            }
        raise AssertionError(query_name)

    audit = schema_mod.collect_static_finding_evidence_payload_schema_audit(fake_run_sql)

    assert audit["table_default_collation"] == "latin1_swedish_ci"
    assert audit["table_default_needs_change"] is True
    assert audit["rows_n"] == 12205
    assert audit["non_ascii_rows"] == 11
    assert audit["evidence_json"]["needs_change"] is True
    assert audit["evidence_chars"]["needs_change"] is True
    assert audit["first_seen_at"]["needs_change"] is True
    assert audit["apply_safe"] is True
    assert audit["required_statement_count"] == 2


def test_build_required_schema_statements_is_bounded() -> None:
    audit = {
        "table_default_needs_change": True,
        "evidence_json": {"needs_change": True},
        "evidence_chars": {"needs_change": False},
        "first_seen_at": {"needs_change": True},
    }

    statements = schema_mod.build_required_static_finding_evidence_payload_schema_statements(audit)

    assert len(statements) == 2
    assert statements[0] == (
        "ALTER TABLE static_finding_evidence_payloads DEFAULT CHARACTER SET utf8mb4 "
        "COLLATE utf8mb4_unicode_ci"
    )
    assert (
        "MODIFY COLUMN evidence_json LONGTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL"
        in statements[1]
    )
    assert "MODIFY COLUMN evidence_chars INT UNSIGNED NOT NULL" in statements[1]
    assert (
        "MODIFY COLUMN first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP" in statements[1]
    )


def test_apply_schema_normalization_executes_only_required_ddl(monkeypatch, tmp_path: Path) -> None:
    executions: list[str] = []
    table_collations = iter(("latin1_swedish_ci", "utf8mb4_unicode_ci"))
    column_rows = iter((_latin1_column_rows(), _utf8_column_rows()))
    stats_rows = iter(
        (
            {
                "rows_n": 12205,
                "negative_chars": 0,
                "null_first_seen": 0,
                "max_chars": 2078,
                "non_ascii_rows": 11,
            },
            {
                "rows_n": 12205,
                "negative_chars": 0,
                "null_first_seen": 0,
                "max_chars": 2078,
                "non_ascii_rows": 11,
            },
        )
    )
    receipt_path = tmp_path / "receipt.json"
    recorded: list[tuple[str, str | None, str | None]] = []

    def fake_run_sql(sql: str, params=(), *, query_name=None, **_kwargs):
        del params
        if query_name == "static_finding_evidence_payload_schema.table_collation":
            return {"table_collation": next(table_collations)}
        if query_name == "static_finding_evidence_payload_schema.columns":
            return next(column_rows)
        if query_name == "static_finding_evidence_payload_schema.stats":
            return next(stats_rows)
        if query_name and query_name.startswith("schema_migrations.apply."):
            executions.append(sql)
            return None
        raise AssertionError(query_name)

    monkeypatch.setattr(
        schema_mod,
        "latest_schema_version",
        lambda _run_sql: "0.3.13-static-session-run-links-schema",
    )
    monkeypatch.setattr(
        schema_mod,
        "write_static_finding_evidence_payload_schema_receipt",
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

    result = schema_mod.apply_static_finding_evidence_payload_schema_normalization(fake_run_sql)

    assert result.applied is True
    assert result.statement_count == 2
    assert result.table_default_updated is True
    assert result.evidence_json_updated is True
    assert result.evidence_chars_updated is True
    assert result.first_seen_at_updated is True
    assert result.receipt_path == str(receipt_path)
    assert any(
        "DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci" in sql for sql in executions
    )
    assert any("MODIFY COLUMN evidence_json" in sql for sql in executions)
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
        if query_name == "static_finding_evidence_payload_schema.table_collation":
            return {"table_collation": "utf8mb4_unicode_ci"}
        if query_name == "static_finding_evidence_payload_schema.columns":
            return _utf8_column_rows()
        if query_name == "static_finding_evidence_payload_schema.stats":
            return {
                "rows_n": 12205,
                "negative_chars": 0,
                "null_first_seen": 0,
                "max_chars": 2078,
                "non_ascii_rows": 11,
            }
        raise AssertionError(query_name)

    monkeypatch.setattr(
        schema_mod,
        "latest_schema_version",
        lambda _run_sql: "0.3.13-static-session-run-links-schema",
    )
    monkeypatch.setattr(
        schema_mod,
        "latest_rows_by_migration",
        lambda _run_sql: {},
    )
    monkeypatch.setattr(
        schema_mod,
        "write_static_finding_evidence_payload_schema_receipt",
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

    result = schema_mod.apply_static_finding_evidence_payload_schema_normalization(fake_run_sql)

    assert result.applied is True
    assert result.statement_count == 0
    assert result.receipt_path == str(receipt_path)
    assert any(kind == "record_schema_migration" for kind, _, _ in recorded)
    assert any(
        kind == "append_schema_version" and value == schema_mod.SCHEMA_VERSION_AFTER
        for kind, value, _ in recorded
    )


def test_apply_schema_normalization_refuses_when_preflight_is_dirty() -> None:
    def fake_run_sql(_sql: str, _params=(), *, query_name=None, **_kwargs):
        if query_name == "static_finding_evidence_payload_schema.table_collation":
            return {"table_collation": "latin1_swedish_ci"}
        if query_name == "static_finding_evidence_payload_schema.columns":
            return _latin1_column_rows()
        if query_name == "static_finding_evidence_payload_schema.stats":
            return {
                "rows_n": 12205,
                "negative_chars": 1,
                "null_first_seen": 0,
                "max_chars": 2078,
                "non_ascii_rows": 11,
            }
        raise AssertionError(query_name)

    with pytest.raises(RuntimeError, match="preflight failed"):
        schema_mod.apply_static_finding_evidence_payload_schema_normalization(fake_run_sql)


def test_normalize_script_help_is_safe() -> None:
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "db" / "normalize_static_finding_evidence_payload_schema.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert (proc.stdout or "").lower().startswith("usage:")
