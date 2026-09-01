"""Regression coverage for the fail-closed permission linkage audit."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from scripts.db import audit_static_permission_observation_linkage as audit


def _row(
    *,
    matrix_row_id: int = 10,
    run_id: int = 7,
    current_apk_id: int = 7,
    base_hash: object = "a" * 64,
) -> dict[str, object]:
    return {
        "matrix_row_id": matrix_row_id,
        "run_id": run_id,
        "current_apk_id": current_apk_id,
        "base_apk_sha256": base_hash,
    }


def _schema_columns() -> list[dict[str, object]]:
    def column(
        table: str,
        name: str,
        type_: str,
        *,
        key: str = "",
        nullable: str = "NO",
        collation: str | None = None,
    ) -> dict[str, object]:
        return {
            "TABLE_NAME": table,
            "COLUMN_NAME": name,
            "COLUMN_TYPE": type_,
            "IS_NULLABLE": nullable,
            "CHARACTER_SET_NAME": None if collation is None else "utf8mb4",
            "COLLATION_NAME": collation,
            "COLUMN_KEY": key,
            "EXTRA": "",
        }

    return [
        column("static_permission_matrix", "id", "bigint(20) unsigned", key="PRI"),
        column("static_permission_matrix", "run_id", "bigint(20) unsigned"),
        column(
            "static_permission_matrix",
            "apk_id",
            "bigint(20) unsigned",
            nullable="YES",
        ),
        column("android_apk_repository", "apk_id", "bigint(20) unsigned", key="PRI"),
        column(
            "android_apk_repository",
            "sha256",
            "char(64)",
            key="UNI",
            nullable="YES",
            collation="utf8mb4_unicode_ci",
        ),
        column("static_analysis_runs", "id", "bigint(20) unsigned", key="PRI"),
        column(
            "static_analysis_runs",
            "base_apk_sha256",
            "char(64)",
            nullable="YES",
            collation="utf8mb4_general_ci",
        ),
    ]


class FakeRunner:
    def __init__(
        self,
        *,
        repository_rows: list[dict[str, object]] | None = None,
        matrix_rows: list[dict[str, object]] | None = None,
        fail_pattern: str | None = None,
        schema_rows: list[dict[str, object]] | None = None,
    ) -> None:
        self.repository_rows = repository_rows or [{"apk_id": 99, "sha256": "a" * 64}]
        self.matrix_rows = matrix_rows or [_row()]
        self.fail_pattern = fail_pattern
        self.schema_rows = _schema_columns() if schema_rows is None else schema_rows

    def __call__(
        self,
        sql: str,
        _params: object = None,
        *,
        fetch: str,
        dictionary: bool = False,
    ) -> Any:
        del dictionary
        if self.fail_pattern and self.fail_pattern in sql:
            raise RuntimeError("synthetic SQL failure")
        if "SHOW CREATE TABLE" in sql:
            table = sql.split("`")[1]
            return (table, f"CREATE TABLE `{table}` (stub INT)")
        if "information_schema.COLUMNS" in sql:
            return self.schema_rows
        if "COUNT(*) FROM static_permission_matrix" in sql:
            return (len(self.matrix_rows),)
        if "FROM android_apk_repository ORDER BY" in sql:
            return self.repository_rows
        if "FROM static_permission_matrix AS spm" in sql:
            return self.matrix_rows
        raise AssertionError(f"unexpected SQL: {sql}")


def test_sha256_normalization_compares_bytes_across_text_collations() -> None:
    assert audit.normalize_sha256("AA" * 32) == audit.normalize_sha256("aa" * 32)
    assert audit.normalize_sha256("  " + "a" * 64 + "  ") == bytes.fromhex("a" * 64)
    assert audit.normalize_sha256("not-hex") is None
    assert audit.normalize_sha256(None) is None


def test_apk_id_is_repository_identifier_and_no_nonexistent_r_id_sql() -> None:
    source = Path(audit.__file__).read_text(encoding="utf-8")
    assert "SELECT apk_id, sha256 FROM android_apk_repository" in source
    assert "r.id = spm.apk_id" not in source
    assert "LOWER(TRIM(r.sha256))" not in source


def test_run_id_substitution_is_distinct_from_verified_content_identity() -> None:
    result = audit.classify_linkage_row(
        _row(run_id=7, current_apk_id=7),
        repository_by_id={7: {"apk_id": 7, "sha256": "b" * 64}, 99: {"apk_id": 99, "sha256": "a" * 64}},
        repository_ids_by_hash={bytes.fromhex("a" * 64): [99]},
    )
    assert result["classification"] == "RUN_ID_SUBSTITUTED"
    assert result["current_repository_row_exists"] is True
    assert result["current_numeric_match_has_verified_content_identity"] is False
    assert result["proposed_repository_apk_id"] == 99


def test_same_numeric_id_with_wrong_hash_is_accidental_match() -> None:
    result = audit.classify_linkage_row(
        _row(run_id=1, current_apk_id=7),
        repository_by_id={7: {"apk_id": 7, "sha256": "b" * 64}, 99: {"apk_id": 99, "sha256": "a" * 64}},
        repository_ids_by_hash={bytes.fromhex("a" * 64): [99]},
    )
    assert result["classification"] == "ACCIDENTAL_NUMERIC_MATCH_HASH_MISMATCH"
    assert result["resolution_status"] == "UNIQUE_BASE_HASH_REPAIR_CANDIDATE"


def test_different_numeric_id_with_same_verified_hash_is_correct_candidate() -> None:
    result = audit.classify_linkage_row(
        _row(run_id=1, current_apk_id=7, base_hash="A" * 64),
        repository_by_id={7: {"apk_id": 7, "sha256": "a" * 64}},
        repository_ids_by_hash={bytes.fromhex("a" * 64): [7]},
    )
    assert result["classification"] == "CORRECT"
    assert result["current_numeric_match_has_verified_content_identity"] is True


@pytest.mark.parametrize(
    ("base_hash", "ids", "expected"),
    [
        ("a" * 64, [], "BASE_HASH_NOT_FOUND"),
        ("a" * 64, [8, 9], "BASE_HASH_AMBIGUOUS"),
        ("xyz", [], "MALFORMED_HASH"),
        (None, [], "MALFORMED_HASH"),
    ],
)
def test_unresolved_and_malformed_hashes_fail_closed(
    base_hash: object,
    ids: list[int],
    expected: str,
) -> None:
    mapping = {bytes.fromhex("a" * 64): ids} if ids else {}
    result = audit.classify_linkage_row(
        _row(base_hash=base_hash),
        repository_by_id={},
        repository_ids_by_hash=mapping,
    )
    assert result["classification"] == expected
    assert result["resolution_status"] == "MANUAL_REVIEW_REQUIRED"


def test_required_sql_error_returns_stable_nonzero() -> None:
    result, exit_code = audit.audit_from_runner(FakeRunner(fail_pattern="COUNT(*)"))
    assert exit_code == audit.EXIT_QUERY
    assert result["error_class"] == "query"


def test_missing_schema_section_returns_stable_nonzero() -> None:
    result, exit_code = audit.audit_from_runner(FakeRunner(schema_rows=[]))
    assert exit_code == audit.EXIT_SCHEMA
    assert result["error_class"] == "schema"


def test_ambiguous_content_mapping_marks_audit_incomplete() -> None:
    runner = FakeRunner(
        repository_rows=[
            {"apk_id": 8, "sha256": "a" * 64},
            {"apk_id": 9, "sha256": "A" * 64},
        ]
    )
    result, exit_code = audit.audit_from_runner(runner)
    assert exit_code == audit.EXIT_INCOMPLETE
    assert result["summary"]["status"] == "INCOMPLETE"


def test_report_and_exact_proposal_are_deterministic() -> None:
    first, first_exit = audit.audit_from_runner(FakeRunner())
    second, second_exit = audit.audit_from_runner(FakeRunner())
    assert first_exit == second_exit == audit.EXIT_OK
    assert first == second
    assert first["summary"]["sections"]["proposal_generation"]["executable_sql_present"] is False


def test_private_proposal_refuses_repository_output(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(audit, "_REPO_ROOT", tmp_path)
    with pytest.raises(ValueError, match="outside the repository"):
        audit._write_private_json(tmp_path / "proposal.json", {"status": "test"})


def test_active_readiness_document_matches_fail_closed_contract() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    text = (
        repo_root
        / "docs/database/permission_intel_scytaledroid_s2_p1a_operational_readiness.md"
    ).read_text(encoding="utf-8")
    assert "android_apk_repository.id" not in text
    assert "Erebus alias (option 2)" not in text
    assert "blocked_legacy_alias" in text
    assert "android_apk_repository.apk_id" in text
    assert "has not been applied" in text


def test_runtime_grants_plan_preserves_privilege_separation() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    text = (repo_root / "docs/database/scytaledroid_pi_runtime_grants_plan.md").read_text(
        encoding="utf-8"
    )
    assert "NOT APPLIED TO PRODUCTION" in text
    assert "scytaledroid_pi_reference_reader" in text
    assert "scytaledroid_pi_governed_submitter" in text
    assert "android_permission_obs_sample`" in text
    assert "Neither role receives `CREATE`, `ALTER`, `DROP`" in text
