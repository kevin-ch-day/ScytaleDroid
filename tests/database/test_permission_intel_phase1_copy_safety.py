from __future__ import annotations

import json
import sys

import pytest
from scytaledroid.Database.tools import permission_intel_phase1_copy as copy


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.setattr(copy, "_source_db_name", lambda: "source_catalog")
    monkeypatch.setattr(copy, "PHASE1_TABLES", ("first_table", "second_table"))
    monkeypatch.setattr(
        copy, "DatabaseEngine", lambda: pytest.fail("Unexpected database connection")
    )


class FakeDB:
    def __init__(self, *, fail=None, target_count=3):
        self.statements = []
        self.closed = False
        self.fail = fail
        self.target_count = target_count

    def fetch_one(self, sql, **kwargs):
        if sql.startswith("SHOW CREATE TABLE"):
            table = sql.split("`")[1]
            return table, f"CREATE TABLE `{table}` (`id` int)"
        return (self.target_count if kwargs.get("query_name", "").endswith("target_count") else 3,)

    def execute(self, sql, **kwargs):
        self.statements.append(sql)
        if self.fail and self.fail in sql:
            raise RuntimeError("synthetic failure")

    def close(self):
        self.closed = True


def test_cli_requires_destination(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["copy"])
    with pytest.raises(SystemExit) as exc:
        copy.main()
    assert exc.value.code == 2


def test_default_plan_has_no_connection_or_receipt(tmp_path, capsys):
    path = tmp_path / "receipt.json"
    result = copy.copy_phase1_tables(target_db="scratch_copy", receipt_path=path)
    plan = json.loads(capsys.readouterr().out)
    assert plan["mode"] == "dry_run"
    assert plan["replace_tables"] is False
    assert plan["tables"] == ["first_table", "second_table"]
    assert all(row["source_count"] is None for row in result)
    assert not path.exists()


@pytest.mark.parametrize(
    "target",
    ["android_permission_intel", "ANDROID_PERMISSION_INTEL", "example_prod", "EXAMPLE_PROD"],
)
@pytest.mark.parametrize(
    "flag,confirmation", [(False, None), (True, None), (True, "wrong"), (False, "exact")]
)
def test_protected_target_needs_both_controls(target, flag, confirmation):
    with pytest.raises(RuntimeError, match="Protected target"):
        copy.copy_phase1_tables(
            target_db=target,
            apply=True,
            allow_protected_target=flag,
            confirmation=target if confirmation == "exact" else confirmation,
        )


@pytest.mark.parametrize(
    "target",
    ["mysql", "information_schema", "performance_schema", "sys", "SOURCE_CATALOG", "", "bad-name"],
)
def test_invalid_target_cannot_be_overridden(target):
    with pytest.raises(RuntimeError):
        copy.copy_phase1_tables(
            target_db=target, apply=True, allow_protected_target=True, confirmation=target
        )


def test_apply_defaults_to_no_drop_and_records_receipt(monkeypatch, tmp_path):
    db = FakeDB()
    monkeypatch.setattr(copy, "DatabaseEngine", lambda: db)
    monkeypatch.setattr(copy.getpass, "getuser", lambda: "test_operator")
    path = tmp_path / "receipt.json"
    result = copy.copy_phase1_tables(target_db="scratch_copy", apply=True, receipt_path=path)
    receipt = json.loads(path.read_text())
    assert receipt["status"] == "completed"
    assert receipt["source_db"] == "source_catalog"
    assert receipt["target_db"] == "scratch_copy"
    assert receipt["operator"] == "test_operator"
    assert receipt["started_at_utc"] and receipt["finished_at_utc"]
    assert receipt["results"] == result
    assert all(r["source_count"] == r["target_count"] == 3 for r in result)
    assert not any("DROP TABLE" in sql for sql in db.statements)
    assert db.closed


def test_protected_apply_requires_exact_case(monkeypatch, tmp_path):
    with pytest.raises(RuntimeError):
        copy.copy_phase1_tables(
            target_db="EXAMPLE_PROD",
            apply=True,
            allow_protected_target=True,
            confirmation="example_prod",
        )
    db = FakeDB()
    monkeypatch.setattr(copy, "DatabaseEngine", lambda: db)
    copy.copy_phase1_tables(
        target_db="EXAMPLE_PROD",
        apply=True,
        allow_protected_target=True,
        confirmation="EXAMPLE_PROD",
        receipt_path=tmp_path / "receipt.json",
    )
    assert any("INSERT INTO `EXAMPLE_PROD`" in sql for sql in db.statements)


def test_truncate_is_explicit_and_restores_fk_checks_on_error(monkeypatch, tmp_path):
    db = FakeDB(fail="DROP TABLE")
    monkeypatch.setattr(copy, "DatabaseEngine", lambda: db)
    path = tmp_path / "receipt.json"
    with pytest.raises(RuntimeError):
        copy.copy_phase1_tables(
            target_db="scratch_copy", apply=True, truncate=True, receipt_path=path
        )
    assert db.statements[-1] == "SET FOREIGN_KEY_CHECKS=1"
    receipt = json.loads(path.read_text())
    assert receipt["status"] == "failed"
    assert receipt["error_type"] == "RuntimeError"
    assert receipt["results"][0]["source_count"] == 3
    assert receipt["results"][0]["target_count"] is None
    assert db.closed


def test_receipt_failure_prevents_connection(tmp_path):
    path = tmp_path / "existing.json"
    path.write_text("retain me")
    with pytest.raises(FileExistsError):
        copy.copy_phase1_tables(target_db="scratch_copy", apply=True, receipt_path=path)
    assert path.read_text() == "retain me"


def test_connection_failure_has_receipt(monkeypatch, tmp_path):
    def fail():
        raise RuntimeError("synthetic credential-like text must not be recorded")

    monkeypatch.setattr(copy, "DatabaseEngine", fail)
    path = tmp_path / "receipt.json"
    with pytest.raises(RuntimeError):
        copy.copy_phase1_tables(target_db="scratch_copy", apply=True, receipt_path=path)
    receipt = json.loads(path.read_text())
    assert receipt["status"] == "failed"
    assert receipt["finished_at_utc"]
    assert "credential-like" not in path.read_text()


def test_automatic_receipt_and_mismatch(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(copy, "DatabaseEngine", lambda: FakeDB(target_count=2))
    copy.copy_phase1_tables(target_db="scratch_copy", apply=True)
    receipts = list(tmp_path.glob("output/audit/permission_intel_copy/*.json"))
    assert len(receipts) == 1
    assert json.loads(receipts[0].read_text())["status"] == "mismatch"


def test_cli_dry_run_and_typed_confirmation(monkeypatch, capsys):
    monkeypatch.setattr(
        sys, "argv", ["copy", "--target-db", "example_prod", "--allow-protected-target"]
    )
    prompts = []

    def answer(prompt):
        prompts.append(prompt)
        return "example_prod"

    monkeypatch.setattr("builtins.input", answer)
    assert copy.main() == 0
    assert prompts and "example_prod" in prompts[0]
    assert json.loads(capsys.readouterr().out)["mode"] == "dry_run"


def test_cli_eof_does_not_apply(monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["copy", "--target-db", "example_prod", "--allow-protected-target", "--apply"]
    )

    def eof(prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert copy.main() == 2


def test_cli_without_apply_only_prints_plan(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["copy", "--target-db", "scratch_copy", "--truncate"])
    assert copy.main() == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["mode"] == "dry_run"
    assert plan["replace_tables"] is True


def test_cli_apply_writes_receipt(monkeypatch, tmp_path):
    db = FakeDB()
    monkeypatch.setattr(copy, "DatabaseEngine", lambda: db)
    path = tmp_path / "receipt.json"
    monkeypatch.setattr(
        sys, "argv", ["copy", "--target-db", "scratch_copy", "--apply", "--json-out", str(path)]
    )
    assert copy.main() == 0
    assert json.loads(path.read_text())["status"] == "completed"
    assert not any("DROP TABLE" in sql for sql in db.statements)


def test_partial_failure_keeps_completed_table_counts(monkeypatch, tmp_path):
    db = FakeDB(fail="INSERT INTO `scratch_copy`.`second_table`")
    monkeypatch.setattr(copy, "DatabaseEngine", lambda: db)
    path = tmp_path / "receipt.json"
    with pytest.raises(RuntimeError):
        copy.copy_phase1_tables(target_db="scratch_copy", apply=True, receipt_path=path)
    receipt = json.loads(path.read_text())
    assert receipt["status"] == "failed"
    assert receipt["results"][0]["target_count"] == 3
    assert receipt["results"][1]["target_count"] is None
