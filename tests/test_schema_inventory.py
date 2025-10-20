"""Tests for schema inspection helpers in db_inventory script."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_db_inventory_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "db_inventory.py"
    spec = importlib.util.spec_from_file_location("db_inventory_test_module", path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError("Unable to load db_inventory module for testing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[arg-type]
    return module


db_inventory = _load_db_inventory_module()


def test_parse_schema_statements_extracts_objects():
    statements = [
        """
        CREATE TABLE IF NOT EXISTS foo (
          id BIGINT NOT NULL AUTO_INCREMENT,
          PRIMARY KEY (id)
        );
        """,
        """
        ALTER TABLE foo
          ADD COLUMN IF NOT EXISTS bar VARCHAR(32) DEFAULT NULL,
          ADD COLUMN baz INT;
        """,
        """
        CREATE INDEX IF NOT EXISTS ix_foo_bar ON foo (bar);
        """,
        """
        CREATE OR REPLACE VIEW v_foo AS SELECT bar FROM foo;
        """,
    ]

    items = db_inventory.parse_schema_statements(statements)

    kinds = {(item.kind, item.name) for item in items}
    assert ("table", "foo") in kinds
    assert ("view", "v_foo") in kinds
    assert any(item.kind == "index" and item.name == "ix_foo_bar" and item.target == "foo" for item in items)

    alters = [item for item in items if item.kind == "alter" and item.name == "foo"]
    assert alters, "Expected alter statement for table foo"
    assert set(alters[0].columns) == {"bar", "baz"}


def test_summarise_schema_usage_reports_missing_elements():
    statements = [
        "CREATE TABLE IF NOT EXISTS foo (id INT);",
        "ALTER TABLE foo ADD COLUMN IF NOT EXISTS bar INT, ADD COLUMN baz INT;",
        "CREATE INDEX IF NOT EXISTS ix_foo_bar ON foo (bar);",
        "CREATE OR REPLACE VIEW v_foo AS SELECT bar FROM foo;",
    ]
    items = db_inventory.parse_schema_statements(statements)

    metadata = db_inventory.SchemaMetadata(
        tables={"foo"},
        views=set(),
        columns={"foo": {"bar"}},
        indexes={"foo": {"ix_foo_bar": {"bar"}}},
    )

    checks = db_inventory.summarise_schema_usage(items, metadata)

    status_map = {(check.item.kind, check.item.name): check for check in checks}

    assert status_map[("table", "foo")].status == "present"
    assert status_map[("index", "ix_foo_bar")].status == "present"
    assert status_map[("view", "v_foo")].status == "missing"

    alter_check = next(check for check in checks if check.item.kind == "alter" and check.item.name == "foo")
    assert alter_check.status == "needs-columns"
    assert "baz" in alter_check.detail
