from __future__ import annotations

from unittest.mock import patch

from scytaledroid.Database.db_func.apps import app_labels
from scytaledroid.Database.db_queries.harvest import apk_repository as apk_queries


def test_usable_display_name_rejects_package_equal_and_empty() -> None:
    assert app_labels.usable_display_name("com.example.app", "Example") == "Example"
    assert app_labels.usable_display_name("com.example.app", "com.example.app") is None
    assert app_labels.usable_display_name("com.example.app", "COM.EXAMPLE.APP") is None
    assert app_labels.usable_display_name("com.example.app", "  ") is None


def test_upsert_app_definition_replaces_package_equal_display_name() -> None:
    sql = " ".join(apk_queries.UPSERT_APP_DEFINITION.split())
    assert "LOWER(TRIM(display_name)) = LOWER(package_name)" in sql
    assert "THEN VALUES(display_name)" in sql
    assert "COALESCE(display_name, VALUES(display_name))" not in sql


def test_upsert_display_names_overwrite_false_replaces_package_equal_placeholder() -> None:
    captured: dict[str, object] = {}

    def fake_run_sql_many(sql, items):
        captured["sql"] = " ".join(sql.split())
        captured["items"] = items

    with patch("scytaledroid.Database.db_core.run_sql_many", fake_run_sql_many):
        count = app_labels.upsert_display_names(
            {"com.example.app": "Example"},
            overwrite=False,
        )
    assert count == 1
    assert "LOWER(TRIM(display_name)) = LOWER(package_name)" in str(captured["sql"])
