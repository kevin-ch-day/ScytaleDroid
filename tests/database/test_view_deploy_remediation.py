from __future__ import annotations

from scytaledroid.Database.db_scripts import view_deploy_remediation as vdr


def test_sql_object_missing_error_detects_mysql_1146():
    class E(Exception):
        pass

    exc = E(1146, "Table 'db.v_static_masvs_matrix_v1' doesn't exist")
    assert vdr.sql_object_missing_error(exc)


def test_sql_object_missing_error_string_fallback():
    assert vdr.sql_object_missing_error(RuntimeError("Table 'x.y' doesn't exist"))


def test_remediation_text_mentions_repair_entrypoint():
    text = vdr.remediation_text()
    assert "recreate_web_consumer_views.py" in text
