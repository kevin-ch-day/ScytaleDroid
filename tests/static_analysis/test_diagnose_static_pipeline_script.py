from __future__ import annotations

from scripts.operator import diagnose_static_pipeline as diag


def test_resolve_db_url_from_split_env(monkeypatch) -> None:
    monkeypatch.delenv("SCYTALEDROID_DB_URL", raising=False)
    monkeypatch.setenv("SCYTALEDROID_DB_NAME", "scytaledroid_db_dev")
    monkeypatch.setenv("SCYTALEDROID_DB_USER", "operator")
    monkeypatch.setenv("SCYTALEDROID_DB_PASSWD", "secret")
    monkeypatch.setenv("SCYTALEDROID_DB_HOST", "localhost")
    monkeypatch.setenv("SCYTALEDROID_DB_PORT", "3306")
    monkeypatch.setenv("SCYTALEDROID_DB_SCHEME", "mysql+pymysql")

    assert (
        diag._resolve_db_url()
        == "mysql://operator:secret@localhost:3306/scytaledroid_db_dev"
    )


def test_normalize_db_scheme_strips_driver_suffix() -> None:
    assert diag._normalize_db_scheme("mysql+pymysql") == "mysql"
    assert diag._normalize_db_scheme("mariadb+mysqldb") == "mariadb"
