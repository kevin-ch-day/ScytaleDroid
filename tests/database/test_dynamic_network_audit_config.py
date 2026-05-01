from __future__ import annotations

from scripts.operator import audit_dynamic_network_consistency as audit


def test_dynamic_network_audit_accepts_split_db_env(monkeypatch):
    monkeypatch.delenv("SCYTALEDROID_DB_URL", raising=False)
    monkeypatch.setenv("SCYTALEDROID_DB_NAME", "scytaledroid_db_dev")
    monkeypatch.setenv("SCYTALEDROID_DB_USER", "operator")
    monkeypatch.setenv("SCYTALEDROID_DB_PASSWD", "secret")
    monkeypatch.setenv("SCYTALEDROID_DB_HOST", "db.local")
    monkeypatch.setenv("SCYTALEDROID_DB_PORT", "3307")

    assert audit._resolve_db_url() == "mysql://operator:secret@db.local:3307/scytaledroid_db_dev"


def test_dynamic_network_audit_prefers_db_url(monkeypatch):
    monkeypatch.setenv("SCYTALEDROID_DB_URL", "mariadb://u:p@host:3306/db")
    monkeypatch.setenv("SCYTALEDROID_DB_NAME", "ignored")

    assert audit._resolve_db_url() == "mariadb://u:p@host:3306/db"
