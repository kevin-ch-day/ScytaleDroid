from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.execution import db_verification
from scytaledroid.StaticAnalysis.cli.menus import static_analysis_menu_helpers as helpers


def test_last_static_package_uses_typed_started_at_ordering(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_run_sql(sql, *_args, **_kwargs):
        captured["sql"] = sql
        return ("com.example.app",)

    monkeypatch.setattr(helpers, "core_q", SimpleNamespace(run_sql=_fake_run_sql))

    package_name = helpers._get_last_static_package()

    assert package_name == "com.example.app"
    sql = str(captured["sql"])
    assert "sar.run_started_at_utc" in sql
    assert "ORDER BY COALESCE(sar.ended_at_utc" in sql


def test_last_static_run_info_uses_typed_started_at_and_text_projection(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_run_sql(sql, *_args, **_kwargs):
        captured["sql"] = sql
        return (
            "com.example.app",
            "1.0",
            "1",
            "sha",
            "COMPLETED",
            "CANONICAL",
            "sess-1",
            "2026-06-14 12:00:00",
        )

    monkeypatch.setattr(helpers, "core_q", SimpleNamespace(run_sql=_fake_run_sql))

    info = helpers._get_last_static_run_info()

    assert info is not None
    sql = str(captured["sql"])
    assert "sar.run_started_at_utc" in sql
    assert "DATE_FORMAT(" in sql
    assert "COALESCE(sar.ended_at_utc" in sql


def test_render_attempt_history_uses_typed_started_text_expression(monkeypatch, capsys) -> None:
    captured: dict[str, object] = {}

    def _fake_run_sql(sql, *_args, **_kwargs):
        captured["sql"] = sql
        return []

    monkeypatch.setattr(db_verification.core_q, "run_sql", _fake_run_sql)

    db_verification._render_attempt_history("sess-1")
    capsys.readouterr()

    sql = str(captured["sql"])
    assert "run_started_at_utc" in sql
    assert "DATE_FORMAT(" in sql
