from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.DynamicAnalysis.storage import persistence


def test_load_artifact_registry_uses_integrity_view_and_resolved_dynamic_run_id(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_run_sql(sql, params=(), **_kwargs):
        captured["sql"] = sql
        captured["params"] = params
        return [("pcap", "dynamic", "stored", "abc", "/tmp/file")]

    monkeypatch.setattr(persistence, "core_q", SimpleNamespace(run_sql=_fake_run_sql))

    rows = persistence._load_artifact_registry("11111111-1111-4111-8111-111111111111")

    assert rows == [
        {
            "artifact_type": "pcap",
            "origin": "dynamic",
            "pull_status": "stored",
            "sha256": "abc",
            "host_path": "/tmp/file",
        }
    ]
    assert captured["params"] == ("11111111-1111-4111-8111-111111111111",)
    sql = str(captured["sql"])
    assert "FROM v_artifact_registry_integrity" in sql
    assert "resolved_dynamic_run_id=%s" in sql

