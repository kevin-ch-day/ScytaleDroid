import json

from scytaledroid.Persistence import db_writer


def test_create_run_includes_profiles(monkeypatch):
    captured: dict[str, object] = {}

    monkeypatch.setattr(db_writer, "ensure_schema", lambda: True)

    def fake_run_sql(query, params=None, **kwargs):
        captured["query"] = query
        captured["params"] = params
        return 7

    monkeypatch.setattr(db_writer.core_q, "run_sql", fake_run_sql)

    run_id = db_writer.create_run(
        package="com.example.app",
        version_code=1,
        version_name="1.0",
        target_sdk=33,
        session_stamp="20240101-010101",
        threat_profile="Active",
        env_profile="enterprise",
    )

    assert run_id == 7
    assert "threat_profile" in captured["query"]
    assert captured["params"][-2:] == ("Active", "enterprise")


def test_write_findings_accepts_mapping(monkeypatch):
    captured: list[tuple] = []

    def fake_run_sql(query, params=None, **kwargs):
        captured.append(params)
        return None

    monkeypatch.setattr(db_writer.core_q, "run_sql", fake_run_sql)

    rows = [
        {
            "severity": "Medium",
            "masvs": "PLATFORM",
            "cvss": "CVSS",
            "kind": "ipc_components",
            "module_id": "manifest",
            "evidence": {"detail": "Receiver exported", "path": "AndroidManifest.xml"},
        }
    ]

    assert db_writer.write_findings(5, rows) is True
    assert len(captured) == 1
    params = captured[0]
    assert params[0] == 5
    evidence_payload = params[5]
    assert isinstance(evidence_payload, str)
    evidence_json = json.loads(evidence_payload)
    assert evidence_json["detail"] == "Receiver exported"
    assert evidence_json["path"] == "AndroidManifest.xml"
    assert params[-1] == "manifest"


def test_ensure_metrics_unique_key_deduplicates(monkeypatch):
    calls: list[str] = []

    def fake_run_sql(query, params=None, fetch=None, dictionary=False, **kwargs):
        text = " ".join(query.strip().split())
        calls.append(text)
        if "SHOW INDEX" in query:
            return None
        if "HAVING COUNT(*) > 1" in query:
            return {"run_id": 1, "feature_key": "dup"}
        return None

    monkeypatch.setattr(db_writer.core_q, "run_sql", fake_run_sql)

    db_writer._ensure_metrics_unique_key()

    assert any("CREATE TABLE metrics_tmp" in call for call in calls)
    assert any("INSERT INTO metrics_tmp" in call for call in calls)
    assert any("RENAME TABLE metrics TO metrics_backup_tmp, metrics_tmp TO metrics" in call for call in calls)
    assert any("ALTER TABLE metrics ADD UNIQUE KEY" in call for call in calls)
