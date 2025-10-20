import json

from scytaledroid.StaticAnalysis.persistence import ingest


def test_ingest_baseline_payload_persists_nested_findings(monkeypatch):
    schema_called = {"value": False}
    monkeypatch.setattr(ingest, "_ensure_schema_ready", lambda: schema_called.__setitem__("value", True) or True)

    calls: list[tuple[str, tuple]] = []

    def fake_run_sql(query, params=None, fetch=None, return_lastrowid=False, **kwargs):
        text = " ".join(str(query).split())
        if "SELECT id FROM apps" in text or "SELECT id FROM app_versions" in text:
            return None
        if "INSERT INTO apps" in text:
            return 11
        if "INSERT INTO app_versions" in text:
            return 22
        if "INSERT INTO static_analysis_runs" in text:
            calls.append(("run", params))
            return 33
        if "INSERT INTO static_analysis_findings" in text:
            calls.append(("finding", params))
            return None
        if "INSERT INTO static_fileproviders" in text:
            calls.append(("provider", params))
            return 44
        if "INSERT INTO static_provider_acl" in text:
            calls.append(("provider_acl", params))
            return None
        return None

    monkeypatch.setattr(ingest.core_q, "run_sql", fake_run_sql)

    payload = {
        "app": {
            "package": "com.example.app",
            "version_name": "1.2.3",
            "version_code": 123,
            "min_sdk": 23,
            "target_sdk": 34,
        },
        "hashes": {"sha256": "abcd"},
        "analysis_version": "2.1.0",
        "scan_profile": "full",
        "detector_results": [
            {
                "detector_id": "manifest_baseline",
                "section_key": "manifest",
                "findings": [
                    {
                        "finding_id": "F-1",
                        "metrics": {"hashes": ["abc123"], "cvss": 7.1},
                        "masvs_control": "MSTG-ARCH-1",
                    }
                ],
            }
        ],
        "metadata": {"session_stamp": "SESSION", "run_scope_label": "Internal"},
        "analytics": {
            "matrices": {"severity_by_category": {"NETWORK": {"P0": 1}}},
            "indicators": {"novelty_index": 0.75},
            "workload": {"summary": {"findings_per_second": 1.25}},
        },
        "baseline": {
            "findings": [
                {
                    "id": "F-1",
                    "severity": "High",
                    "category": "NETWORK",
                    "title": "Exported component",
                    "evidence": {"path": "AndroidManifest.xml", "preview": "<activity>"},
                    "fix": "Restrict export",
                    "tags": ["manifest", "ipc"],
                }
            ],
            "manifest_flags": {"debuggable": False},
        },
        "detector_metrics": {
            "ipc_components": {"exports": 5},
            "provider_acl": {
                "acl_snapshot": [
                    {
                        "name": "com.example.Provider",
                        "exported": True,
                        "authorities": ["com.example.provider"],
                        "base_permission": None,
                        "read_permission": None,
                        "write_permission": None,
                        "base_guard": "none",
                        "read_guard": "none",
                        "write_guard": "none",
                        "effective_guard": "none",
                        "grant_uri_permissions": False,
                        "path_permissions": [
                            {
                                "path": "/foo",
                                "read_permission": None,
                                "write_permission": None,
                                "read_guard": "none",
                                "write_guard": "none",
                            }
                        ],
                    }
                ]
            },
        },
    }

    assert ingest.ingest_baseline_payload(payload) is True
    assert schema_called["value"] is True

    run_params = next(params for kind, params in calls if kind == "run")
    assert run_params[0] == 22
    assert run_params[1] == "SESSION"
    assert run_params[2] == "Internal"
    assert run_params[3] == "abcd"
    assert run_params[4] == "2.1.0"
    assert run_params[5] == "full"
    assert run_params[6] == 1
    metrics_json = json.loads(run_params[7])
    assert metrics_json["ipc_components"]["exports"] == 5
    repro_json = json.loads(run_params[8])
    assert repro_json["manifest_flags"]["debuggable"] is False
    matrices_json = json.loads(run_params[9])
    assert matrices_json["severity_by_category"]["NETWORK"]["P0"] == 1
    indicators_json = json.loads(run_params[10])
    assert indicators_json["novelty_index"] == 0.75
    workload_json = json.loads(run_params[11])
    assert workload_json["summary"]["findings_per_second"] == 1.25

    finding_params = next(params for kind, params in calls if kind == "finding")
    assert finding_params[0] == 33
    assert finding_params[1] == "F-1"
    assert finding_params[2] is None
    assert finding_params[3] == "High"
    assert finding_params[4] == "NETWORK"
    assert finding_params[5] == "Exported component"
    tags = json.loads(finding_params[6])
    assert tags == ["manifest", "ipc"]
    evidence = json.loads(finding_params[7])
    assert evidence["path"] == "AndroidManifest.xml"
    assert finding_params[8] == "Restrict export"
    assert finding_params[9] is None
    assert finding_params[10] == 7.1
    assert finding_params[11] == "MSTG-ARCH-1"
    assert finding_params[12] == "manifest_baseline"
    assert finding_params[13] == "manifest"
    evidence_refs = json.loads(finding_params[14])
    assert evidence_refs == ["abc123"]

    provider_params = next(params for kind, params in calls if kind == "provider")
    assert provider_params[0] == 33
    assert provider_params[1] == "com.example.Provider"
    authorities = json.loads(provider_params[2])
    assert authorities == ["com.example.provider"]
    acl_params = next(params for kind, params in calls if kind == "provider_acl")
    assert acl_params[0] == 44
    assert acl_params[1] == "/foo"


def test_ingest_baseline_payload_schema_failure(monkeypatch):
    monkeypatch.setattr(ingest, "_ensure_schema_ready", lambda: False)
    assert ingest.ingest_baseline_payload({"app": {"package": "com.example"}}) is False
