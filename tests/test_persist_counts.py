from __future__ import annotations

import json
from collections import Counter
from types import SimpleNamespace

import pytest

from scytaledroid.StaticAnalysis.cli import db_persist


def _make_stub_report() -> SimpleNamespace:
    manifest = SimpleNamespace(
        package_name="com.example.app",
        version_name="1.2.3",
        version_code=123,
        target_sdk=33,
        min_sdk=21,
        app_label="Example App",
    )
    manifest_flags = SimpleNamespace(
        allow_backup=False,
        request_legacy_external_storage=False,
        uses_cleartext_traffic=True,
        network_security_config=None,
    )
    permissions = SimpleNamespace(
        declared=("android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"),
        dangerous=("android.permission.ACCESS_FINE_LOCATION",),
        custom=tuple(),
    )

    class Exported:
        def total(self) -> int:
            return 1

    severity_gate = SimpleNamespace(value="P1")
    finding = SimpleNamespace(
        severity_gate=severity_gate,
        category_masvs=SimpleNamespace(value="PLATFORM"),
        finding_id="TEST-001",
        because="Receiver is exported but does not declare a permission.",
        evidence=[SimpleNamespace(location="AndroidManifest.xml", description=None, hash_short=None)],
        title="Exported component",
        remediate="Fix",
        severity="Medium",
        fix="Fix",
    )
    detector = SimpleNamespace(
        section_key="diffs",
        detector_id="diff_exported_components",
        findings=[finding],
        metrics={},
        duration_sec=0.15,
    )

    return SimpleNamespace(
        manifest=manifest,
        manifest_flags=manifest_flags,
        permissions=permissions,
        exported_components=Exported(),
        detector_results=[detector],
        metadata={},
        hashes={"sha256": "deadfeed"},
    )


@pytest.fixture
def stub_string_data() -> dict[str, object]:
    return {
        "counts": {
            "http_cleartext": 1,
            "endpoints": 1,
            "api_keys": 0,
            "analytics_ids": 0,
            "cloud_refs": 0,
            "ipc": 0,
            "uris": 0,
            "flags": 0,
            "certs": 0,
            "high_entropy": 0,
        },
        "samples": {
            "http_cleartext": [
                {
                    "value": "http://example.com",
                    "src": "classes.dex",
                    "scheme": "http",
                    "root_domain": "example.com",
                    "source_type": "code",
                    "confidence": "high",
                }
            ]
        },
        "aggregates": {
            "api_keys_high": [],
            "endpoint_roots": [
                {
                    "root_domain": "example.com",
                    "total": 1,
                    "schemes": {"http": 1},
                    "source_types": ["code"],
                }
            ],
        },
    }


@pytest.fixture
def baseline_payload() -> dict[str, object]:
    return {
        "app": {
            "package": "com.example.app",
            "label": "Example App",
            "version_name": "1.2.3",
            "version_code": 123,
            "target_sdk": 33,
            "min_sdk": 21,
        },
        "baseline": {
            "manifest_flags": {
                "uses_cleartext_traffic": True,
                "request_legacy_external_storage": False,
            },
            "threat": {"profile": "Active"},
            "environment": {"profile": "enterprise"},
            "exports": {
                "activities": 1,
                "services": 0,
                "receivers": 0,
                "providers": 0,
            },
            "permissions": {
                "declared": ["android.permission.INTERNET"],
                "counts": {"dangerous": 1, "signature": 0, "custom": 0},
            },
            "string_analysis": {
                "counts": {
                    "http_cleartext": 1,
                    "endpoints": 1,
                    "api_keys": 0,
                    "analytics_ids": 0,
                    "cloud_refs": 0,
                    "ipc": 0,
                    "uris": 0,
                    "flags": 0,
                    "certs": 0,
                    "high_entropy": 0,
                },
                "samples": {
                    "http_cleartext": [
                        {
                            "value": "http://example.com",
                            "src": "classes.dex",
                            "confidence": "high",
                            "scheme": "http",
                        }
                    ]
                },
            },
            "findings": [
                {
                    "id": "TEST-001",
                    "severity": "Medium",
                    "title": "Exported component",
                    "evidence": {"file": "AndroidManifest.xml"},
                    "fix": "Add permission",
                }
            ],
        },
    }


def test_persist_run_summary_tracks_session(monkeypatch, stub_string_data, baseline_payload):
    report = _make_stub_report()
    session_stamp = "20250102-020202"
    scope_label = "App=com.example.app"
    finding_totals = Counter({"Medium": 1, "High": 0, "Low": 0, "Info": 0})

    calls: dict[str, object] = {}

    def fake_create_run(**kwargs):
        calls["create_run"] = kwargs
        return 101

    def fake_write_buckets(run_id, payload):
        calls["write_buckets"] = (run_id, payload)
        return True

    def fake_write_metrics(run_id, payload, module_id=None):
        calls["write_metrics"] = (run_id, payload)
        return True

    def fake_write_contributors(run_id, rows):
        calls.setdefault("contributors_rows", rows)
        return True

    def fake_persist_findings(run_id, rows):
        calls.setdefault("findings_rows", rows)
        return True

    def fake_persist_controls(run_id, package, coverage):
        calls["control_coverage"] = {
            control_id: (entry.status if hasattr(entry, "status") else entry.get("status"))
            for control_id, entry in coverage.items()
        }

    summary_calls: dict[str, object] = {}

    def fake_sf_upsert_summary(**kwargs):
        summary_calls.update(kwargs)
        return 11

    def fake_sf_replace(summary_id, findings):
        calls["sf_replace"] = (summary_id, tuple(findings))
        return (1, len(tuple(findings)))

    string_summary_args: dict[str, object] = {}

    def fake_sa_upsert(summary_record):
        string_summary_args.update(summary_record.to_parameters())
        return 12

    monkeypatch.setattr(db_persist._dw, "create_run", fake_create_run)
    monkeypatch.setattr(db_persist._dw, "write_buckets", fake_write_buckets)
    monkeypatch.setattr(db_persist._dw, "write_metrics", fake_write_metrics)
    monkeypatch.setattr(db_persist._dw, "write_contributors", fake_write_contributors)
    monkeypatch.setattr(db_persist, "_persist_findings", fake_persist_findings)
    monkeypatch.setattr(db_persist, "_persist_masvs_controls", fake_persist_controls)

    monkeypatch.setattr(db_persist._sf, "ensure_tables", lambda: True)
    monkeypatch.setattr(db_persist._sf, "upsert_summary", fake_sf_upsert_summary)
    monkeypatch.setattr(db_persist._sf, "replace_findings", fake_sf_replace)

    monkeypatch.setattr(db_persist._sa, "ensure_tables", lambda: True)
    monkeypatch.setattr(db_persist._sa, "upsert_summary", fake_sa_upsert)
    monkeypatch.setattr(db_persist._sa, "replace_top_samples", lambda summary_id, samples, top_n=3: (0, 0))
    monkeypatch.setattr(
        db_persist.core_q,
        "run_sql",
        lambda query, params=None, fetch="none", dictionary=False: {
            "threat_profile": "Active",
            "env_profile": "enterprise",
        }
        if "SELECT threat_profile" in query
        else None,
    )

    outcome = db_persist.persist_run_summary(
        report,
        stub_string_data,
        run_package="com.example.app",
        session_stamp=session_stamp,
        scope_label=scope_label,
        finding_totals=finding_totals,
        baseline_payload=baseline_payload,
        dry_run=False,
    )

    assert outcome.success is True
    assert outcome.run_id == 101

    assert calls["create_run"]["package"] == "com.example.app"
    assert calls["create_run"]["app_label"] == "Example App"
    assert calls["create_run"]["session_stamp"] == session_stamp
    assert calls["create_run"]["threat_profile"] == "Active"
    assert calls["create_run"]["env_profile"] == "enterprise"
    assert summary_calls["session_stamp"] == session_stamp
    details_raw = summary_calls["details"]
    if isinstance(details_raw, str):
        summary_details = json.loads(details_raw)
    else:
        summary_details = details_raw
    app_details = summary_details["app"]
    assert app_details["label"] == "Example App"
    assert app_details["package"] == "com.example.app"
    assert app_details["version_name"] == "1.2.3"
    assert app_details["version_code"] == 123
    assert app_details["target_sdk"] == 33
    assert string_summary_args["run_id"] == 101
    assert string_summary_args["session_stamp"] == session_stamp
    assert calls["write_buckets"][0] == 101
    metrics_payload = calls["write_metrics"][1]
    assert "network.code_http_hosts" in metrics_payload
    assert "findings.preview_coverage_pct" in metrics_payload
    assert "findings.path_coverage_pct" in metrics_payload
    rows = calls["findings_rows"]
    assert len(rows) == 1
    row = rows[0]
    assert row["rule_id"] == "BASE-IPC-COMP-NO-ACL"
    assert row["evidence_path"] == "AndroidManifest.xml"
    assert row["evidence_preview"] == "Receiver is exported but does not declare a permission."
    assert row["cvss_v40_b_vector"]
    assert row["cvss_v40_b_score"]
    assert row["cvss_v40_bte_vector"]
    assert row["cvss_v40_bte_score"]

    assert calls["control_coverage"] == {"PLATFORM-IPC-1": "FAIL"}


def test_persist_run_summary_dry_run_skips_writes(monkeypatch, stub_string_data, baseline_payload):
    report = _make_stub_report()
    session_stamp = "20250102-020202"
    scope_label = "App=com.example.app"
    finding_totals = Counter({"Medium": 1, "High": 0, "Low": 0, "Info": 0})

    monkeypatch.setattr(
        db_persist._dw,
        "create_run",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("create_run should not be called")),
    )
    monkeypatch.setattr(
        db_persist._dw,
        "write_buckets",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("write_buckets")),
    )
    monkeypatch.setattr(
        db_persist._dw,
        "write_metrics",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("write_metrics")),
    )
    monkeypatch.setattr(
        db_persist._dw,
        "write_contributors",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("write_contributors")),
    )
    monkeypatch.setattr(
        db_persist,
        "_persist_findings",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("persist_findings")),
    )
    monkeypatch.setattr(
        db_persist,
        "_persist_masvs_controls",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("persist_controls")),
    )

    outcome = db_persist.persist_run_summary(
        report,
        stub_string_data,
        run_package="com.example.app",
        session_stamp=session_stamp,
        scope_label=scope_label,
        finding_totals=finding_totals,
        baseline_payload=baseline_payload,
        dry_run=True,
    )

    assert outcome.run_id is None
    assert outcome.success is True
