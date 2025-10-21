from __future__ import annotations

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
        masvs_coverage=[("BASE-IPC-COMP-NO-ACL", {"location": "AndroidManifest.xml"})],
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

    def fake_prepare_run_envelope(**kwargs):
        calls["prepare_run_envelope"] = kwargs
        envelope = SimpleNamespace(
            run_id=101,
            app_label="Example App",
            target_sdk=33,
            threat_profile="Active",
            env_profile="enterprise",
        )
        return envelope, []

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

    static_calls: dict[str, object] = {}

    def fake_persist_static_findings(**kwargs):
        static_calls.setdefault("static_findings", kwargs)
        return []

    def fake_persist_string_summary(**kwargs):
        static_calls.setdefault("string_summary", kwargs)
        return []

    monkeypatch.setattr(db_persist, "prepare_run_envelope", fake_prepare_run_envelope)
    monkeypatch.setattr(db_persist, "write_buckets", fake_write_buckets)
    monkeypatch.setattr(db_persist, "write_metrics", fake_write_metrics)
    monkeypatch.setattr(db_persist, "write_contributors", fake_write_contributors)
    monkeypatch.setattr(db_persist, "persist_findings", fake_persist_findings)
    monkeypatch.setattr(db_persist, "persist_masvs_controls", fake_persist_controls)
    monkeypatch.setattr(db_persist, "persist_static_findings", fake_persist_static_findings)
    monkeypatch.setattr(db_persist, "persist_string_summary", fake_persist_string_summary)
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

    envelope_call = calls["prepare_run_envelope"]
    assert envelope_call["session_stamp"] == session_stamp
    assert envelope_call["run_package"] == "com.example.app"
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
    assert static_calls["static_findings"]["session_stamp"] == session_stamp
    assert static_calls["string_summary"]["session_stamp"] == session_stamp


def test_persist_run_summary_dry_run_skips_writes(monkeypatch, stub_string_data, baseline_payload):
    report = _make_stub_report()
    session_stamp = "20250102-020202"
    scope_label = "App=com.example.app"
    finding_totals = Counter({"Medium": 1, "High": 0, "Low": 0, "Info": 0})

    monkeypatch.setattr(
        db_persist,
        "prepare_run_envelope",
        lambda **kwargs: (SimpleNamespace(run_id=None, threat_profile="T", env_profile="E"), []),
    )
    monkeypatch.setattr(
        db_persist,
        "write_buckets",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("write_buckets")),
    )
    monkeypatch.setattr(
        db_persist,
        "write_metrics",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("write_metrics")),
    )
    monkeypatch.setattr(
        db_persist,
        "write_contributors",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("write_contributors")),
    )
    monkeypatch.setattr(
        db_persist,
        "persist_findings",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("persist_findings")),
    )
    monkeypatch.setattr(
        db_persist,
        "persist_masvs_controls",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("persist_controls")),
    )
    monkeypatch.setattr(
        db_persist,
        "persist_static_findings",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("persist_static")),
    )
    monkeypatch.setattr(
        db_persist,
        "persist_string_summary",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("persist_strings")),
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
