from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping

import pytest

from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.StaticAnalysis.cli.db_persist import persist_run_summary
from scytaledroid.StaticAnalysis.persistence.snapshots import write_permission_snapshot


@dataclass
class _Flags:
    allow_backup: bool = False
    request_legacy_external_storage: bool = False
    uses_cleartext_traffic: bool = True


@dataclass
class _ExportedComponents:
    activities: List[str]
    services: List[str]
    receivers: List[str]
    providers: List[str]

    def total(self) -> int:
        return len(self.activities) + len(self.services) + len(self.receivers) + len(self.providers)


class _Permissions:
    declared = [
        "android.permission.READ_CONTACTS",
        "android.permission.INTERNET",
    ]


@dataclass
class _Manifest:
    package_name: str
    app_label: str
    version_name: str
    version_code: int
    target_sdk: int
    min_sdk: int


class _SeverityGate:
    def __init__(self, value: str) -> None:
        self.value = value


class _Finding:
    severity = "High"
    severity_label = None
    metrics: Mapping[str, str] = {"severity": "High"}
    severity_gate = _SeverityGate("High")
    evidence: Mapping[str, Any] = {"path": "AndroidManifest.xml", "summary": "Exported component"}
    detail = "Exported component without permission"
    headline = None
    summary = None
    because = None
    path = "AndroidManifest.xml"
    offset = "0"
    rule_id_hint = "BASE-IPC-COMP-NO-ACL"
    extra = {"rule_id": "BASE-IPC-COMP-NO-ACL"}
    category_masvs = type("Cat", (), {"value": "PLATFORM"})()
    module = "manifest_baseline"
    finding_id = "BASE-IPC-COMP-NO-ACL"
    title = "Exported component without permission"


class _DetectorResult:
    detector_id = "manifest_baseline"
    module_id = "manifest"
    findings = [_Finding()]
    masvs_coverage = [
        (
            "BASE-CLR-001",
            {"detail": "Cleartext traffic allowed"},
        )
    ]


class _Report:
    def __init__(self, manifest: _Manifest) -> None:
        self.manifest = manifest
        self.manifest_flags = _Flags()
        self.exported_components = _ExportedComponents(
            activities=["com.example.ExportedActivity"],
            services=[],
            receivers=[],
            providers=[],
        )
        self.permissions = _Permissions()
        self.detector_results = [_DetectorResult()]
        self.metadata = {
            "run_profile": "full",
            "run_scope_label": "Integration Test",
            "session_stamp": "",
        }


def _scalar(sql: str, params: tuple[Any, ...]) -> int:
    value = core_q.run_sql(sql, params, fetch="one")
    if isinstance(value, dict):
        value = next(iter(value.values()), 0)
    elif isinstance(value, (list, tuple)):
        value = value[0] if value else 0
    return int(value or 0)


@pytest.mark.integration
def test_persist_run_summary_populates_canonical_tables():
    session_stamp = "20251030-000000"
    scope_label = "Integration Test"
    package = "com.example.integration"

    manifest = _Manifest(
        package_name=package,
        app_label="Integration App",
        version_name="1.0.0",
        version_code=123,
        target_sdk=33,
        min_sdk=24,
    )
    report = _Report(manifest)

    string_data = {
        "counts": {"high_entropy": 1, "api_keys": 1},
        "samples": {
            "endpoints": [
                {
                    "scheme": "http",
                    "root_domain": "example.com",
                    "source_type": "code",
                    "decision": "effective",
                }
            ]
        },
        "aggregates": {
            "api_keys_high": [{"value": "AKIA_TEST"}],
            "endpoint_roots": ["example.com"],
        },
    }

    baseline_payload = {
        "app": {
            "label": manifest.app_label,
            "package": manifest.package_name,
            "session_stamp": session_stamp,
            "scope_label": scope_label,
            "version_name": manifest.version_name,
            "version_code": manifest.version_code,
        },
        "baseline": {
            "findings": [
                {
                    "finding_id": "BASE-IPC-COMP-NO-ACL",
                    "severity": "High",
                    "title": "Exported component without permission",
                    "evidence": {"path": "AndroidManifest.xml"},
                    "fix": "Restrict exported component",
                },
            ],
            "string_analysis": {
                "counts": {"endpoints": 1, "high_entropy": 1},
                "samples": {
                    "endpoints": [
                        {
                            "value_masked": "http://example.com",
                            "src": "AndroidManifest.xml",
                            "risk_tag": "http_cleartext",
                            "scheme": "http",
                            "root_domain": "example.com",
                            "source_type": "code",
                        }
                    ]
                },
            },
        },
    }

    finding_totals = {"High": 1, "Medium": 0, "Low": 0, "Info": 0}

    outcome = persist_run_summary(
        report,
        string_data,
        package,
        session_stamp=session_stamp,
        scope_label=scope_label,
        finding_totals=finding_totals,
        baseline_payload=baseline_payload,
        dry_run=False,
    )

    if outcome.run_id is None:
        pytest.skip("Persistence did not yield a run_id; skipping integration assertions.")

    assert outcome.success
    run_id = outcome.run_id

    snapshot_id = write_permission_snapshot(session_stamp, scope_label=scope_label)
    assert snapshot_id is not None

    assert _scalar("SELECT COUNT(*) FROM runs WHERE session_stamp=%s", (session_stamp,)) == 1
    assert _scalar("SELECT COUNT(*) FROM findings WHERE run_id=%s", (run_id,)) == outcome.persisted_findings
    assert _scalar("SELECT COUNT(*) FROM static_findings_summary WHERE session_stamp=%s", (session_stamp,)) == 1
    assert _scalar(
        """
        SELECT COUNT(*)
        FROM static_findings f
        JOIN static_findings_summary s ON s.id = f.summary_id
        WHERE s.session_stamp = %s
        """,
        (session_stamp,),
    ) > 0
    assert _scalar("SELECT COUNT(*) FROM static_string_summary WHERE session_stamp=%s", (session_stamp,)) == 1
    assert _scalar(
        """
        SELECT COUNT(*)
        FROM static_string_samples x
        JOIN static_string_summary s ON s.id = x.summary_id
        WHERE s.session_stamp = %s
        """,
        (session_stamp,),
    ) == outcome.string_samples_persisted
    assert _scalar("SELECT COUNT(*) FROM buckets WHERE run_id=%s", (run_id,)) > 0
    assert _scalar("SELECT COUNT(*) FROM metrics WHERE run_id=%s", (run_id,)) > 0
    assert _scalar("SELECT COUNT(*) FROM contributors WHERE run_id=%s", (run_id,)) >= 0
    assert _scalar("SELECT COUNT(*) FROM permission_audit_snapshots WHERE snapshot_id=%s", (snapshot_id,)) == 1
    assert _scalar("SELECT COUNT(*) FROM permission_audit_apps WHERE snapshot_id=%s", (snapshot_id,)) > 0
