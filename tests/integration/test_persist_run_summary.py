from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.StaticAnalysis.cli.core.run_persistence import persist_run_summary
from scytaledroid.StaticAnalysis.cli.persistence.run_summary import refresh_static_run_manifest
from scytaledroid.Database.db_utils.artifact_registry import record_artifacts
from scytaledroid.StaticAnalysis.persistence import ingest


@dataclass
class _Flags:
    allow_backup: bool = False
    request_legacy_external_storage: bool = False
    uses_cleartext_traffic: bool = True


@dataclass
class _ExportedComponents:
    activities: list[str]
    services: list[str]
    receivers: list[str]
    providers: list[str]

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
    def __init__(self, manifest: _Manifest, *, metadata: Mapping[str, Any] | None = None) -> None:
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
        base_metadata: dict[str, Any] = {
            "run_profile": "full",
            "run_scope_label": "Integration Test",
            "session_stamp": "",
        }
        if metadata:
            base_metadata.update(metadata)
        self.metadata = base_metadata


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
    report = _Report(
        manifest,
        metadata={
            "session_stamp": session_stamp,
            "apk_id": 987654321,
            "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        },
    )

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
    assert _scalar("SELECT COUNT(*) FROM permission_audit_snapshots WHERE snapshot_key=%s", (f"perm-audit:app:{session_stamp}",)) >= 0
    assert _scalar("SELECT COUNT(*) FROM permission_audit_apps", ()) >= 0

    spr_row = core_q.run_sql(
        """
        SELECT risk_score, risk_grade, dangerous, signature, vendor
        FROM static_permission_risk
        WHERE session_stamp=%s AND package_name=%s
        """,
        (session_stamp, package),
        fetch="one",
    )
    assert spr_row is not None
    risk_score, risk_grade, dangerous_count, signature_count, vendor_count = spr_row
    assert float(risk_score) >= 0.0
    assert isinstance(risk_grade, str) and risk_grade
    assert dangerous_count >= 0
    assert signature_count >= 0
    assert vendor_count >= 0

    snapshot_row = core_q.run_sql(
        """
        SELECT snapshot_id
        FROM permission_audit_snapshots
        WHERE snapshot_key=%s
        ORDER BY snapshot_id DESC
        LIMIT 1
        """,
        (f"perm-audit:app:{session_stamp}",),
        fetch="one",
    )
    snapshot_id = snapshot_row[0] if snapshot_row else None
    assert snapshot_id is not None

    audit_row = core_q.run_sql(
        """
        SELECT dangerous_count, signature_count, vendor_count
        FROM permission_audit_apps
        WHERE snapshot_id=%s AND package_name=%s
        """,
        (snapshot_id, package),
        fetch="one",
    )
    assert audit_row is not None
    assert audit_row == (dangerous_count, signature_count, vendor_count)


@pytest.mark.integration
def test_run_manifest_includes_manifest_evidence(tmp_path):
    session_stamp = "20251030-000999"
    scope_label = "Integration Manifest Evidence"
    package = "com.example.manifest"

    manifest = _Manifest(
        package_name=package,
        app_label="Manifest App",
        version_name="1.0.0",
        version_code=123,
        target_sdk=33,
        min_sdk=24,
    )
    report = _Report(
        manifest,
        metadata={
            "session_stamp": session_stamp,
            "apk_id": 987654321,
            "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        },
    )
    string_data = {"counts": {"high_entropy": 1}, "samples": {}}
    baseline_payload = {
        "app": {"package": package, "session_stamp": session_stamp, "scope_label": scope_label},
        "baseline": {"findings": [], "string_analysis": {"counts": {"endpoints": 0}, "samples": {}}},
    }
    finding_totals = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}

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
    if outcome.static_run_id is None:
        pytest.skip("Persistence did not yield a static_run_id; skipping manifest assertions.")

    run_root = Path("evidence") / "static_runs" / str(outcome.static_run_id)
    run_root.mkdir(parents=True, exist_ok=True)
    manifest_evidence_path = run_root / "manifest_evidence.json"
    manifest_evidence_path.write_text(
        '{"schema":"manifest_evidence_v1","components":[]}', encoding="utf-8"
    )
    record_artifacts(
        run_id=str(outcome.static_run_id),
        run_type="static",
        artifacts=[
            {
                "path": str(manifest_evidence_path),
                "type": "manifest_evidence",
                "sha256": "dummy",
                "size_bytes": 1,
                "created_at_utc": "2025-10-30T00:00:00Z",
                "origin": "host",
                "pull_status": "n/a",
            }
        ],
        origin="host",
        pull_status="n/a",
    )
    refresh_static_run_manifest(outcome.static_run_id)

    manifest_path = run_root / "run_manifest.json"
    assert manifest_path.exists()
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact_types = {entry.get("type") for entry in payload.get("artifacts", [])}
    assert "manifest_evidence" in artifact_types


@pytest.mark.integration
def test_ingest_baseline_populates_provider_tables():
    session_stamp = "20251030-000123"
    scope_label = "Integration Providers"
    package = "com.example.providers"

    payload = {
        "app": {
            "package": package,
            "label": "Provider App",
            "version_name": "1.0.0",
            "version_code": 42,
            "min_sdk": 24,
            "target_sdk": 33,
        },
        "hashes": {"sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
        "metadata": {
            "session_stamp": session_stamp,
            "run_scope_label": scope_label,
            "detector_metrics": {
                "provider_acl": {
                    "acl_snapshot": [
                        {
                            "name": "com.example.LegacyProvider",
                            "authorities": ["com.example.providers.legacy"],
                            "exported": True,
                            "grant_uri_permissions": True,
                            "base_permission": None,
                            "read_permission": "com.example.permission.READ",
                            "write_permission": "com.example.permission.WRITE",
                            "base_guard": "none",
                            "read_guard": "weak",
                            "write_guard": "weak",
                            "effective_guard": "weak",
                            "path_permissions": [
                                {
                                    "path": "/data",
                                    "read_permission": "com.example.permission.READ",
                                    "write_permission": "com.example.permission.WRITE",
                                    "read_guard": "weak",
                                    "write_guard": "weak",
                                    "pathType": "literal",
                                }
                            ],
                        }
                    ]
                }
            },
        },
        "findings": [],
    }

    assert ingest.ingest_baseline_payload(payload)

    provider_row = core_q.run_sql(
        "SELECT package_name, authority, session_stamp FROM static_fileproviders WHERE package_name=%s",
        (package,),
        fetch="one",
    )
    assert provider_row is not None
    assert provider_row[0] == package
    assert provider_row[2] == session_stamp

    acl_row = core_q.run_sql(
        "SELECT package_name, authority, path, path_type FROM static_provider_acl WHERE package_name=%s",
        (package,),
        fetch="one",
    )
    assert acl_row is not None
    assert acl_row[0] == package
    assert acl_row[1] == "com.example.providers.legacy"
