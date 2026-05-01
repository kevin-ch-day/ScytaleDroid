from __future__ import annotations

from pathlib import Path

from scytaledroid.StaticAnalysis.cli.persistence.static_handoff import (
    build_static_handoff,
    persist_static_handoff,
)
from scytaledroid.StaticAnalysis.core import (
    ManifestFlags,
    ManifestSummary,
    PermissionSummary,
    StaticAnalysisReport,
)


def _sample_report() -> StaticAnalysisReport:
    return StaticAnalysisReport(
        file_path="/tmp/app.apk",
        relative_path=None,
        file_name="app.apk",
        file_size=1,
        hashes={"sha256": "b" * 64},
        manifest=ManifestSummary(package_name="com.example.app", version_code="123"),
        manifest_flags=ManifestFlags(
            uses_cleartext_traffic=True,
            allow_backup=True,
            request_legacy_external_storage=False,
            network_security_config="@xml/network_security_config",
        ),
        permissions=PermissionSummary(
            declared=(
                "android.permission.INTERNET",
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION",
            ),
            dangerous=(
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION",
            ),
        ),
        detector_metrics={
            "ipc_components": {"exported_without_permission": 3},
            "provider_acl": {"without_permissions": 2},
            "storage_surface": {"fileproviders": 1},
            "network_surface": {"cleartext_permitted": True, "cleartext_domain_count": 2},
        },
        analysis_matrices={"severity_by_category": {"NETWORK": {"High": 1}}},
    )


def test_static_handoff_hash_is_deterministic(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    payload = build_static_handoff(
        report=_sample_report(),
        string_data={},
        package_name="com.example.app",
        version_code=123,
        base_apk_sha256="a" * 64,
        artifact_set_hash="c" * 64,
        static_run_id=9,
        session_label="20260219",
        tool_semver="2.0.1",
        tool_git_commit="deadbeef",
        schema_version="0.2.6",
    )
    h1 = persist_static_handoff(static_run_id=9, handoff_payload=payload)
    h2 = persist_static_handoff(static_run_id=9, handoff_payload=payload)
    assert h1 == h2
    assert payload["masvs"]["masvs_mapping_hash"]
    out_path = Path("evidence/static_runs/9/static_handoff.json")
    assert out_path.exists()


def test_static_handoff_secret_candidates_are_redacted_shape():
    payload = build_static_handoff(
        report=_sample_report(),
        string_data={
            "selected_samples": {
                "api_keys": [
                    {"value_masked": "AKIA...ZZ", "sample_hash": "h1", "src": "classes.dex"},
                ]
            }
        },
        package_name="com.example.app",
        version_code=123,
        base_apk_sha256="a" * 64,
        artifact_set_hash="c" * 64,
        static_run_id=9,
        session_label="20260219",
        tool_semver="2.0.1",
        tool_git_commit="deadbeef",
        schema_version="0.2.6",
    )
    secrets = payload["strings"]["secret_candidates_redacted"]
    assert isinstance(secrets, list)
    assert secrets
    assert "value_redacted" in secrets[0]
    assert "value_hash" in secrets[0]
    assert "value" not in secrets[0]
