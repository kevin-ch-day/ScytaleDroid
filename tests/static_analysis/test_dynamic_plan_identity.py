from __future__ import annotations

from scytaledroid.DeviceAnalysis.identity import compute_signer_set_hash
from scytaledroid.StaticAnalysis.cli.views.renderers.dynamic_plan import build_dynamic_plan
from scytaledroid.StaticAnalysis.core import (
    ComponentSummary,
    ManifestFlags,
    ManifestSummary,
    PermissionSummary,
    StaticAnalysisReport,
)


def test_build_dynamic_plan_uses_canonical_signer_set_hash() -> None:
    signatures = (
        "BB" * 32,
        "aa" * 32,
    )
    report = StaticAnalysisReport(
        file_path="/tmp/example.apk",
        relative_path="example.apk",
        file_name="example.apk",
        file_size=123,
        hashes={"sha256": "f" * 64},
        manifest=ManifestSummary(package_name="com.example.app", version_name="1.0", version_code="123"),
        manifest_flags=ManifestFlags(),
        permissions=PermissionSummary(),
        components=ComponentSummary(),
        exported_components=ComponentSummary(),
        signatures=signatures,
        metadata={
            "package": "com.example.app",
            "version_name": "1.0",
            "version_code": "123",
            "base_apk_sha256": "a" * 64,
            "artifact_set_hash": "b" * 64,
            "apk_set_id": 44,
            "run_signature": "c" * 64,
            "run_signature_version": "v1",
            "static_handoff_hash": "d" * 64,
            "identity_valid": True,
            "identity_error_reason": None,
        },
    )

    plan = build_dynamic_plan(report, {"aggregates": {}, "selected_samples": {}})
    identity = plan["run_identity"]

    expected_hash = compute_signer_set_hash(signatures)

    assert identity["signer_primary_digest"] == ("aa" * 32)
    assert identity["signer_set_hash"] == expected_hash
    assert identity["signer_digest"] == expected_hash


def test_build_dynamic_plan_uses_merged_split_domain_payload() -> None:
    report = StaticAnalysisReport(
        file_path="/tmp/example.apk",
        relative_path="example.apk",
        file_name="example.apk",
        file_size=123,
        hashes={"sha256": "f" * 64},
        manifest=ManifestSummary(package_name="com.example.split", version_name="1.0", version_code="123"),
        manifest_flags=ManifestFlags(),
        permissions=PermissionSummary(),
        components=ComponentSummary(),
        exported_components=ComponentSummary(),
        signatures=("aa" * 32,),
        metadata={
            "package": "com.example.split",
            "version_name": "1.0",
            "version_code": "123",
            "base_apk_sha256": "a" * 64,
            "artifact_set_hash": "b" * 64,
            "apk_set_id": 44,
            "run_signature": "c" * 64,
            "run_signature_version": "v1",
            "static_handoff_hash": "d" * 64,
            "identity_valid": True,
            "identity_error_reason": None,
        },
    )

    payload = {
        "baseline": {
            "string_analysis": {
                "aggregation_scope": "artifact_merged",
                "aggregates": {
                    "endpoint_roots": [
                        {
                            "root_domain": "base.example.com",
                            "total": 2,
                            "schemes": {"https": 2},
                            "source_types": ["code"],
                        },
                        {
                            "root_domain": "feature.example.com",
                            "total": 1,
                            "schemes": {"http": 1},
                            "source_types": ["code"],
                        },
                    ],
                    "endpoint_cleartext": [
                        {
                            "value": "http://feature.example.com/api",
                            "src": "split_config.feature",
                            "root_domain": "feature.example.com",
                            "scheme": "http",
                            "risk_tag": "http_cleartext",
                            "confidence": "high",
                        }
                    ],
                },
                "selected_samples": {},
                "samples": {
                    "api_keys": [
                        {
                            "value": "AIza0123456789abcdefghijklmnopqrstuvwxy",
                            "src": "classes.dex",
                            "root_domain": "base.example.com",
                            "posture": "actionable",
                            "ownership_class": "first_party",
                            "api_context": "auth_flow",
                            "pair_group": "google:token_endpoint_family",
                            "verification_status": "supported_opt_in",
                        }
                    ],
                    "endpoints": [
                        {
                            "value": "https://feature.example.com/api",
                            "src": "split_config.feature",
                            "root_domain": "feature.example.com",
                            "posture": "exploratory",
                            "ownership_class": "unknown_third_party",
                            "api_context": "network_target",
                            "pair_group": "",
                            "verification_status": "unverified",
                        }
                    ],
                },
            }
        }
    }

    plan = build_dynamic_plan(report, payload)
    network = plan["network_targets"]

    assert network["domains"] == ["base.example.com", "feature.example.com"]
    assert network["cleartext_domains"] == ["feature.example.com"]
    assert network["domain_sources"][0]["postures"] == ["actionable"]
    assert network["domain_sources"][0]["pair_groups"] == ["google:token_endpoint_family"]
    assert "strings" in network["domain_sources"][0]["sources"]
