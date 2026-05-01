from __future__ import annotations

import json
from pathlib import Path

from scytaledroid.DynamicAnalysis.plans.loader import load_dynamic_plan


def test_load_dynamic_plan_enriches_legacy_static_features_and_identity(tmp_path: Path) -> None:
    plan_path = tmp_path / "legacy_plan.json"
    legacy = {
        "plan_schema_version": "v1",
        "schema_version": "0.2.6",
        "generated_at": "2026-02-21T18:50:22.803877Z",
        "package_name": "com.facebook.katana",
        "version_name": "548.1.0.51.64",
        "version_code": "468616494",
        "run_identity": {
            "artifact_set_hash": "b" * 64,
            "base_apk_sha256": "a" * 64,
            "run_signature": "c" * 64,
            "run_signature_version": "v1",
            "static_handoff_hash": "d" * 64,
            "identity_valid": True,
            "identity_error_reason": None,
        },
        "exported_components": {"total": 131},
        "permissions": {
            "declared": ["android.permission.INTERNET", "android.permission.CAMERA"],
            "dangerous": ["android.permission.CAMERA"],
            "high_value": ["android.permission.CAMERA"],
        },
        "risk_flags": {"uses_cleartext_traffic": None},
        "network_targets": {
            "domains": [],
            "cleartext_domains": [],
            "domain_sources": [],
            "domain_sources_note": "Sources are advisory signals (strings, nsc) and are not ground truth.",
        },
    }
    plan_path.write_text(json.dumps(legacy), encoding="utf-8")

    out = load_dynamic_plan(plan_path)
    ident = out.get("run_identity") or {}
    sf = out.get("static_features") or {}

    assert ident.get("package_name_lc") == "com.facebook.katana"
    assert ident.get("version_code") == "468616494"
    # Legacy fallback: signer fields are derived from run_signature when missing.
    assert ident.get("signer_digest") == ("c" * 64)
    assert ident.get("signer_set_hash") == ("c" * 64)

    assert sf.get("schema_version") == "v1"
    assert sf.get("exported_components_total") == 131
    assert sf.get("dangerous_permission_count") == 1
    assert sf.get("perm_dangerous_n") == 1
    assert sf.get("permissions_total") == 2
    assert sf.get("uses_cleartext_traffic") is False
    assert "static_risk_score" in sf
    assert sf.get("static_risk_band") in {"LOW", "MEDIUM", "HIGH"}
