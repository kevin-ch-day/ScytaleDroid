from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.ml.evidence_pack_ml_preflight import RunInputs
from scytaledroid.DynamicAnalysis.ml.freeze_profile.identity_contract import (
    normalize_hex_hash,
    resolve_paper_identity_contract,
)


def _run(
    tmp_path: Path,
    run_id: str,
    *,
    package: str = "com.example.app",
    version: str = "1",
    base_sha: str = "a" * 64,
    artifact_hash: str = "b" * 64,
    signer_hash: str = "c" * 64,
    static_hash: str = "d" * 64,
    target_package: str | None = None,
    target_version: str | None = None,
    static_features: dict | None = None,
) -> RunInputs:
    return RunInputs(
        run_id=run_id,
        run_dir=tmp_path / run_id,
        manifest={"target": {"package_name": target_package or package, "version_code": target_version or version}},
        plan={
            "package_name": package,
            "version_code": version,
            "run_identity": {
                "package_name_lc": package,
                "version_code": version,
                "base_apk_sha256": base_sha,
                "artifact_set_hash": artifact_hash,
                "signer_set_hash": signer_hash,
                "signer_digest": signer_hash,
                "static_handoff_hash": static_hash,
            },
            "static_features": static_features
            if static_features is not None
            else {
                "exported_components_total": 1,
                "dangerous_permission_count": 2,
                "uses_cleartext_traffic": False,
                "sdk_indicator_score": 0.0,
            },
        },
        summary={},
        pcap_report={},
        pcap_features={},
        pcap_path=None,
        identity_key=f"{package}:{version}",
        package_name=package,
        run_profile="baseline",
    )


def test_normalize_hex_hash_rejects_bad_identity_values() -> None:
    assert normalize_hex_hash("A" * 64, expected_len=64) == "a" * 64
    assert normalize_hex_hash("g" * 64, expected_len=64) is None
    assert normalize_hex_hash("a" * 63, expected_len=64) is None


def test_identity_contract_accepts_consistent_app_build_group(tmp_path: Path) -> None:
    key, reason, details = resolve_paper_identity_contract([_run(tmp_path, "r1"), _run(tmp_path, "r2")])

    assert key == "base_apk_sha256:" + "a" * 64
    assert reason is None
    assert details is None


def test_identity_contract_blocks_missing_static_features(tmp_path: Path) -> None:
    key, reason, details = resolve_paper_identity_contract([_run(tmp_path, "r1", static_features={})])

    assert key is None
    assert reason == "ML_SKIPPED_MISSING_STATIC_FEATURES"
    assert details == {
        "runs": {
            "r1": [
                "exported_components_total",
                "dangerous_permission_count",
                "uses_cleartext_traffic",
                "sdk_indicator_score",
            ]
        }
    }


def test_identity_contract_blocks_apk_drift_against_manifest_target(tmp_path: Path) -> None:
    key, reason, details = resolve_paper_identity_contract([_run(tmp_path, "r1", target_version="2")])

    assert key is None
    assert reason == "ML_SKIPPED_APK_CHANGED_DURING_RUN"
    assert details == {"runs": {"r1": {"expected_version_code": "1", "observed_version_code": "2"}}}


def test_identity_contract_blocks_mixed_artifact_sets(tmp_path: Path) -> None:
    key, reason, details = resolve_paper_identity_contract(
        [_run(tmp_path, "r1", artifact_hash="b" * 64), _run(tmp_path, "r2", artifact_hash="e" * 64)]
    )

    assert key is None
    assert reason == "ML_SKIPPED_APK_CHANGED_DURING_RUN"
    assert details == {"conflicting_artifact_set_hash": ["b" * 64, "e" * 64]}


def test_identity_contract_allows_signer_metadata_variation_when_apk_identity_matches(tmp_path: Path) -> None:
    key, reason, details = resolve_paper_identity_contract(
        [_run(tmp_path, "r1", signer_hash="c" * 64), _run(tmp_path, "r2", signer_hash="f" * 64)]
    )

    assert key == "base_apk_sha256:" + "a" * 64
    assert reason is None
    assert details is None
