from __future__ import annotations

import json
from types import SimpleNamespace
from pathlib import Path

from scytaledroid.DynamicAnalysis.ml import evidence_pack_ml_orchestrator as orchestrator


def _run_stub(
    tmp_path: Path,
    run_id: str,
    *,
    base_sha: str | None,
    static_handoff_hash: str | None,
    include_static_features: bool = True,
):
    run_dir = tmp_path / run_id
    plan = {
        "package_name": "com.example.app",
        "version_code": "123",
        "run_identity": {
            "package_name_lc": "com.example.app",
            "version_code": "123",
            "signer_digest": "deadbeef",
            "base_apk_sha256": base_sha,
            "static_handoff_hash": static_handoff_hash,
        },
    }
    if include_static_features:
        plan["static_features"] = {
            "exported_components_total": 10,
            "dangerous_permission_count": 3,
            "uses_cleartext_traffic": False,
            "sdk_indicator_score": 0.5,
        }
    return SimpleNamespace(
        run_id=run_id,
        package_name="com.example.app",
        run_profile="interactive",
        run_dir=run_dir,
        manifest={"target": {"package_name": "com.example.app", "version_code": "123"}},
        plan=plan,
    )


def test_resolve_paper_identity_contract_valid(tmp_path: Path) -> None:
    runs = [
        _run_stub(tmp_path, "r1", base_sha="a" * 64, static_handoff_hash="b" * 64),
        _run_stub(tmp_path, "r2", base_sha="a" * 64, static_handoff_hash="b" * 64),
    ]
    identity_key, reason, details = orchestrator._resolve_paper_identity_contract(runs)  # type: ignore[arg-type]
    assert identity_key == f"base_apk_sha256:{'a' * 64}"
    assert reason is None
    assert details is None


def test_resolve_paper_identity_contract_missing_base_sha(tmp_path: Path) -> None:
    runs = [
        _run_stub(tmp_path, "r1", base_sha=None, static_handoff_hash="b" * 64),
        _run_stub(tmp_path, "r2", base_sha="a" * 64, static_handoff_hash="b" * 64),
    ]
    identity_key, reason, details = orchestrator._resolve_paper_identity_contract(runs)  # type: ignore[arg-type]
    assert identity_key is None
    assert reason == "ML_SKIPPED_MISSING_BASE_APK_SHA256"
    assert details and details.get("run_ids") == ["r1"]


def test_write_run_skip_writes_cohort_status(tmp_path: Path) -> None:
    run = _run_stub(tmp_path, "r1", base_sha="a" * 64, static_handoff_hash="b" * 64)
    orchestrator._write_run_skip(  # type: ignore[arg-type]
        run,
        frozen=False,
        reason="ML_SKIPPED_BASELINE_GATE_FAIL",
        details={"baseline_windows_total": 1},
    )
    status_path = run.run_dir / "analysis" / "ml" / "v1" / "cohort_status.json"
    payload = json.loads(status_path.read_text(encoding="utf-8"))
    assert payload["status"] == "EXCLUDED"
    assert payload["reason_code"] == "ML_SKIPPED_BASELINE_GATE_FAIL"
    assert payload["details"]["baseline_windows_total"] == 1


def test_unknown_reason_code_rejected() -> None:
    from pytest import raises

    with raises(RuntimeError, match="Unknown paper exclusion reason code"):
        orchestrator._validate_paper_reason_code("SOME_UNKNOWN_REASON")  # type: ignore[attr-defined]


def test_resolve_paper_identity_contract_missing_static_features(tmp_path: Path) -> None:
    runs = [
        _run_stub(
            tmp_path,
            "r1",
            base_sha="a" * 64,
            static_handoff_hash="b" * 64,
            include_static_features=False,
        ),
        _run_stub(
            tmp_path,
            "r2",
            base_sha="a" * 64,
            static_handoff_hash="b" * 64,
            include_static_features=True,
        ),
    ]
    identity_key, reason, details = orchestrator._resolve_paper_identity_contract(runs)  # type: ignore[arg-type]
    assert identity_key is None
    assert reason == "ML_SKIPPED_MISSING_STATIC_FEATURES"
    assert isinstance(details, dict) and "runs" in details


def test_resolve_paper_identity_contract_apk_changed(tmp_path: Path) -> None:
    run = _run_stub(tmp_path, "r1", base_sha="a" * 64, static_handoff_hash="b" * 64)
    run.manifest = {"target": {"package_name": "com.example.app", "version_code": "124"}}
    identity_key, reason, details = orchestrator._resolve_paper_identity_contract([run])  # type: ignore[arg-type]
    assert identity_key is None
    assert reason == "ML_SKIPPED_APK_CHANGED_DURING_RUN"
    assert isinstance(details, dict) and "runs" in details
