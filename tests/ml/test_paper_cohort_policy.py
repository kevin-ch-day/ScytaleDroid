from __future__ import annotations

import json
from types import SimpleNamespace
from pathlib import Path

from scytaledroid.DynamicAnalysis.ml import evidence_pack_ml_orchestrator as orchestrator


def _run_stub(tmp_path: Path, run_id: str, *, base_sha: str | None, static_handoff_hash: str | None):
    run_dir = tmp_path / run_id
    return SimpleNamespace(
        run_id=run_id,
        package_name="com.example.app",
        run_profile="interactive",
        run_dir=run_dir,
        plan={"run_identity": {"base_apk_sha256": base_sha, "static_handoff_hash": static_handoff_hash}},
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
