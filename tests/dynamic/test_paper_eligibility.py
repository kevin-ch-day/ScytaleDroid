from __future__ import annotations

from scytaledroid.DynamicAnalysis.paper_eligibility import derive_paper_eligibility


def _manifest(*, run_profile: str = "interaction_scripted", valid: bool = True, wc: int | None = 25, cpv: int = 1):
    dataset = {"valid_dataset_run": valid, "run_profile": run_profile}
    if wc is not None:
        dataset["window_count"] = wc
    operator = {"run_profile": run_profile, "capture_policy_version": cpv}
    if run_profile == "interaction_scripted":
        operator.update(
            {
                "script_hash": "e" * 64,
                "script_exit_code": 0,
                "script_end_marker": True,
                "step_count_planned": 4,
                "step_count_completed": 4,
                "script_timing_within_tolerance": True,
            }
        )
    return {
        "dataset": dataset,
        "operator": operator,
        "target": {"package_name": "com.example.app", "version_code": "123"},
    }


def _plan(*, with_identity: bool = True, with_static: bool = True):
    ident = {"version_code": "123"}
    if with_identity:
        ident.update(
            {
                "base_apk_sha256": "a" * 64,
                "artifact_set_hash": "b" * 64,
                "signer_set_hash": "c" * 64,
            }
        )
    if with_static:
        ident["static_handoff_hash"] = "d" * 64
    return {"run_identity": ident}


def test_paper_eligibility_happy_path() -> None:
    out = derive_paper_eligibility(
        manifest=_manifest(),
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is True
    assert out.reason_code is None


def test_paper_eligibility_manual_is_excluded() -> None:
    out = derive_paper_eligibility(
        manifest=_manifest(run_profile="interaction_manual"),
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_MANUAL_NON_COHORT"


def test_paper_eligibility_window_missing_precedence() -> None:
    out = derive_paper_eligibility(
        manifest=_manifest(wc=None),
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_WINDOW_COUNT_MISSING"


def test_paper_eligibility_policy_mismatch_precedence_over_window() -> None:
    out = derive_paper_eligibility(
        manifest=_manifest(wc=10, cpv=2),
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    # per precedence, policy mismatch outranks window issues
    assert out.reason_code == "EXCLUDED_POLICY_VERSION_MISMATCH"


def test_paper_eligibility_missing_required_identity_field() -> None:
    out = derive_paper_eligibility(
        manifest=_manifest(),
        plan=_plan(with_identity=False),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_MISSING_REQUIRED_IDENTITY_FIELD"


def test_paper_eligibility_script_end_missing() -> None:
    manifest = _manifest()
    manifest["operator"]["script_end_marker"] = False
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_SCRIPT_END_MISSING"


def test_paper_eligibility_script_step_mismatch() -> None:
    manifest = _manifest()
    manifest["operator"]["step_count_completed"] = 3
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_SCRIPT_STEP_MISSING"
