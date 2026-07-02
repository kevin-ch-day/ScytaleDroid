from __future__ import annotations

from scytaledroid.DynamicAnalysis.paper_eligibility import derive_paper_eligibility


def _manifest(*, package: str, template_id: str, valid_dataset_run: bool = True) -> dict[str, object]:
    identity = {
        "version_code": "123",
        "base_apk_sha256": "a" * 64,
        "artifact_set_hash": "b" * 64,
        "signer_set_hash": "c" * 64,
    }
    return {
        "dataset": {
            "valid_dataset_run": valid_dataset_run,
            "run_profile": "interaction_scripted",
            "window_count": 36,
        },
        "operator": {
            "capture_policy_version": 2,
            "run_profile": "interaction_scripted",
            "interaction_protocol_version": 2,
            "template_id": template_id,
            "scenario_template": template_id,
            "script_hash": "d" * 64,
            "script_exit_code": 0,
            "script_end_marker": True,
            "step_count_planned": 6,
            "step_count_completed": 6,
        },
        "target": {
            "package_name": package,
            "run_identity": identity,
            "static_handoff_hash": "e" * 64,
        },
    }


def _plan(*, package: str) -> dict[str, object]:
    return {
        "package_name": package,
        "run_identity": {
            "package_name_lc": package.lower(),
            "version_code": "123",
            "base_apk_sha256": "a" * 64,
            "artifact_set_hash": "b" * 64,
            "signer_set_hash": "c" * 64,
            "static_handoff_hash": "e" * 64,
        },
    }


def test_superseded_news_template_remains_eligible_for_current_successor() -> None:
    result = derive_paper_eligibility(
        manifest=_manifest(package="bbc.mobile.news.ww", template_id="news_reader_basic_v1"),
        plan=_plan(package="bbc.mobile.news.ww"),
        min_windows=20,
        required_capture_policy_version=2,
    )

    assert result.paper_eligible is True
    assert "EXCLUDED_SCRIPT_TEMPLATE_MISMATCH" not in result.all_reason_codes


def test_superseded_facebook_template_remains_eligible_for_current_successor() -> None:
    result = derive_paper_eligibility(
        manifest=_manifest(package="com.facebook.katana", template_id="facebook_basic_v2"),
        plan=_plan(package="com.facebook.katana"),
        min_windows=20,
        required_capture_policy_version=2,
    )

    assert result.paper_eligible is True
    assert "EXCLUDED_SCRIPT_TEMPLATE_MISMATCH" not in result.all_reason_codes


def test_unrelated_template_mismatch_still_excluded() -> None:
    result = derive_paper_eligibility(
        manifest=_manifest(package="com.facebook.katana", template_id="news_reader_basic_v1"),
        plan=_plan(package="com.facebook.katana"),
        min_windows=20,
        required_capture_policy_version=2,
    )

    assert result.paper_eligible is False
    assert result.reason_code == "EXCLUDED_SCRIPT_TEMPLATE_MISMATCH"
