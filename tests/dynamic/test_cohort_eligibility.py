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
                "template_id": "social_feed_basic_v2",
                "scenario_template": "social_feed_basic_v2",
                "interaction_protocol_version": 2,
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


def test_paper_eligibility_manual_is_allowed() -> None:
    out = derive_paper_eligibility(
        manifest=_manifest(run_profile="interaction_manual"),
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is True
    assert out.reason_code is None


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


def test_paper_eligibility_script_template_mismatch() -> None:
    manifest = _manifest()
    manifest["operator"]["template_id"] = "messaging_basic_v1"
    manifest["operator"]["scenario_template"] = "messaging_basic_v1"
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_SCRIPT_TEMPLATE_MISMATCH"


def test_paper_eligibility_script_timing_drift_is_warning_only() -> None:
    manifest = _manifest()
    manifest["operator"]["script_timing_within_tolerance"] = False
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is True
    assert out.reason_code is None


def test_paper_eligibility_social_template_v2_allowed() -> None:
    manifest = _manifest()
    manifest["operator"]["scenario_template"] = "social_feed_basic_v2"
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is True


def test_paper_eligibility_snapchat_template_allowed() -> None:
    manifest = _manifest()
    manifest["target"]["package_name"] = "com.snapchat.android"
    manifest["operator"]["template_id"] = "snapchat_basic_v1"
    manifest["operator"]["scenario_template"] = "snapchat_basic_v1"
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is True


def test_paper_eligibility_snapchat_wrong_template_excluded() -> None:
    manifest = _manifest()
    manifest["target"]["package_name"] = "com.snapchat.android"
    manifest["operator"]["template_id"] = "social_feed_basic_v2"
    manifest["operator"]["scenario_template"] = "social_feed_basic_v2"
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_SCRIPT_TEMPLATE_MISMATCH"


def test_paper_eligibility_x_twitter_template_allowed() -> None:
    manifest = _manifest()
    manifest["target"]["package_name"] = "com.twitter.android"
    manifest["operator"]["template_id"] = "x_twitter_full_session_v1"
    manifest["operator"]["scenario_template"] = "x_twitter_full_session_v1"
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is True


def test_paper_eligibility_x_wrong_template_excluded() -> None:
    manifest = _manifest()
    manifest["target"]["package_name"] = "com.twitter.android"
    manifest["operator"]["template_id"] = "social_feed_basic_v2"
    manifest["operator"]["scenario_template"] = "social_feed_basic_v2"
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_SCRIPT_TEMPLATE_MISMATCH"


def test_paper_eligibility_whatsapp_template_allowed() -> None:
    manifest = _manifest()
    manifest["target"]["package_name"] = "com.whatsapp"
    manifest["operator"]["template_id"] = "whatsapp_basic_v1"
    manifest["operator"]["scenario_template"] = "whatsapp_basic_v1"
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is True


def test_paper_eligibility_facebook_template_allowed() -> None:
    manifest = _manifest()
    manifest["target"]["package_name"] = "com.facebook.katana"
    manifest["operator"]["template_id"] = "facebook_basic_v2"
    manifest["operator"]["scenario_template"] = "facebook_basic_v2"
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is True


def test_paper_eligibility_legacy_template_is_excluded() -> None:
    manifest = _manifest()
    manifest["operator"]["template_id"] = "social_feed_basic"
    manifest["operator"]["scenario_template"] = "social_feed_basic"
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_PROTOCOL_LEGACY_TEMPLATE"


def test_paper_eligibility_protocol_fit_poor_does_not_exclude() -> None:
    manifest = _manifest()
    manifest["operator"]["protocol_fit"] = "poor"
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is True
    assert out.reason_code is None


def test_paper_eligibility_script_send_is_excluded() -> None:
    manifest = _manifest()
    manifest["operator"]["script_protocol_send"] = True
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_SCRIPT_PROTOCOL_SEND"


def test_paper_eligibility_identity_mismatch_version() -> None:
    manifest = _manifest(run_profile="baseline_idle")
    manifest["target"]["run_identity"] = {
        "version_code": "999",
        "base_apk_sha256": "a" * 64,
        "artifact_set_hash": "b" * 64,
        "signer_set_hash": "c" * 64,
    }
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_IDENTITY_MISMATCH"


def test_messaging_baseline_idle_low_signal_reason_is_explicit() -> None:
    manifest = _manifest(run_profile="baseline_idle", valid=False)
    manifest["dataset"]["invalid_reason_code"] = "PCAP_MISSING"
    manifest["dataset"]["low_signal"] = True
    manifest["dataset"]["exploratory_class"] = "LOW_SIGNAL_IDLE"
    manifest["target"]["package_name"] = "com.whatsapp"
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_LOW_SIGNAL_IDLE_BASELINE"


def test_messaging_baseline_idle_is_non_cohort_even_if_valid() -> None:
    manifest = _manifest(run_profile="baseline_idle", valid=True)
    manifest["target"]["package_name"] = "com.whatsapp"
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_BASELINE_IDLE_NON_COHORT"


def test_messaging_baseline_connected_v1_is_legacy_non_cohort() -> None:
    manifest = _manifest(run_profile="baseline_connected", valid=True)
    manifest["target"]["package_name"] = "com.whatsapp"
    manifest["operator"]["baseline_protocol_id"] = "baseline_connected_v1"
    manifest["operator"]["baseline_protocol_version"] = 1
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_BASELINE_PROTOCOL_LEGACY"


def test_messaging_call_template_is_exploratory_only() -> None:
    manifest = _manifest(run_profile="interaction_scripted", valid=True)
    manifest["target"]["package_name"] = "com.whatsapp"
    manifest["operator"]["template_id"] = "messaging_call_basic_v1"
    manifest["operator"]["scenario_template"] = "messaging_call_basic_v1"
    manifest["operator"]["call_attempted"] = True
    manifest["operator"]["call_connected"] = True
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_CALL_EXPLORATORY_ONLY"


def test_call_action_in_non_call_template_is_excluded() -> None:
    manifest = _manifest(run_profile="interaction_scripted", valid=True)
    manifest["target"]["package_name"] = "com.whatsapp"
    manifest["operator"]["template_id"] = "whatsapp_basic_v1"
    manifest["operator"]["scenario_template"] = "whatsapp_basic_v1"
    manifest["operator"]["script_call_in_non_call_template"] = True
    out = derive_paper_eligibility(
        manifest=manifest,
        plan=_plan(),
        min_windows=20,
        required_capture_policy_version=1,
    )
    assert out.paper_eligible is False
    assert out.reason_code == "EXCLUDED_PROTOCOL_CALL_ACTION_IN_NON_CALL_TEMPLATE"
