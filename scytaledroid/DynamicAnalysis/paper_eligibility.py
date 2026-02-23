"""Paper-mode eligibility derivation and exclusion taxonomy.

Single source of truth for evidence-first paper eligibility decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import MESSAGING_PACKAGES
from scytaledroid.DynamicAnalysis.templates.category_map import resolved_template_for_package

_MESSAGING_PACKAGES_LC = {p.lower() for p in MESSAGING_PACKAGES}
_SOCIAL_TEMPLATE_ALLOWED = {
    "social_feed_basic_v2",
    "facebook_basic_v2",
    "snapchat_basic_v1",
    "x_twitter_full_session_v1",
}
_MESSAGING_TEMPLATE_ALLOWED = {
    # Legacy category-map entrypoints (resolved from package).
    "messaging_basic_v1",
    "whatsapp_basic_v1",
    # Activity-specific messaging templates (actual observed template_id_actual).
    "messaging_idle_v1",
    "messaging_text_v1",
    "messaging_voice_v1",
    "messaging_video_v1",
    "whatsapp_idle_v1",
    "whatsapp_text_v1",
    "whatsapp_voice_v1",
    "whatsapp_video_v1",
    # Mixed/call exploratory template.
    "messaging_call_basic_v1",
}
_LEGACY_TEMPLATE_IDS = {"social_feed_basic", "messaging_basic"}

EXCLUSION_REASON_CODES: tuple[str, ...] = (
    "EXCLUDED_SCRIPT_HASH_MISMATCH",
    "EXCLUDED_SCRIPT_TEMPLATE_MISMATCH",
    "EXCLUDED_PROTOCOL_LEGACY_TEMPLATE",
    "EXCLUDED_SCRIPT_PROTOCOL_SEND",
    "EXCLUDED_PROTOCOL_CALL_ACTION_IN_NON_CALL_TEMPLATE",
    "EXCLUDED_SCRIPT_ABORT",
    "EXCLUDED_SCRIPT_END_MISSING",
    "EXCLUDED_SCRIPT_STEP_MISSING",
    "EXCLUDED_SCRIPT_TIMEOUT",
    "EXCLUDED_SCRIPT_UI_STATE_MISMATCH",
    "EXCLUDED_PROTOCOL_FIT_POOR",
    "EXCLUDED_MANUAL_NON_COHORT",
    "EXCLUDED_EXTRA_RUN",
    "EXCLUDED_INTENT_NOT_ALLOWED",
    "EXCLUDED_IDENTITY_MISMATCH",
    "EXCLUDED_POLICY_VERSION_MISMATCH",
    "EXCLUDED_MISSING_REQUIRED_IDENTITY_FIELD",
    "EXCLUDED_NO_EVIDENCE_PACK",
    "EXCLUDED_INCOMPLETE_ARTIFACT_SET",
    "EXCLUDED_LOW_SIGNAL_IDLE_BASELINE",
    "EXCLUDED_BASELINE_IDLE_NON_COHORT",
    "EXCLUDED_BASELINE_PROTOCOL_LEGACY",
    "EXCLUDED_CALL_EXPLORATORY_ONLY",
    "EXCLUDED_CALL_NOT_CONNECTED",
    "EXCLUDED_TSHARK_PARSE_FAILED",
    "EXCLUDED_CAPINFOS_PARSE_FAILED",
    "EXCLUDED_FEATURE_EXTRACTION_FAILED",
    "EXCLUDED_WINDOW_COUNT_MISSING",
    "EXCLUDED_WINDOW_COUNT_TOO_LOW",
    "EXCLUDED_DURATION_TOO_SHORT",
    "EXCLUDED_MISSING_QUALITY_KEYS",
    "EXCLUDED_OUTSIDE_REPLACEMENT_SCOPE",
    "EXCLUDED_NOT_SELECTED_BY_DETERMINISTIC_RANK",
    "EXCLUDED_INTERNAL_ERROR",
)

# Lower numeric value == higher precedence
EXCLUSION_REASON_PRECEDENCE: dict[str, int] = {
    # Script/protocol
    "EXCLUDED_SCRIPT_HASH_MISMATCH": 10,
    "EXCLUDED_PROTOCOL_LEGACY_TEMPLATE": 11,
    "EXCLUDED_SCRIPT_TEMPLATE_MISMATCH": 12,
    "EXCLUDED_SCRIPT_PROTOCOL_SEND": 13,
    "EXCLUDED_PROTOCOL_CALL_ACTION_IN_NON_CALL_TEMPLATE": 14,
    "EXCLUDED_SCRIPT_ABORT": 15,
    "EXCLUDED_SCRIPT_END_MISSING": 16,
    "EXCLUDED_SCRIPT_STEP_MISSING": 17,
    "EXCLUDED_SCRIPT_TIMEOUT": 18,
    "EXCLUDED_SCRIPT_UI_STATE_MISMATCH": 19,
    "EXCLUDED_PROTOCOL_FIT_POOR": 20,
    # Identity/policy
    "EXCLUDED_IDENTITY_MISMATCH": 20,
    "EXCLUDED_POLICY_VERSION_MISMATCH": 21,
    "EXCLUDED_MISSING_REQUIRED_IDENTITY_FIELD": 22,
    # Evidence/artifacts
    "EXCLUDED_NO_EVIDENCE_PACK": 30,
    "EXCLUDED_INCOMPLETE_ARTIFACT_SET": 31,
    "EXCLUDED_LOW_SIGNAL_IDLE_BASELINE": 30,
    "EXCLUDED_BASELINE_IDLE_NON_COHORT": 31,
    "EXCLUDED_BASELINE_PROTOCOL_LEGACY": 32,
    "EXCLUDED_CALL_EXPLORATORY_ONLY": 53,
    "EXCLUDED_CALL_NOT_CONNECTED": 54,
    "EXCLUDED_TSHARK_PARSE_FAILED": 32,
    "EXCLUDED_CAPINFOS_PARSE_FAILED": 33,
    "EXCLUDED_FEATURE_EXTRACTION_FAILED": 34,
    # Window/duration/quality keys
    "EXCLUDED_WINDOW_COUNT_MISSING": 40,
    "EXCLUDED_WINDOW_COUNT_TOO_LOW": 41,
    "EXCLUDED_DURATION_TOO_SHORT": 42,
    "EXCLUDED_MISSING_QUALITY_KEYS": 43,
    # Intent/cohort policy
    "EXCLUDED_INTENT_NOT_ALLOWED": 50,
    "EXCLUDED_MANUAL_NON_COHORT": 51,
    "EXCLUDED_EXTRA_RUN": 52,
    # Selection/ranking
    "EXCLUDED_OUTSIDE_REPLACEMENT_SCOPE": 60,
    "EXCLUDED_NOT_SELECTED_BY_DETERMINISTIC_RANK": 61,
    # Fallback
    "EXCLUDED_INTERNAL_ERROR": 99,
}


@dataclass(frozen=True)
class PaperEligibility:
    paper_eligible: bool
    reason_code: str | None
    all_reason_codes: tuple[str, ...]


def _choose_primary_reason(codes: list[str]) -> str | None:
    if not codes:
        return None
    uniq = sorted(set(codes), key=lambda c: (EXCLUSION_REASON_PRECEDENCE.get(c, 999), c))
    return uniq[0]


def _is_truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(value) != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "ok", "pass"}
    return False


def _norm_str(value: object) -> str:
    return str(value or "").strip()


def _norm_hex(value: object) -> str:
    return str(value or "").strip().lower()


def derive_paper_eligibility(
    *,
    manifest: dict[str, Any] | None,
    plan: dict[str, Any] | None,
    min_windows: int,
    required_capture_policy_version: int,
) -> PaperEligibility:
    try:
        m = manifest if isinstance(manifest, dict) else {}
        p = plan if isinstance(plan, dict) else {}
        ds = m.get("dataset") if isinstance(m.get("dataset"), dict) else {}
        op = m.get("operator") if isinstance(m.get("operator"), dict) else {}
        target = m.get("target") if isinstance(m.get("target"), dict) else {}
        plan_identity = p.get("run_identity") if isinstance(p.get("run_identity"), dict) else {}
        target_identity = target.get("run_identity") if isinstance(target.get("run_identity"), dict) else {}

        reasons: list[str] = []
        if not _is_truthy(ds.get("valid_dataset_run")):
            # Keep paper-mode surface compact; artifact-level checks are done elsewhere.
            reasons.append("EXCLUDED_INCOMPLETE_ARTIFACT_SET")
            pkg_lc = _norm_str(target.get("package_name")).lower()
            run_profile = str(ds.get("run_profile") or op.get("run_profile") or "").strip().lower()
            invalid_reason = _norm_str(ds.get("invalid_reason_code")).upper()
            low_signal = _is_truthy(ds.get("low_signal"))
            exploratory_class = _norm_str(ds.get("exploratory_class")).upper()
            if (
                pkg_lc in _MESSAGING_PACKAGES_LC
                and run_profile == "baseline_idle"
                and (
                    invalid_reason in {"PCAP_MISSING", "PCAP_TOO_SMALL"}
                    or low_signal
                    or exploratory_class == "LOW_SIGNAL_IDLE"
                )
            ):
                reasons.append("EXCLUDED_LOW_SIGNAL_IDLE_BASELINE")

        capture_policy_version = op.get("capture_policy_version")
        try:
            cpv_i = int(capture_policy_version)
        except Exception:
            cpv_i = None
        if cpv_i != int(required_capture_policy_version):
            reasons.append("EXCLUDED_POLICY_VERSION_MISMATCH")

        run_profile = str(ds.get("run_profile") or op.get("run_profile") or "").strip().lower()
        pkg_lc = _norm_str(target.get("package_name")).lower()
        if pkg_lc in _MESSAGING_PACKAGES_LC and run_profile == "baseline_idle":
            reasons.append("EXCLUDED_BASELINE_IDLE_NON_COHORT")
        if pkg_lc in _MESSAGING_PACKAGES_LC and run_profile == "baseline_connected":
            baseline_protocol_id = _norm_str(op.get("baseline_protocol_id")).lower()
            try:
                baseline_protocol_version = int(op.get("baseline_protocol_version"))
            except Exception:
                baseline_protocol_version = None
            if baseline_protocol_id != "baseline_connected_v2" or baseline_protocol_version is None or baseline_protocol_version < 2:
                reasons.append("EXCLUDED_BASELINE_PROTOCOL_LEGACY")
        if run_profile.startswith("interaction_scripted"):
            observed_template = _norm_str(op.get("template_id") or op.get("scenario_template")).lower()
            expected_template = _norm_str(resolved_template_for_package(pkg_lc)).lower()
            allowed_templates = _MESSAGING_TEMPLATE_ALLOWED if pkg_lc in _MESSAGING_PACKAGES_LC else _SOCIAL_TEMPLATE_ALLOWED
            if observed_template in _LEGACY_TEMPLATE_IDS:
                reasons.append("EXCLUDED_PROTOCOL_LEGACY_TEMPLATE")
            try:
                protocol_version = int(op.get("interaction_protocol_version"))
            except Exception:
                protocol_version = None
            if protocol_version is None or protocol_version < 2:
                reasons.append("EXCLUDED_PROTOCOL_LEGACY_TEMPLATE")
            # App-specific governance: scripted runs should match the resolved
            # template for the package (category mapping + app overrides).
            # Exception: messaging call template is exploratory-only and may be
            # intentionally selected via hard-switch.
            # Messaging runs may resolve to an activity-specific template even though the
            # category map "expected template" is the generic entrypoint.
            call_template_exception = (
                pkg_lc in _MESSAGING_PACKAGES_LC and observed_template == "messaging_call_basic_v1"
            )
            messaging_activity_template_exception = (
                pkg_lc in _MESSAGING_PACKAGES_LC
                and expected_template in {"messaging_basic_v1", "whatsapp_basic_v1"}
                and observed_template in _MESSAGING_TEMPLATE_ALLOWED
            )
            if not observed_template:
                reasons.append("EXCLUDED_SCRIPT_TEMPLATE_MISMATCH")
            elif expected_template:
                if (
                    observed_template != expected_template
                    and not call_template_exception
                    and not messaging_activity_template_exception
                ):
                    reasons.append("EXCLUDED_SCRIPT_TEMPLATE_MISMATCH")
            elif observed_template not in allowed_templates:
                reasons.append("EXCLUDED_SCRIPT_TEMPLATE_MISMATCH")
            script_hash = str(op.get("script_hash") or "").strip().lower()
            if not script_hash:
                reasons.append("EXCLUDED_SCRIPT_HASH_MISMATCH")
            # Text-mode messaging templates may legitimately send messages.
            if _is_truthy(op.get("script_protocol_send")) and not str(observed_template).endswith("_text_v1"):
                reasons.append("EXCLUDED_SCRIPT_PROTOCOL_SEND")
            if _is_truthy(op.get("script_call_in_non_call_template")):
                reasons.append("EXCLUDED_PROTOCOL_CALL_ACTION_IN_NON_CALL_TEMPLATE")
            try:
                script_exit_code = int(op.get("script_exit_code"))
            except Exception:
                script_exit_code = 1
            if script_exit_code != 0:
                reasons.append("EXCLUDED_SCRIPT_ABORT")
            if op.get("script_end_marker") is not True:
                reasons.append("EXCLUDED_SCRIPT_END_MISSING")
            try:
                planned = int(op.get("step_count_planned"))
                completed = int(op.get("step_count_completed"))
            except Exception:
                planned = 0
                completed = -1
            if planned <= 0 or completed != planned:
                reasons.append("EXCLUDED_SCRIPT_STEP_MISSING")
            # Timing drift is operationally useful but not a paper exclusion by itself.
            if op.get("script_ui_state_ok") is False:
                reasons.append("EXCLUDED_SCRIPT_UI_STATE_MISMATCH")
            # Operator protocol fit feedback is an operational signal, not a hard
            # paper exclusion. Keep it as a separate flag for review, but do not
            # exclude otherwise-valid runs from cohort/quota.
            if observed_template == "messaging_call_basic_v1":
                # Mixed/call exploratory-only template (retained, non-cohort).
                reasons.append("EXCLUDED_CALL_EXPLORATORY_ONLY")
                if op.get("call_connected") is False:
                    reasons.append("EXCLUDED_CALL_NOT_CONNECTED")
            if observed_template in {"messaging_voice_v1", "messaging_video_v1", "whatsapp_voice_v1", "whatsapp_video_v1"}:
                # Cohort-eligible call templates must connect to be meaningful.
                if op.get("call_connected") is False:
                    reasons.append("EXCLUDED_CALL_NOT_CONNECTED")
        # Manual runs are cohort-eligible in this tool (operators may collect
        # scripted or manual interactions to satisfy quota). If a paper policy
        # needs to exclude manual runs, that should be enforced via a separate
        # paper-mode toggle, not hard-coded here.

        plan_package = _norm_str(plan_identity.get("package_name_lc") or p.get("package_name")).lower()
        target_package = _norm_str(target.get("package_name")).lower()
        plan_version = _norm_str(plan_identity.get("version_code") or p.get("version_code"))
        target_version = _norm_str(target_identity.get("version_code") or target.get("version_code"))
        plan_base_sha = _norm_hex(plan_identity.get("base_apk_sha256"))
        target_base_sha = _norm_hex(target_identity.get("base_apk_sha256") or target.get("base_apk_sha256"))
        plan_artifact_set_hash = _norm_hex(plan_identity.get("artifact_set_hash"))
        target_artifact_set_hash = _norm_hex(target_identity.get("artifact_set_hash") or target.get("artifact_set_hash"))
        plan_signer_set_hash = _norm_hex(plan_identity.get("signer_set_hash") or plan_identity.get("signer_digest"))
        target_signer_set_hash = _norm_hex(
            target_identity.get("signer_set_hash")
            or target.get("signer_set_hash")
            or target_identity.get("signer_digest")
        )
        static_handoff_hash = _norm_hex(plan_identity.get("static_handoff_hash") or target.get("static_handoff_hash"))
        version_code = plan_version or target_version
        base_sha = plan_base_sha or target_base_sha
        artifact_set_hash = plan_artifact_set_hash or target_artifact_set_hash
        signer_set_hash = plan_signer_set_hash or target_signer_set_hash
        if not (version_code and base_sha and artifact_set_hash and signer_set_hash and static_handoff_hash):
            reasons.append("EXCLUDED_MISSING_REQUIRED_IDENTITY_FIELD")
        # Identity must be stable between planned static identity and observed dynamic target.
        if plan_package and target_package and plan_package != target_package:
            reasons.append("EXCLUDED_IDENTITY_MISMATCH")
        if plan_version and target_version and plan_version != target_version:
            reasons.append("EXCLUDED_IDENTITY_MISMATCH")
        if plan_base_sha and target_base_sha and plan_base_sha != target_base_sha:
            reasons.append("EXCLUDED_IDENTITY_MISMATCH")
        if plan_artifact_set_hash and target_artifact_set_hash and plan_artifact_set_hash != target_artifact_set_hash:
            reasons.append("EXCLUDED_IDENTITY_MISMATCH")
        if plan_signer_set_hash and target_signer_set_hash and plan_signer_set_hash != target_signer_set_hash:
            reasons.append("EXCLUDED_IDENTITY_MISMATCH")

        wc = ds.get("window_count")
        if wc in (None, ""):
            reasons.append("EXCLUDED_WINDOW_COUNT_MISSING")
        else:
            try:
                wc_i = int(wc)
            except Exception:
                wc_i = -1
            if wc_i < int(min_windows):
                reasons.append("EXCLUDED_WINDOW_COUNT_TOO_LOW")

        primary = _choose_primary_reason(reasons)
        return PaperEligibility(
            paper_eligible=(primary is None),
            reason_code=primary,
            all_reason_codes=tuple(sorted(set(reasons))),
        )
    except Exception:
        return PaperEligibility(
            paper_eligible=False,
            reason_code="EXCLUDED_INTERNAL_ERROR",
            all_reason_codes=("EXCLUDED_INTERNAL_ERROR",),
        )


__all__ = [
    "EXCLUSION_REASON_CODES",
    "EXCLUSION_REASON_PRECEDENCE",
    "PaperEligibility",
    "derive_paper_eligibility",
]
