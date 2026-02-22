"""Paper-mode eligibility derivation and exclusion taxonomy.

Single source of truth for evidence-first paper eligibility decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


EXCLUSION_REASON_CODES: tuple[str, ...] = (
    "EXCLUDED_SCRIPT_HASH_MISMATCH",
    "EXCLUDED_SCRIPT_ABORT",
    "EXCLUDED_SCRIPT_END_MISSING",
    "EXCLUDED_SCRIPT_STEP_MISSING",
    "EXCLUDED_SCRIPT_TIMEOUT",
    "EXCLUDED_SCRIPT_UI_STATE_MISMATCH",
    "EXCLUDED_MANUAL_NON_COHORT",
    "EXCLUDED_EXTRA_RUN",
    "EXCLUDED_INTENT_NOT_ALLOWED",
    "EXCLUDED_IDENTITY_MISMATCH",
    "EXCLUDED_POLICY_VERSION_MISMATCH",
    "EXCLUDED_MISSING_REQUIRED_IDENTITY_FIELD",
    "EXCLUDED_NO_EVIDENCE_PACK",
    "EXCLUDED_INCOMPLETE_ARTIFACT_SET",
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
    "EXCLUDED_SCRIPT_ABORT": 11,
    "EXCLUDED_SCRIPT_END_MISSING": 12,
    "EXCLUDED_SCRIPT_STEP_MISSING": 13,
    "EXCLUDED_SCRIPT_TIMEOUT": 14,
    "EXCLUDED_SCRIPT_UI_STATE_MISMATCH": 15,
    # Identity/policy
    "EXCLUDED_IDENTITY_MISMATCH": 20,
    "EXCLUDED_POLICY_VERSION_MISMATCH": 21,
    "EXCLUDED_MISSING_REQUIRED_IDENTITY_FIELD": 22,
    # Evidence/artifacts
    "EXCLUDED_NO_EVIDENCE_PACK": 30,
    "EXCLUDED_INCOMPLETE_ARTIFACT_SET": 31,
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

        capture_policy_version = op.get("capture_policy_version")
        try:
            cpv_i = int(capture_policy_version)
        except Exception:
            cpv_i = None
        if cpv_i != int(required_capture_policy_version):
            reasons.append("EXCLUDED_POLICY_VERSION_MISMATCH")

        run_profile = str(ds.get("run_profile") or op.get("run_profile") or "").strip().lower()
        if run_profile.startswith("interaction_scripted"):
            script_hash = str(op.get("script_hash") or "").strip().lower()
            if not script_hash:
                reasons.append("EXCLUDED_SCRIPT_HASH_MISMATCH")
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
            if op.get("script_timing_within_tolerance") is False:
                reasons.append("EXCLUDED_SCRIPT_TIMEOUT")
            if op.get("script_ui_state_ok") is False:
                reasons.append("EXCLUDED_SCRIPT_UI_STATE_MISMATCH")
        if "manual" in run_profile:
            reasons.append("EXCLUDED_MANUAL_NON_COHORT")

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
