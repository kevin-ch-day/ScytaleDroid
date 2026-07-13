"""Freeze/profile identity contract checks for ML eligibility."""

from __future__ import annotations

from typing import Any

from ..evidence_pack_ml_preflight import RunInputs

REQUIRED_STATIC_FEATURES = (
    "exported_components_total",
    "dangerous_permission_count",
    "uses_cleartext_traffic",
    "sdk_indicator_score",
)


def resolve_paper_identity_contract(app_runs: list[RunInputs]) -> tuple[str | None, str | None, dict[str, Any] | None]:
    base_sha_values: set[str] = set()
    static_handoff_values: set[str] = set()
    missing_base_sha_run_ids: list[str] = []
    missing_static_link_run_ids: list[str] = []
    missing_static_features: dict[str, list[str]] = {}
    apk_change_mismatches: dict[str, dict[str, str]] = {}
    bad_identity_hashes: dict[str, str] = {}
    artifact_set_hash_values: set[str] = set()
    signer_set_hash_values: set[str] = set()
    for r in app_runs:
        ident = r.plan.get("run_identity") if isinstance(r.plan, dict) and isinstance(r.plan.get("run_identity"), dict) else {}
        base_sha = normalize_hex_hash(ident.get("base_apk_sha256"), expected_len=64) if isinstance(ident, dict) else None
        static_handoff_hash = normalize_hex_hash(ident.get("static_handoff_hash"), expected_len=64) if isinstance(ident, dict) else None
        artifact_set_hash = normalize_hex_hash(ident.get("artifact_set_hash"), expected_len=64) if isinstance(ident, dict) else None
        signer_set_hash = normalize_hex_hash(ident.get("signer_set_hash") or ident.get("signer_digest"), expected_len=64) if isinstance(ident, dict) else None
        if base_sha is None:
            bad_identity_hashes[str(r.run_id)] = "base_apk_sha256"
        if static_handoff_hash is None:
            bad_identity_hashes[str(r.run_id)] = "static_handoff_hash"
        if artifact_set_hash is None:
            bad_identity_hashes[str(r.run_id)] = "artifact_set_hash"
        if signer_set_hash is None:
            bad_identity_hashes[str(r.run_id)] = "signer_set_hash"
        if not base_sha:
            missing_base_sha_run_ids.append(str(r.run_id))
        else:
            base_sha_values.add(base_sha)
        if not static_handoff_hash:
            missing_static_link_run_ids.append(str(r.run_id))
        else:
            static_handoff_values.add(static_handoff_hash)
        if artifact_set_hash:
            artifact_set_hash_values.add(artifact_set_hash)
        if signer_set_hash:
            signer_set_hash_values.add(signer_set_hash)
        static_features = (
            r.plan.get("static_features")
            if isinstance(r.plan, dict) and isinstance(r.plan.get("static_features"), dict)
            else {}
        )
        missing = [key for key in REQUIRED_STATIC_FEATURES if key not in static_features]
        if missing:
            missing_static_features[str(r.run_id)] = missing
        package = str(ident.get("package_name_lc") or r.plan.get("package_name") or "").strip().lower() if isinstance(r.plan, dict) else ""
        version_code = str(ident.get("version_code") or r.plan.get("version_code") or "").strip() if isinstance(r.plan, dict) else ""
        signer_digest = str(ident.get("signer_digest") or "").strip() if isinstance(ident, dict) else ""
        if not package or not version_code:
            missing_static_link_run_ids.append(str(r.run_id))
        if not signer_digest or signer_digest.upper() == "UNKNOWN":
            missing_static_link_run_ids.append(str(r.run_id))
        target = r.manifest.get("target") if isinstance(r.manifest.get("target"), dict) else {}
        target_package = str(target.get("package_name") or "").strip().lower()
        target_version = str(target.get("version_code") or "").strip()
        if package and target_package and package != target_package:
            apk_change_mismatches[str(r.run_id)] = {
                "expected_package_name_lc": package,
                "observed_package_name_lc": target_package,
            }
        if version_code and target_version and version_code != target_version:
            apk_change_mismatches[str(r.run_id)] = {
                "expected_version_code": version_code,
                "observed_version_code": target_version,
            }

    if missing_base_sha_run_ids:
        return None, "ML_SKIPPED_MISSING_BASE_APK_SHA256", {"run_ids": sorted(missing_base_sha_run_ids)}
    if bad_identity_hashes:
        return None, "ML_SKIPPED_BAD_IDENTITY_HASH", {"runs": bad_identity_hashes}
    if missing_static_link_run_ids:
        return None, "ML_SKIPPED_MISSING_STATIC_LINK", {"run_ids": sorted(set(missing_static_link_run_ids))}
    if missing_static_features:
        return None, "ML_SKIPPED_MISSING_STATIC_FEATURES", {"runs": missing_static_features}
    if apk_change_mismatches:
        return None, "ML_SKIPPED_APK_CHANGED_DURING_RUN", {"runs": apk_change_mismatches}
    if len(base_sha_values) != 1:
        return None, "ML_SKIPPED_MISSING_STATIC_LINK", {"conflicting_base_apk_sha256": sorted(base_sha_values)}
    # A single base APK can be linked to more than one static handoff hash when
    # the same APK was statically analyzed more than once. That is provenance
    # variation, not runtime identity drift. Required static feature presence is
    # checked above, so do not block ML solely on this field.
    if len(artifact_set_hash_values) != 1:
        return None, "ML_SKIPPED_APK_CHANGED_DURING_RUN", {"conflicting_artifact_set_hash": sorted(artifact_set_hash_values)}
    # Some historical plans carry a static-run scoped signer hash while the
    # evidence manifest carries a stable target signer-set hash. When the base
    # APK and artifact set are stable, signer hash variation is provenance
    # metadata drift, not evidence that the app changed during the run.
    return f"base_apk_sha256:{next(iter(base_sha_values))}", None, None


def normalize_hex_hash(value: object, *, expected_len: int) -> str | None:
    raw = str(value or "").strip().lower()
    if not raw or len(raw) != int(expected_len):
        return None
    allowed = set("0123456789abcdef")
    if any(ch not in allowed for ch in raw):
        return None
    return raw


__all__ = ["REQUIRED_STATIC_FEATURES", "normalize_hex_hash", "resolve_paper_identity_contract"]
