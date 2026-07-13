"""Per-run artifact and status writers for freeze/profile ML mode."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.core.freeze_identity import (
    FREEZE_DATASET_HASH_ALGORITHM,
    FREEZE_DATASET_IDENTITY_VERSION,
    compute_freeze_dataset_hash_from_path,
)
from scytaledroid.Utils.IO.atomic_write import atomic_write_text

from .. import ml_parameters_profile as config
from ..evidence_pack_ml_preflight import RunInputs
from ..io import MLOutputPaths
from ..method_basis import runtime_ml_method_basis
from ..seed_identity import salt_metadata
from ..telemetry_windowing import WindowSpec

PAPER_EXCLUSION_REASON_CODES = {
    "ML_SKIPPED_BASELINE_GATE_FAIL",
    "ML_SKIPPED_MISSING_FREEZE_MANIFEST",
    "ML_SKIPPED_BAD_FREEZE_CHECKSUM",
    "ML_SKIPPED_MISSING_STATIC_LINK",
    "ML_SKIPPED_MISSING_BASE_APK_SHA256",
    "ML_SKIPPED_MISSING_STATIC_FEATURES",
    "ML_SKIPPED_APK_CHANGED_DURING_RUN",
    "ML_SKIPPED_BAD_IDENTITY_HASH",
    "ML_SKIPPED_INCOMPLETE_ARTIFACT_SET",
}


def write_model_manifest(
    path: Path,
    *,
    run_inputs: RunInputs,
    identity_key_used: str,
    seed: int,
    window_spec: WindowSpec,
    model_outputs: dict[str, dict[str, Any]],
    freeze_manifest_path: str | None,
    ml_config_fingerprint: str,
    ml_config_fingerprint_payload: dict[str, Any],
) -> None:
    env = run_inputs.manifest.get("environment") or {}
    env_dict = env if isinstance(env, dict) else {}
    host_tools = env.get("host_tools") if isinstance(env, dict) else None
    try:
        import numpy
        import sklearn

        deps = {"numpy": numpy.__version__, "sklearn": sklearn.__version__}
    except Exception:
        deps = {}
    freeze_sha256 = None
    freeze_dataset_hash = None
    if freeze_manifest_path:
        try:
            freeze_sha256 = _sha256_file(Path(freeze_manifest_path))
        except Exception:
            freeze_sha256 = None
        try:
            freeze_dataset_hash = compute_freeze_dataset_hash_from_path(Path(freeze_manifest_path))
        except Exception:
            freeze_dataset_hash = None
    payload: dict[str, Any] = {
        "ml_schema_version": config.ML_SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "method_basis": runtime_ml_method_basis(context="per_run_model_manifest"),
        "ml_config_fingerprint": str(ml_config_fingerprint),
        "ml_config_fingerprint_payload": ml_config_fingerprint_payload,
        "frozen": bool(freeze_manifest_path),
        "freeze_manifest_path": freeze_manifest_path,
        "freeze_manifest_sha256": freeze_sha256,
        "freeze_dataset_identity_version": int(FREEZE_DATASET_IDENTITY_VERSION) if freeze_manifest_path else None,
        "freeze_dataset_hash_algorithm": str(FREEZE_DATASET_HASH_ALGORITHM) if freeze_manifest_path else None,
        "freeze_dataset_hash": freeze_dataset_hash,
        "identity_key_used": identity_key_used,
        "seed": int(seed),
        **salt_metadata(),
        "tool_semver": env_dict.get("tool_semver"),
        "tool_git_commit": env_dict.get("tool_git_commit"),
        "schema_version": env_dict.get("schema_version"),
        "feature_schema_version": (
            run_inputs.pcap_features.get("feature_schema_version")
            if isinstance(run_inputs.pcap_features, dict)
            else None
        ),
        "windowing": {
            "window_size_s": float(window_spec.window_size_s),
            "stride_s": float(window_spec.stride_s),
            "drop_partial_windows": True,
            "timebase": "pcap_time_relative_seconds",
        },
        "paper_constants": {
            "window_size_s": float(config.WINDOW_SIZE_S),
            "window_stride_s": float(config.WINDOW_STRIDE_S),
            "min_windows_baseline": int(config.MIN_WINDOWS_BASELINE),
            "min_pcap_bytes_fallback": int(config.MIN_PCAP_BYTES_FALLBACK),
            "np_percentile_method": str(config.NP_PERCENTILE_METHOD),
        },
        "capture_semantics": {
            "capture_scope": "PCAPdroid-filtered capture restricted to the target package.",
            "byte_semantics": "aggregate frame length (frame.len) as reported by tshark.",
            "directionality": "no direction split is performed.",
            **_capture_semantics_from_run_inputs(run_inputs),
        },
        "score_semantics": "higher_is_more_anomalous",
        "inputs": {
            "run_id": run_inputs.run_id,
            "package_name": run_inputs.package_name,
            "run_profile": run_inputs.run_profile,
            "plan_path": "inputs/static_dynamic_plan.json",
            "summary_path": "analysis/summary.json",
            "pcap_report_path": "analysis/pcap_report.json",
            "pcap_features_path": "analysis/pcap_features.json",
        },
        "environment": {
            "python_version": env.get("python_version") if isinstance(env, dict) else None,
            "host_tools": host_tools,
            "deps": deps,
        },
        "models": model_outputs,
        "model_reporting_roles": {
            config.MODEL_IFOREST: "primary",
            config.MODEL_OCSVM: "secondary_model_robustness_check",
        },
    }
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    write_ml_semantic_config(
        path.parent,
        ml_config_fingerprint=str(ml_config_fingerprint),
        ml_config_fingerprint_payload=ml_config_fingerprint_payload,
    )


def semantic_config_path(out_dir: Path) -> Path:
    return out_dir / "ml_semantic_config.json"


def write_ml_semantic_config(
    out_dir: Path,
    *,
    ml_config_fingerprint: str,
    ml_config_fingerprint_payload: dict[str, Any],
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = semantic_config_path(out_dir)
    if p.exists():
        return
    payload = {
        "ml_config_fingerprint": str(ml_config_fingerprint),
        "ml_config_fingerprint_payload": ml_config_fingerprint_payload,
    }
    atomic_write_text(p, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def read_ml_config_fingerprint(out_dir: Path) -> str | None:
    # Prefer sidecar (stable, no timestamps). Fall back to model_manifest.json for back-compat.
    p = semantic_config_path(out_dir)
    if p.exists():
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
            fp = str(obj.get("ml_config_fingerprint") or "").strip()
            return fp or None
        except Exception:
            return None
    man = out_dir / "model_manifest.json"
    if man.exists():
        try:
            obj = json.loads(man.read_text(encoding="utf-8"))
            fp = str(obj.get("ml_config_fingerprint") or "").strip()
            return fp or None
        except Exception:
            return None
    return None


def write_run_skip(run: RunInputs, *, frozen: bool, reason: str, details: dict[str, Any] | None = None) -> None:
    paths = MLOutputPaths(run_dir=run.run_dir, schema_label=config.ML_SCHEMA_LABEL)
    paths.output_dir.mkdir(parents=True, exist_ok=True)
    if not (frozen and paths.summary_path.exists()):
        payload = {
            "ml_schema_version": config.ML_SCHEMA_VERSION,
            "run_id": run.run_id,
            "package_name": run.package_name,
            "run_profile": run.run_profile,
            "skip": {"reason": reason},
        }
        if details:
            payload["skip"]["details"] = details
        atomic_write_text(paths.summary_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    write_cohort_status(run, status="EXCLUDED", reason_code=reason, details=details)


def write_app_skip(
    app_runs: list[RunInputs],
    *,
    frozen: bool,
    reason: str,
    details: dict[str, Any] | None = None,
) -> None:
    for r in app_runs:
        write_run_skip(r, frozen=frozen, reason=reason, details=details)


def write_cohort_status(
    run: RunInputs,
    *,
    status: str,
    reason_code: str | None,
    details: dict[str, Any] | None = None,
) -> None:
    paths = MLOutputPaths(run_dir=run.run_dir, schema_label=config.ML_SCHEMA_LABEL)
    paths.output_dir.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
        "paper_contract_version": int(config.PAPER_CONTRACT_VERSION),
        "reason_taxonomy_version": int(config.REASON_TAXONOMY_VERSION),
        "freeze_contract_version": int(config.FREEZE_CONTRACT_VERSION),
        "plan_schema_version": (
            str(run.plan.get("plan_schema_version") or "").strip()
            if isinstance(run.plan, dict)
            else None
        ),
        "run_id": run.run_id,
        "package_name": run.package_name,
        "status": status,
        "reason_code": reason_code,
        "gates": {
            "min_windows_baseline": int(config.MIN_WINDOWS_BASELINE),
            "min_pcap_bytes": int(config.MIN_PCAP_BYTES),
        },
    }
    validate_paper_reason_code(reason_code)
    if details:
        payload["details"] = details
    target = run.manifest.get("target") if isinstance(run.manifest, dict) and isinstance(run.manifest.get("target"), dict) else {}
    run_identity = run.plan.get("run_identity") if isinstance(run.plan, dict) and isinstance(run.plan.get("run_identity"), dict) else {}
    payload["identity"] = {
        "package_name_lc": run_identity.get("package_name_lc") or run.plan.get("package_name"),
        "version_code": run_identity.get("version_code") or run.plan.get("version_code"),
        "base_apk_sha256": run_identity.get("base_apk_sha256"),
        "artifact_set_hash": run_identity.get("artifact_set_hash"),
        "signer_set_hash": run_identity.get("signer_set_hash") or run_identity.get("signer_digest"),
        "static_handoff_hash": run_identity.get("static_handoff_hash"),
        "identity_checked_at_start_utc": target.get("identity_checked_at_start_utc"),
        "identity_checked_at_end_utc": target.get("identity_checked_at_end_utc"),
        "identity_checked_at_gate_utc": None,
        "identity_start": target.get("identity_start"),
        "identity_end": target.get("identity_end"),
        "identity_gate": None,
    }
    atomic_write_text(paths.cohort_status_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def write_global_cohort_status(root: Path, *, reason: str, details: dict[str, Any] | None = None) -> None:
    out = root / "analysis" / "ml" / "paper" / "cohort_status.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "ml_schema_version": int(config.ML_SCHEMA_VERSION),
        "status": "EXCLUDED",
        "reason_code": reason,
        "gates": {
            "min_windows_baseline": int(config.MIN_WINDOWS_BASELINE),
            "min_pcap_bytes": int(config.MIN_PCAP_BYTES),
        },
    }
    validate_paper_reason_code(reason)
    if details:
        payload["details"] = details
    atomic_write_text(out, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def validate_paper_reason_code(reason_code: str | None) -> None:
    if reason_code is None:
        return
    if reason_code not in PAPER_EXCLUSION_REASON_CODES:
        raise RuntimeError(f"Unknown paper exclusion reason code: {reason_code}")


def _capture_semantics_from_run_inputs(run_inputs: RunInputs) -> dict[str, Any]:
    manifest = run_inputs.manifest if isinstance(run_inputs.manifest, dict) else {}
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), list) else []
    meta_rel = None
    for art in artifacts:
        if isinstance(art, dict) and str(art.get("type") or "") == "pcapdroid_capture_meta":
            rp = art.get("relative_path")
            if isinstance(rp, str) and rp:
                meta_rel = rp
                break
    pcapdroid_version = "unknown"
    capture_mode = "unknown"
    filter_type = "PCAPdroid app_filter (package)"
    if meta_rel:
        try:
            meta_path = run_inputs.run_dir / meta_rel
            payload = json.loads(meta_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                capture_mode = str(payload.get("capture_mode") or "unknown")
                pkg = payload.get("pcapdroid_package")
                if isinstance(pkg, str) and pkg.strip():
                    pcapdroid_version = str(payload.get("pcapdroid_version") or "unknown")
        except Exception:
            pass
    report = run_inputs.pcap_report if isinstance(run_inputs.pcap_report, dict) else {}
    capinfos = report.get("capinfos") if isinstance(report.get("capinfos"), dict) else {}
    parsed = capinfos.get("parsed") if isinstance(capinfos.get("parsed"), dict) else {}
    linktype = (
        parsed.get("file_type")
        or parsed.get("encapsulation")
        or report.get("linktype")
        or "unknown"
    )
    return {
        "capture_tool": "PCAPdroid",
        "filter_type": filter_type,
        "capture_mode": str(capture_mode),
        "pcapdroid_version": str(pcapdroid_version),
        "pcap_linktype": str(linktype),
    }


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


__all__ = [
    "PAPER_EXCLUSION_REASON_CODES",
    "read_ml_config_fingerprint",
    "semantic_config_path",
    "validate_paper_reason_code",
    "write_app_skip",
    "write_cohort_status",
    "write_global_cohort_status",
    "write_ml_semantic_config",
    "write_model_manifest",
    "write_run_skip",
]
