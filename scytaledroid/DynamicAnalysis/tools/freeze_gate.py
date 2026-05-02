"""Research-grade canonical dynamic gate checks (fail-closed)."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.DynamicAnalysis.core.freeze_identity import compute_freeze_dataset_hash_from_path
from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as profile_config
from scytaledroid.DynamicAnalysis.plans.loader import enrich_dynamic_plan

DB_VERIFY_RETRIES = 3
DB_VERIFY_BACKOFF_SECONDS = (0.5, 1.0, 2.0)


@dataclass(frozen=True)
class GateResult:
    passed: bool
    errors: list[str]
    checked_runs: int


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_freeze_gate(*, freeze_path: Path, evidence_root: Path) -> GateResult:
    errors: list[str] = []
    freeze = _read_json(freeze_path)
    if not isinstance(freeze, dict):
        return GateResult(False, [f"invalid_freeze_manifest:{freeze_path}"], 0)
    included = freeze.get("included_run_ids")
    if not isinstance(included, list) or not included:
        return GateResult(False, [f"missing_included_run_ids:{freeze_path}"], 0)
    expected_freeze_sha = _sha256_file(freeze_path)
    try:
        expected_dataset_hash = compute_freeze_dataset_hash_from_path(freeze_path)
    except Exception as exc:
        expected_dataset_hash = None
        errors.append(f"freeze_manifest:bad_dataset_hash:{exc}")
    freeze_threshold = _extract_freeze_min_pcap_bytes(freeze)
    if freeze_threshold is None:
        errors.append("freeze_manifest:missing_min_pcap_bytes_used")
    elif int(freeze_threshold) != int(profile_config.MIN_PCAP_BYTES):
        errors.append(
            f"freeze_manifest:min_pcap_bytes_mismatch:{int(freeze_threshold)}!={int(profile_config.MIN_PCAP_BYTES)}"
        )
    run_ids = [str(r).strip() for r in included if str(r).strip()]
    checked = 0
    for run_id in run_ids:
        checked += 1
        run_dir = evidence_root / run_id
        ml_dir = run_dir / "analysis" / "ml" / profile_config.ML_SCHEMA_LABEL
        model_manifest_path = ml_dir / "model_manifest.json"
        summary_path = ml_dir / "ml_summary.json"
        threshold_path = ml_dir / "baseline_threshold.json"
        dars_path = ml_dir / "dars_v1.json"
        dars_hash_path = ml_dir / "dars_v1.sha256"
        cohort_status_path = ml_dir / "cohort_status.json"
        topk_path = ml_dir / "top_anomalous_windows.csv"
        zscore_path = ml_dir / "attribution_proxy.csv"
        if_scores = ml_dir / "window_scores.csv"
        required_paths = [
            cohort_status_path,
            model_manifest_path,
            summary_path,
            threshold_path,
            dars_path,
            dars_hash_path,
            topk_path,
            zscore_path,
            if_scores,
        ]
        for req in required_paths:
            if not req.exists():
                errors.append(f"{run_id}:missing:{req.name}")
        if errors and any(err.startswith(f"{run_id}:missing:") for err in errors):
            continue

        model_manifest = _read_json(model_manifest_path) or {}
        summary = _read_json(summary_path) or {}
        dars = _read_json(dars_path) or {}
        cohort_status = _read_json(cohort_status_path) or {}
        plan = _read_json(run_dir / "inputs" / "static_dynamic_plan.json") or {}
        if isinstance(plan, dict):
            plan = enrich_dynamic_plan(plan)
        run_manifest = _read_json(run_dir / "run_manifest.json") or {}
        identity = plan.get("run_identity") if isinstance(plan.get("run_identity"), dict) else {}

        if str(cohort_status.get("status") or "") != "CANONICAL_PAPER_ELIGIBLE":
            errors.append(f"{run_id}:not_paper_eligible:{cohort_status.get('reason_code')}")

        for key in (
            "static_handoff_hash",
            "base_apk_sha256",
            "artifact_set_hash",
            "package_name_lc",
            "version_code",
            "signer_digest",
            "signer_set_hash",
        ):
            value = identity.get(key)
            if not isinstance(value, str) or not value.strip():
                # version_code may be numeric in some plan payloads.
                if key == "version_code" and value not in (None, ""):
                    pass
                elif key == "signer_set_hash" and isinstance(identity.get("signer_digest"), str) and str(identity.get("signer_digest")).strip():
                    pass
                else:
                    errors.append(f"{run_id}:missing_plan_identity:{key}")
        signer_set_hash_raw = str(identity.get("signer_set_hash") or identity.get("signer_digest") or "").strip()
        signer_set_hash = _normalize_hex_hash(signer_set_hash_raw, expected_len=64)
        if signer_set_hash is None:
            errors.append(f"{run_id}:bad_identity_hash:signer_set_hash")

        target = run_manifest.get("target") if isinstance(run_manifest.get("target"), dict) else {}
        plan_package = str(identity.get("package_name_lc") or plan.get("package_name") or "").strip().lower()
        target_package = str(target.get("package_name") or "").strip().lower()
        if plan_package and target_package and plan_package != target_package:
            errors.append(f"{run_id}:apk_changed_during_run:package_name")
        plan_version = str(identity.get("version_code") or plan.get("version_code") or "").strip()
        target_version = str(target.get("version_code") or "").strip()
        if plan_version and target_version and plan_version != target_version:
            errors.append(f"{run_id}:apk_changed_during_run:version_code")
        target_identity = target.get("run_identity") if isinstance(target.get("run_identity"), dict) else {}
        target_base_sha = str(target_identity.get("base_apk_sha256") or "").strip().lower()
        plan_base_sha = str(identity.get("base_apk_sha256") or "").strip().lower()
        if target_base_sha and plan_base_sha and target_base_sha != plan_base_sha:
            errors.append(f"{run_id}:apk_changed_during_run:base_apk_sha256")
        target_signer_set_hash = str(
            target_identity.get("signer_set_hash")
            or target.get("signer_set_hash")
            or ""
        ).strip().lower()
        plan_signer_set_hash = str(
            identity.get("signer_set_hash")
            or identity.get("signer_digest")
            or ""
        ).strip().lower()
        if not target_signer_set_hash:
            errors.append(f"{run_id}:missing_observed_signer_set_hash")
        elif plan_signer_set_hash and target_signer_set_hash != plan_signer_set_hash:
            errors.append(f"{run_id}:apk_changed_during_run:signer_set_hash")

        operator = run_manifest.get("operator") if isinstance(run_manifest.get("operator"), dict) else {}
        capture_policy_version = operator.get("capture_policy_version")
        try:
            capture_policy_version_i = int(capture_policy_version)
        except Exception:
            capture_policy_version_i = None
        if capture_policy_version_i != int(profile_config.PAPER_CONTRACT_VERSION):
            errors.append(f"{run_id}:capture_policy_version_mismatch:{capture_policy_version_i}")
        static_features = plan.get("static_features") if isinstance(plan.get("static_features"), dict) else {}
        for key in (
            "exported_components_total",
            "dangerous_permission_count",
            "uses_cleartext_traffic",
            "sdk_indicator_score",
        ):
            if key not in static_features:
                errors.append(f"{run_id}:missing_static_features:{key}")
        static_handoff_hash = _normalize_hex_hash(identity.get("static_handoff_hash"), expected_len=64)
        base_apk_sha256 = _normalize_hex_hash(identity.get("base_apk_sha256"), expected_len=64)
        artifact_set_hash = _normalize_hex_hash(identity.get("artifact_set_hash"), expected_len=64)
        if static_handoff_hash is None:
            errors.append(f"{run_id}:bad_identity_hash:static_handoff_hash")
        if base_apk_sha256 is None:
            errors.append(f"{run_id}:bad_identity_hash:base_apk_sha256")
        if artifact_set_hash is None:
            errors.append(f"{run_id}:bad_identity_hash:artifact_set_hash")
        package_name_lc = str(identity.get("package_name_lc") or plan.get("package_name") or "").strip().lower()
        version_code_raw = identity.get("version_code")
        if version_code_raw in (None, ""):
            version_code_raw = plan.get("version_code")
        try:
            version_code = int(version_code_raw) if version_code_raw not in (None, "") else None
        except Exception:
            version_code = None
        if static_handoff_hash and base_apk_sha256 and artifact_set_hash:
            if not _verify_static_link(
                static_handoff_hash=static_handoff_hash,
                base_apk_sha256=base_apk_sha256,
                artifact_set_hash=artifact_set_hash,
                package_name_lc=package_name_lc or None,
                version_code=version_code,
            ):
                errors.append(f"{run_id}:static_link_db_mismatch")

        for key in ("tool_git_commit", "schema_version", "ml_schema_version", "feature_schema_version"):
            value = model_manifest.get(key)
            if value in (None, "", "<unknown>"):
                errors.append(f"{run_id}:missing_manifest_stamp:{key}")

        freeze_sha = model_manifest.get("freeze_manifest_sha256")
        if not isinstance(freeze_sha, str) or not freeze_sha.strip():
            errors.append(f"{run_id}:missing_manifest_stamp:freeze_manifest_sha256")
        elif freeze_sha.strip().lower() != expected_freeze_sha.lower():
            errors.append(f"{run_id}:freeze_sha_mismatch")

        # Dataset identity hash is a stable citation anchor. Enforce when present.
        # Back-compat: older ML manifests may not contain freeze_dataset_hash.
        dataset_hash = model_manifest.get("freeze_dataset_hash")
        if expected_dataset_hash and dataset_hash not in (None, ""):
            if not isinstance(dataset_hash, str) or not dataset_hash.strip():
                errors.append(f"{run_id}:missing_manifest_stamp:freeze_dataset_hash")
            elif dataset_hash.strip().lower() != expected_dataset_hash.strip().lower():
                errors.append(f"{run_id}:freeze_dataset_hash_mismatch")

        models = model_manifest.get("models") if isinstance(model_manifest.get("models"), dict) else {}
        iforest = models.get(profile_config.MODEL_IFOREST) if isinstance(models, dict) else None
        if not isinstance(iforest, dict):
            errors.append(f"{run_id}:missing_iforest_manifest")
        else:
            if str(iforest.get("training_mode") or "") != "baseline_only":
                errors.append(f"{run_id}:baseline_gate:training_mode")
            gates = iforest.get("quality_gates") if isinstance(iforest.get("quality_gates"), dict) else {}
            if not gates.get("baseline_pcap_bytes_ok"):
                errors.append(f"{run_id}:baseline_gate:baseline_pcap_bytes_ok")
            if not gates.get("baseline_windows_ok"):
                errors.append(f"{run_id}:baseline_gate:baseline_windows_ok")

        summary_models = summary.get("models") if isinstance(summary.get("models"), dict) else {}
        if profile_config.MODEL_IFOREST not in summary_models:
            errors.append(f"{run_id}:missing_summary_iforest")

        if not isinstance(dars.get("scores"), dict) or profile_config.MODEL_IFOREST not in dars.get("scores", {}):
            errors.append(f"{run_id}:missing_dars_iforest")

        try:
            expected = _sha256_file(dars_path).strip().lower()
            actual = dars_hash_path.read_text(encoding="utf-8").strip().lower()
            if actual != expected:
                errors.append(f"{run_id}:dars_hash_mismatch")
        except Exception:
            errors.append(f"{run_id}:dars_hash_check_failed")


    return GateResult(passed=not errors, errors=errors, checked_runs=checked)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Research-grade canonical dynamic gate checks")
    parser.add_argument(
        "--research",
        action="store_true",
        help="Preferred flag; run canonical research gate checks.",
    )
    parser.add_argument(
        "--freeze-path",
        default=str(Path(app_config.DATA_DIR) / "archive" / profile_config.FREEZE_CANONICAL_FILENAME),
        help="Path to canonical freeze manifest.",
    )
    parser.add_argument(
        "--evidence-root",
        default=str(Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"),
        help="Dynamic evidence root directory.",
    )
    args = parser.parse_args(argv)

    result = run_freeze_gate(
        freeze_path=Path(args.freeze_path),
        evidence_root=Path(args.evidence_root),
    )
    print(f"Checked runs: {result.checked_runs}")
    if result.passed:
        print("RESEARCH CANONICAL GATE: PASS")
        return 0
    print("RESEARCH CANONICAL GATE: FAIL")
    for err in result.errors:
        print(f"- {err}")
    return 1


def _verify_static_link(
    *,
    static_handoff_hash: str,
    base_apk_sha256: str,
    artifact_set_hash: str,
    package_name_lc: str | None,
    version_code: int | None,
) -> bool:
    sql = """
        SELECT COUNT(*)
        FROM v_static_handoff_v1
        WHERE LOWER(static_handoff_hash)=LOWER(%s)
          AND LOWER(base_apk_sha256)=LOWER(%s)
          AND LOWER(artifact_set_hash)=LOWER(%s)
          AND UPPER(COALESCE(run_class,''))='CANONICAL'
          AND COALESCE(identity_conflict_flag,0)=0
    """
    args: list[Any] = [static_handoff_hash, base_apk_sha256, artifact_set_hash]
    if package_name_lc:
        sql += " AND LOWER(package_name_lc)=LOWER(%s)"
        args.append(package_name_lc)
    if version_code is not None:
        sql += " AND version_code=%s"
        args.append(int(version_code))

    attempts = max(1, int(DB_VERIFY_RETRIES))
    for attempt in range(attempts):
        try:
            row = core_q.run_sql(sql, tuple(args), fetch="one")
            return bool(row and int(row[0]) >= 1)
        except Exception:
            if attempt >= attempts - 1:
                return False
            backoff = DB_VERIFY_BACKOFF_SECONDS[min(attempt, len(DB_VERIFY_BACKOFF_SECONDS) - 1)]
            time.sleep(float(backoff))
    return False


def _extract_freeze_min_pcap_bytes(freeze: dict[str, Any]) -> int | None:
    value = freeze.get("min_pcap_bytes_used")
    if value is None:
        qa = freeze.get("qa_thresholds") if isinstance(freeze.get("qa_thresholds"), dict) else {}
        value = qa.get("min_pcap_bytes") if isinstance(qa, dict) else None
    try:
        return int(value) if value is not None else None
    except Exception:
        return None


def _normalize_hex_hash(value: object, *, expected_len: int) -> str | None:
    raw = str(value or "").strip().lower()
    if not raw:
        return None
    if len(raw) != int(expected_len):
        return None
    allowed = set("0123456789abcdef")
    if any(ch not in allowed for ch in raw):
        return None
    return raw


if __name__ == "__main__":
    raise SystemExit(main())
