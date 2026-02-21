"""Research-grade canonical dynamic gate checks (fail-closed)."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.DynamicAnalysis.ml import ml_parameters_paper2 as paper2_config


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


def run_paper_gate(*, freeze_path: Path, evidence_root: Path) -> GateResult:
    errors: list[str] = []
    freeze = _read_json(freeze_path)
    if not isinstance(freeze, dict):
        return GateResult(False, [f"invalid_freeze_manifest:{freeze_path}"], 0)
    included = freeze.get("included_run_ids")
    if not isinstance(included, list) or not included:
        return GateResult(False, [f"missing_included_run_ids:{freeze_path}"], 0)
    expected_freeze_sha = _sha256_file(freeze_path)
    run_ids = [str(r).strip() for r in included if str(r).strip()]
    checked = 0
    for run_id in run_ids:
        checked += 1
        run_dir = evidence_root / run_id
        ml_dir = run_dir / "analysis" / "ml" / paper2_config.ML_SCHEMA_LABEL
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
        identity = plan.get("run_identity") if isinstance(plan.get("run_identity"), dict) else {}

        if str(cohort_status.get("status") or "") != "CANONICAL_PAPER_ELIGIBLE":
            errors.append(f"{run_id}:not_paper_eligible:{cohort_status.get('reason_code')}")

        for key in ("static_handoff_hash", "base_apk_sha256"):
            value = identity.get(key)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{run_id}:missing_plan_identity:{key}")
        static_handoff_hash = str(identity.get("static_handoff_hash") or "").strip().lower()
        base_apk_sha256 = str(identity.get("base_apk_sha256") or "").strip().lower()
        if static_handoff_hash and base_apk_sha256:
            if not _verify_static_link(static_handoff_hash=static_handoff_hash, base_apk_sha256=base_apk_sha256):
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

        models = model_manifest.get("models") if isinstance(model_manifest.get("models"), dict) else {}
        iforest = models.get(paper2_config.MODEL_IFOREST) if isinstance(models, dict) else None
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
        if paper2_config.MODEL_IFOREST not in summary_models:
            errors.append(f"{run_id}:missing_summary_iforest")

        if not isinstance(dars.get("scores"), dict) or paper2_config.MODEL_IFOREST not in dars.get("scores", {}):
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
        "--paper",
        action="store_true",
        help="Deprecated compatibility flag; use --research.",
    )
    parser.add_argument(
        "--freeze-path",
        default=str(Path(app_config.DATA_DIR) / "archive" / paper2_config.FREEZE_CANONICAL_FILENAME),
        help="Path to canonical freeze manifest.",
    )
    parser.add_argument(
        "--evidence-root",
        default=str(Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"),
        help="Dynamic evidence root directory.",
    )
    args = parser.parse_args(argv)

    result = run_paper_gate(
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


def _verify_static_link(*, static_handoff_hash: str, base_apk_sha256: str) -> bool:
    try:
        row = core_q.run_sql(
            """
            SELECT COUNT(*)
            FROM v_static_handoff_v1
            WHERE LOWER(static_handoff_hash)=LOWER(%s)
              AND LOWER(base_apk_sha256)=LOWER(%s)
              AND UPPER(COALESCE(run_class,''))='CANONICAL'
              AND COALESCE(identity_conflict_flag,0)=0
            """,
            (static_handoff_hash, base_apk_sha256),
            fetch="one",
        )
        return bool(row and int(row[0]) >= 1)
    except Exception:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
