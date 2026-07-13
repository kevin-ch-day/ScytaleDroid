"""Read-only contract checks for the Paper 2 v2 runtime results package."""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_PAPER2_V2_ROOT = Path("output/_internal/publication/paper2_v2")


@dataclass(frozen=True)
class Paper2V2ContractResult:
    ok: bool
    errors: list[str]
    warnings: list[str]
    details: dict[str, Any]


def validate_paper2_v2_results_contract(
    output_root: Path = DEFAULT_PAPER2_V2_ROOT,
    *,
    freeze_path: Path | None = None,
) -> Paper2V2ContractResult:
    """Validate that generated Paper 2 v2 outputs match the locked freeze.

    The v2 package is authoritative for Paper 2 runtime statistics.  This check
    verifies that generated tables and deterministic hashes still belong to the
    same freeze, selected build groups, included run set, feature contract, and
    model-parameter contract.
    """

    output_root = Path(output_root)
    errors: list[str] = []
    warnings: list[str] = []
    details: dict[str, Any] = {"output_root": str(output_root)}

    results_path = output_root / "publication_results_v2.json"
    cohort_path = output_root / "paper2_cohort_v2.csv"
    per_app_path = output_root / "paper2_per_app_rdi_v2.csv"
    if not results_path.exists():
        return Paper2V2ContractResult(False, [f"missing_file:{results_path}"], warnings, details)
    if not cohort_path.exists():
        errors.append(f"missing_file:{cohort_path}")
    if not per_app_path.exists():
        errors.append(f"missing_file:{per_app_path}")
    if errors:
        return Paper2V2ContractResult(False, errors, warnings, details)

    results = _read_json(results_path)
    resolved_freeze_path = Path(str(freeze_path or results.get("freeze_path") or ""))
    if not resolved_freeze_path.exists():
        errors.append(f"missing_freeze:{resolved_freeze_path}")
        return Paper2V2ContractResult(False, errors, warnings, details)

    freeze = _read_json(resolved_freeze_path)
    dataset_plan_path = Path(str(results.get("dataset_plan_path") or ""))
    dataset_plan = _read_json(dataset_plan_path) if dataset_plan_path.exists() else {}
    cohort_rows = _read_csv(cohort_path)
    per_app_rows = _read_csv(per_app_path)
    deterministic = results.get("deterministic_manifest") if isinstance(results.get("deterministic_manifest"), dict) else {}

    freeze_apps = freeze.get("apps") if isinstance(freeze.get("apps"), dict) else {}
    freeze_packages = sorted(str(pkg) for pkg in freeze_apps.keys())
    cohort_by_pkg = {str(row.get("package_name") or ""): row for row in cohort_rows}
    per_app_by_pkg = {str(row.get("package_name") or ""): row for row in per_app_rows}
    details.update(
        {
            "freeze_path": str(resolved_freeze_path),
            "results_path": str(results_path),
            "cohort_path": str(cohort_path),
            "per_app_path": str(per_app_path),
            "freeze_packages": len(freeze_packages),
            "cohort_rows": len(cohort_rows),
            "per_app_rows": len(per_app_rows),
        }
    )

    actual_freeze_sha = _sha256(resolved_freeze_path)
    _expect_equal(errors, "freeze_sha256", str(results.get("freeze_sha256") or ""), actual_freeze_sha)
    _expect_equal(
        errors,
        "dataset_lock_sha256",
        str(deterministic.get("dataset_lock_sha256") or ""),
        str(freeze.get("freeze_dataset_hash") or ""),
    )
    _expect_equal(
        errors,
        "included_run_set_hash",
        str(deterministic.get("included_run_set_hash") or ""),
        _hash_jsonable(sorted(str(run_id) for run_id in freeze.get("included_run_ids") or [])),
    )
    for field in ("feature_contract_hash", "model_parameter_hash", "ml_scoring_run_id"):
        if not str(deterministic.get(field) or "").strip():
            errors.append(f"missing_deterministic_field:{field}")

    cohort_packages = sorted(pkg for pkg in cohort_by_pkg if pkg)
    per_app_packages = sorted(pkg for pkg in per_app_by_pkg if pkg)
    _expect_equal(errors, "package_set:cohort", cohort_packages, freeze_packages)
    _expect_equal(errors, "package_set:per_app_rdi", per_app_packages, freeze_packages)

    plan_runs = _index_plan_runs(dataset_plan)
    selected_builds: dict[str, dict[str, Any]] = {}
    for pkg in freeze_packages:
        freeze_app = freeze_apps.get(pkg) if isinstance(freeze_apps.get(pkg), dict) else {}
        cohort = cohort_by_pkg.get(pkg) or {}
        included_ids = [str(run_id) for run_id in freeze_app.get("included_run_ids") or []]
        plan_for_app = [plan_runs.get(run_id, {}) for run_id in included_ids]
        plan_versions = sorted({str(row.get("version_code") or "") for row in plan_for_app if row.get("version_code")})
        plan_base_hashes = sorted(
            {str(row.get("base_apk_sha256") or "") for row in plan_for_app if row.get("base_apk_sha256")}
        )
        plan_artifact_hashes = sorted(
            {str(row.get("artifact_set_hash") or "") for row in plan_for_app if row.get("artifact_set_hash")}
        )
        expected_version = str(freeze_app.get("selected_version_code") or "")
        expected_base_sha = str(freeze_app.get("selected_base_apk_sha256") or "")
        cohort_artifact_hashes = sorted(
            token for token in str(cohort.get("artifact_set_hashes") or "").split(";") if token
        )

        _expect_equal(errors, f"{pkg}:selected_version_code", str(cohort.get("selected_version_code") or ""), expected_version)
        _expect_equal(
            errors,
            f"{pkg}:selected_base_apk_sha256",
            str(cohort.get("selected_base_apk_sha256") or ""),
            expected_base_sha,
        )
        if plan_versions:
            _expect_equal(errors, f"{pkg}:plan_version_codes", plan_versions, [expected_version])
        if plan_base_hashes:
            _expect_equal(errors, f"{pkg}:plan_base_apk_sha256", plan_base_hashes, [expected_base_sha])
        if plan_artifact_hashes:
            _expect_equal(errors, f"{pkg}:artifact_set_hashes", cohort_artifact_hashes, plan_artifact_hashes)
        else:
            warnings.append(f"{pkg}:artifact_set_hashes_not_available_in_plan")
        selected_builds[pkg] = {
            "version_code": expected_version,
            "base_apk_sha256": expected_base_sha,
            "artifact_set_hashes": cohort_artifact_hashes,
            "included_run_count": len(included_ids),
        }

    details["selected_builds_hash"] = _hash_jsonable(selected_builds)
    details["selected_builds"] = selected_builds
    details["primary_rdi_hash"] = _hash_jsonable(
        {
            pkg: {
                "if_baseline_rdi": per_app_by_pkg[pkg].get("if_baseline_rdi"),
                "if_interactive_rdi": per_app_by_pkg[pkg].get("if_interactive_rdi"),
                "if_delta_rdi": per_app_by_pkg[pkg].get("if_delta_rdi"),
            }
            for pkg in per_app_packages
        }
    )

    return Paper2V2ContractResult(ok=not errors, errors=errors, warnings=warnings, details=details)


def _index_plan_runs(dataset_plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    apps = dataset_plan.get("apps") if isinstance(dataset_plan.get("apps"), dict) else {}
    for app in apps.values():
        if not isinstance(app, dict):
            continue
        runs = app.get("runs") if isinstance(app.get("runs"), list) else []
        for run in runs:
            if not isinstance(run, dict):
                continue
            run_id = str(run.get("run_id") or "").strip()
            if run_id:
                out[run_id] = run
    return out


def _expect_equal(errors: list[str], field: str, actual: Any, expected: Any) -> None:
    if actual != expected:
        errors.append(f"mismatch:{field}:expected={expected!r}:actual={actual!r}")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Invalid JSON: {path}: {type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Invalid JSON object: {path}")
    return payload


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(line for line in handle if not line.startswith("#")))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_jsonable(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "DEFAULT_PAPER2_V2_ROOT",
    "Paper2V2ContractResult",
    "validate_paper2_v2_results_contract",
]
