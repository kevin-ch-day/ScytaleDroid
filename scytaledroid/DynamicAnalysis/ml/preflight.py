"""ML preflight gates and frozen-input loading (Paper #2)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .identity import identity_key_fallback, identity_key_from_plan
from . import config as ml_config
from .windowing import WindowSpec, iter_windows


@dataclass(frozen=True)
class RunInputs:
    run_id: str
    run_dir: Path
    manifest: dict[str, Any]
    plan: dict[str, Any] | None
    summary: dict[str, Any] | None
    pcap_report: dict[str, Any] | None
    pcap_features: dict[str, Any] | None
    pcap_path: Path | None
    identity_key: str | None
    package_name: str | None
    run_profile: str | None


@dataclass(frozen=True)
class MlPreflightResult:
    """Deterministic per-run ML preflight outcome (evidence-pack only)."""

    ml_schema_version: int
    run_id: str
    package_name: str | None
    run_profile: str | None
    identity_key: str | None
    frozen_inputs_ok: bool
    missing_inputs: list[str]
    sampling_duration_seconds: float | None
    windows_total_expected: int
    dropped_partial_windows_expected: int
    skip_reason: str | None


def load_run_inputs(run_dir: Path) -> RunInputs | None:
    manifest_path = run_dir / "run_manifest.json"
    if not manifest_path.exists():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    run_id = str(manifest.get("dynamic_run_id") or run_dir.name)

    def _load_json(rel: str) -> dict[str, Any] | None:
        path = run_dir / rel
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    plan = _load_json("inputs/static_dynamic_plan.json")
    summary = _load_json("analysis/summary.json")
    pcap_report = _load_json("analysis/pcap_report.json")
    pcap_features = _load_json("analysis/pcap_features.json")

    # Locate canonical PCAP from manifest artifacts.
    pcap_path = None
    artifacts = manifest.get("artifacts") or []
    if isinstance(artifacts, list):
        for item in artifacts:
            if not isinstance(item, dict):
                continue
            if item.get("type") != "pcapdroid_capture":
                continue
            rel = item.get("relative_path")
            if isinstance(rel, str) and rel:
                candidate = run_dir / rel
                if candidate.exists():
                    pcap_path = candidate
                    break

    ident = identity_key_from_plan(plan) or identity_key_fallback(manifest)
    target = manifest.get("target") or {}
    package = target.get("package_name") if isinstance(target, dict) else None
    operator = manifest.get("operator") or {}
    run_profile = operator.get("run_profile") if isinstance(operator, dict) else None

    return RunInputs(
        run_id=run_id,
        run_dir=run_dir,
        manifest=manifest,
        plan=plan,
        summary=summary,
        pcap_report=pcap_report,
        pcap_features=pcap_features,
        pcap_path=pcap_path,
        identity_key=ident,
        package_name=str(package) if isinstance(package, str) else None,
        run_profile=str(run_profile) if isinstance(run_profile, str) else None,
    )


def is_valid_dataset_run(inputs: RunInputs) -> bool:
    operator = inputs.manifest.get("operator") or {}
    if not isinstance(operator, dict):
        return False
    if str(operator.get("tier") or "").lower() != "dataset":
        return False
    validity = operator.get("dataset_validity")
    if not isinstance(validity, dict):
        return False
    return validity.get("valid_dataset_run") is True


def get_sampling_duration_seconds(inputs: RunInputs) -> float | None:
    if not isinstance(inputs.summary, dict):
        return None
    telemetry = (inputs.summary.get("telemetry") or {}).get("stats") or {}
    if not isinstance(telemetry, dict):
        return None
    value = telemetry.get("sampling_duration_seconds")
    try:
        return float(value)
    except Exception:
        return None


def compute_ml_preflight(inputs: RunInputs) -> MlPreflightResult:
    """Validate frozen inputs and compute windowing expectations.

    This is DB-free and deterministic; it must not depend on runtime state.
    """
    missing: list[str] = []

    # Required frozen inputs (PM locked).
    if not (inputs.run_dir / "run_manifest.json").exists():
        missing.append("run_manifest.json")
    if not (inputs.run_dir / "inputs" / "static_dynamic_plan.json").exists():
        missing.append("inputs/static_dynamic_plan.json")
    if not (inputs.run_dir / "analysis" / "summary.json").exists():
        missing.append("analysis/summary.json")
    if not (inputs.run_dir / "analysis" / "pcap_report.json").exists():
        missing.append("analysis/pcap_report.json")
    if not (inputs.run_dir / "analysis" / "pcap_features.json").exists():
        missing.append("analysis/pcap_features.json")
    if not inputs.pcap_path or not inputs.pcap_path.exists():
        missing.append("pcap")

    duration_s = get_sampling_duration_seconds(inputs)
    windows_total = 0
    dropped_partial = 0
    if duration_s and duration_s > 0:
        spec = WindowSpec(
            window_size_s=ml_config.WINDOW_SIZE_S,
            stride_s=ml_config.WINDOW_STRIDE_S,
        )
        windows, dropped = iter_windows(float(duration_s), spec)
        windows_total = len(windows)
        dropped_partial = int(dropped)

    frozen_ok = not missing
    skip_reason: str | None = None
    if missing:
        # Map missing frozen inputs to PM-approved skip enums.
        if "analysis/pcap_report.json" in missing:
            skip_reason = "ML_SKIPPED_MISSING_PROTOCOL_FEATURES"
        else:
            skip_reason = "ML_SKIPPED_EMPTY_FEATURE_VECTOR"
    elif windows_total <= 0:
        skip_reason = "ML_SKIPPED_INSUFFICIENT_WINDOWS"

    return MlPreflightResult(
        ml_schema_version=ml_config.ML_SCHEMA_VERSION,
        run_id=inputs.run_id,
        package_name=inputs.package_name,
        run_profile=inputs.run_profile,
        identity_key=inputs.identity_key,
        frozen_inputs_ok=frozen_ok,
        missing_inputs=missing,
        sampling_duration_seconds=duration_s,
        windows_total_expected=int(windows_total),
        dropped_partial_windows_expected=int(dropped_partial),
        skip_reason=skip_reason,
    )


def write_ml_preflight(path: Path, result: MlPreflightResult) -> None:
    payload = {
        "ml_schema_version": result.ml_schema_version,
        "run_id": result.run_id,
        "package_name": result.package_name,
        "run_profile": result.run_profile,
        "identity_key": result.identity_key,
        "frozen_inputs_ok": result.frozen_inputs_ok,
        "missing_inputs": result.missing_inputs,
        "sampling_duration_seconds": result.sampling_duration_seconds,
        "windows_total_expected": result.windows_total_expected,
        "dropped_partial_windows_expected": result.dropped_partial_windows_expected,
        "skip_reason": result.skip_reason,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

