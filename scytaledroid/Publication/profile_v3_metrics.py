"""Profile v3 publication metrics (freeze/profile mode).

This module computes Profile v3 derived metrics from existing per-run ML artifacts:
- run-balanced phase means (each run contributes equally)
- pooled idle SD with ddof=1
- ISC and BSI with explicit null handling

It is intentionally read-only over evidence packs: no ML retraining, no backfill/repair.
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from scytaledroid.DynamicAnalysis.run_profile_norm import (
    RunProfileConflictError,
    phase_from_normalized_profile,
    resolve_run_profile_from_manifest,
)

ENGINE_IFOREST = "iforest"
ENGINE_ALIASES = {
    "iforest": ENGINE_IFOREST,
    "isolation_forest": ENGINE_IFOREST,
    "if": ENGINE_IFOREST,
    "isoforest": ENGINE_IFOREST,
}

ALLOWED_CATEGORIES = {"social_messaging", "cloud_productivity", "rtc_collaboration"}


class ProfileV3Error(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True)
class ScoreSchema:
    headers: tuple[str, ...]
    score_col: str
    window_id_col: str | None
    engine_col: str | None


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    package: str
    run_profile_raw: str
    phase: str  # idle|interactive
    device_fingerprint: str
    flags: list[int]


@dataclass(frozen=True)
class PerAppRow:
    package: str
    app: str
    app_category: str
    n_idle_runs: int
    n_interactive_runs: int
    idle_windows_total: int
    interactive_windows_total: int
    mu_idle_rdi: float
    sigma_idle_rdi: float
    mu_interactive_rdi: float
    delta_rdi: float
    isc: float | None
    isc_reason: str
    bsi: float | None
    bsi_reason: str
    device_fingerprints: tuple[str, ...]


def _rjson(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ProfileV3Error("PROFILE_V3_BAD_JSON", f"failed to read json {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ProfileV3Error("PROFILE_V3_BAD_JSON", f"expected object in {path}")
    return payload


def _norm_engine(value: object) -> str | None:
    s = str(value or "").strip().lower()
    if not s:
        return None
    return ENGINE_ALIASES.get(s)


def _find_first(headers: list[str], candidates: tuple[str, ...]) -> str | None:
    lowered = {h.strip().lower(): h for h in headers}
    for cand in candidates:
        if cand in lowered:
            return lowered[cand]
    return None


def inspect_window_scores_schema(path: Path) -> ScoreSchema:
    try:
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            headers = next(reader)
    except Exception as exc:  # noqa: BLE001
        raise ProfileV3Error(
            "PROFILE_V3_MISSING_WINDOW_SCORES_SCHEMA",
            f"unable to read window_scores header: {path}: {exc}",
        ) from exc
    headers = [str(h) for h in headers]
    score = _find_first(headers, ("score", "anomaly_score", "raw_score"))
    if not score:
        raise ProfileV3Error(
            "PROFILE_V3_MISSING_WINDOW_SCORES_SCHEMA",
            f"no accepted score column in {path}; headers={headers}",
        )
    window_id = _find_first(headers, ("window_id", "window_index", "t0_index"))
    engine = _find_first(headers, ("engine_id", "model", "engine"))
    return ScoreSchema(headers=tuple(headers), score_col=score, window_id_col=window_id, engine_col=engine)


def resolve_iforest_threshold(payload: dict[str, Any]) -> float:
    return resolve_iforest_threshold_with_source(payload)[0]


def resolve_iforest_threshold_with_source(payload: dict[str, Any]) -> tuple[float, str]:
    # Single value keys (preferred).
    candidates: list[tuple[str, float]] = []
    for key in ("threshold", "exceedance_threshold", "baseline_threshold", "rdi_threshold"):
        if key in payload:
            try:
                candidates.append((key, float(payload[key])))
            except Exception as exc:  # noqa: BLE001
                raise ProfileV3Error("PROFILE_V3_MISSING_THRESHOLD", f"bad threshold key {key}: {exc}") from exc
    if candidates:
        uniq = sorted({v for _, v in candidates})
        if len(uniq) > 1:
            raise ProfileV3Error(
                "PROFILE_V3_MISSING_THRESHOLD",
                f"ambiguous threshold keys present with different values: {candidates}",
            )
        # Preserve precedence: first matching key is the label we record.
        return candidates[0][1], candidates[0][0]

    # Multi-model layouts.
    thresholds = payload.get("thresholds")
    if isinstance(thresholds, dict) and ENGINE_IFOREST in thresholds:
        try:
            return float(thresholds[ENGINE_IFOREST]), "thresholds.iforest"
        except Exception as exc:  # noqa: BLE001
            raise ProfileV3Error("PROFILE_V3_MISSING_THRESHOLD", f"bad thresholds.iforest: {exc}") from exc

    models = payload.get("models")
    if isinstance(models, dict):
        iforest = models.get(ENGINE_IFOREST)
        if isinstance(iforest, dict) and "threshold" in iforest:
            try:
                return float(iforest["threshold"]), "models.iforest.threshold"
            except Exception as exc:  # noqa: BLE001
                raise ProfileV3Error("PROFILE_V3_MISSING_THRESHOLD", f"bad models.iforest.threshold: {exc}") from exc

    raise ProfileV3Error("PROFILE_V3_MISSING_THRESHOLD", "no resolvable iforest threshold")


def load_profile_v3_catalog(path: Path) -> dict[str, dict[str, str]]:
    payload = _rjson(path)
    out: dict[str, dict[str, str]] = {}
    for pkg, meta in payload.items():
        if not isinstance(meta, dict):
            raise ProfileV3Error("PROFILE_V3_BAD_CATALOG", f"catalog entry must be object: {pkg}")
        app = str(meta.get("app") or "").strip()
        cat = str(meta.get("app_category") or "").strip()
        if not app or not cat:
            raise ProfileV3Error("PROFILE_V3_BAD_CATALOG", f"missing app/app_category for {pkg}")
        if cat not in ALLOWED_CATEGORIES:
            raise ProfileV3Error("PROFILE_V3_BAD_CATALOG", f"invalid app_category for {pkg}: {cat}")
        out[str(pkg).strip()] = {"app": app, "app_category": cat}
    return out


def load_profile_v3_manifest(path: Path) -> dict[str, Any]:
    payload = _rjson(path)
    if str(payload.get("profile_id") or "").strip() != "profile_v3_structural":
        raise ProfileV3Error("PROFILE_V3_BAD_MANIFEST", f"unexpected profile_id in {path}")
    included = payload.get("included_run_ids")
    if not isinstance(included, list) or not included:
        raise ProfileV3Error("PROFILE_V3_BAD_MANIFEST", f"empty included_run_ids in {path}")
    return payload


def _extract_run_profile(run_manifest: dict[str, Any]) -> str:
    try:
        resolved = resolve_run_profile_from_manifest(run_manifest, strict_conflict=True)
    except RunProfileConflictError as exc:
        raise ProfileV3Error("PROFILE_V3_RUN_PROFILE_CONFLICT", str(exc)) from exc
    return str(resolved.normalized or "").strip().lower()


def _phase_from_profile(run_profile: str) -> str:
    phase = phase_from_normalized_profile(run_profile)
    if phase in {"idle", "interactive"}:
        return phase
    raise ProfileV3Error("PROFILE_V3_UNKNOWN_RUN_PROFILE", f"unrecognized run_profile: {run_profile}")


def _device_fingerprint(run_manifest: dict[str, Any]) -> str:
    env = run_manifest.get("environment") if isinstance(run_manifest.get("environment"), dict) else {}
    # Keep it as a stable string for CSVs (avoid schema churn).
    model = str(env.get("device_model") or env.get("model") or "").strip()
    android = str(env.get("android_version") or env.get("sdk_int") or "").strip()
    build = str(env.get("build_fingerprint") or env.get("fingerprint") or "").strip()
    parts = [p for p in (model, android, build) if p]
    return "|".join(parts) if parts else "unknown"


def resolve_ml_schema_dir(run_dir: Path) -> Path:
    """Resolve the canonical ML output directory for a run.

    Prefer v1 for backward compatibility. If multiple schema directories exist and
    none is v1, fail closed to avoid silent drift.
    """
    base = run_dir / "analysis" / "ml"
    if not base.exists():
        raise ProfileV3Error("PROFILE_V3_MISSING_ML_DIR", f"missing {base}")
    v1 = base / "v1"
    if v1.exists():
        return v1
    dirs = sorted([p for p in base.iterdir() if p.is_dir()], key=lambda p: p.name)
    if len(dirs) == 1:
        return dirs[0]
    found = [p.name for p in dirs]
    raise ProfileV3Error("PROFILE_V3_MISSING_ML_DIR", f"ambiguous ml schema dirs under {base}: {found}")


def inspect_run_inputs(
    *,
    run_dir: Path,
    allow_multi_model: bool,
) -> dict[str, object]:
    """Inspect a run directory and return provenance details for profile manifests."""
    ml_dir = resolve_ml_schema_dir(run_dir)
    scores_path = ml_dir / "window_scores.csv"
    thr_path = ml_dir / "baseline_threshold.json"
    if not scores_path.exists():
        raise ProfileV3Error("PROFILE_V3_MISSING_WINDOW_SCORES_SCHEMA", f"missing {scores_path}")
    if not thr_path.exists():
        raise ProfileV3Error("PROFILE_V3_MISSING_THRESHOLD", f"missing {thr_path}")
    schema = inspect_window_scores_schema(scores_path)
    thr_payload = _rjson(thr_path)
    threshold, threshold_source = resolve_iforest_threshold_with_source(thr_payload)
    return {
        "ml_schema_dir": str(ml_dir.relative_to(run_dir)),
        "window_scores_headers": list(schema.headers),
        "score_col": schema.score_col,
        "engine_col": schema.engine_col or "",
        "threshold_source": threshold_source,
        "threshold_value": float(threshold),
        "allow_multi_model": bool(allow_multi_model),
    }


def compute_run_flags(
    *,
    run_dir: Path,
    run_id: str,
    allow_multi_model: bool,
    allow_manual_interaction: bool,
) -> RunRecord:
    man_path = run_dir / "run_manifest.json"
    ml_dir = resolve_ml_schema_dir(run_dir)
    scores_path = ml_dir / "window_scores.csv"
    thr_path = ml_dir / "baseline_threshold.json"
    if not scores_path.exists():
        raise ProfileV3Error("PROFILE_V3_MISSING_WINDOW_SCORES_SCHEMA", f"missing {scores_path}")
    if not thr_path.exists():
        raise ProfileV3Error("PROFILE_V3_MISSING_THRESHOLD", f"missing {thr_path}")
    run_manifest = _rjson(man_path)
    target = run_manifest.get("target") if isinstance(run_manifest.get("target"), dict) else {}
    pkg = str(target.get("package_name") or target.get("package") or "").strip()
    if not pkg:
        raise ProfileV3Error("PROFILE_V3_BAD_MANIFEST", f"missing package_name in {man_path}")
    run_profile = _extract_run_profile(run_manifest)
    if run_profile == "interaction_manual" and not allow_manual_interaction:
        raise ProfileV3Error(
            "PROFILE_V3_MANUAL_RUN_NOT_ALLOWED",
            f"manual interaction runs are excluded in Profile v3 (run_id={run_id}, package={pkg})",
        )
    phase = _phase_from_profile(run_profile)
    device_fp = _device_fingerprint(run_manifest)
    threshold_payload = _rjson(thr_path)
    threshold = resolve_iforest_threshold(threshold_payload)

    schema = inspect_window_scores_schema(scores_path)
    flags: list[int] = []
    with scores_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not isinstance(row, dict):
                continue
            if schema.engine_col:
                eng_raw = row.get(schema.engine_col)
                eng = _norm_engine(eng_raw)
                if eng is None:
                    # Unknown engine id: ignore unless multi-model is enabled.
                    if allow_multi_model:
                        continue
                    continue
                if eng != ENGINE_IFOREST:
                    # Ignore non-primary engines unless explicit support is added.
                    continue
            # If engine column missing, treat as single-engine output (assumed iforest).
            try:
                score = float(str(row.get(schema.score_col) or "").strip())
            except Exception as exc:  # noqa: BLE001
                raise ProfileV3Error("PROFILE_V3_BAD_SCORE", f"bad score in {scores_path}: {exc}") from exc
            flags.append(1 if score > float(threshold) else 0)

    if not flags:
        raise ProfileV3Error("PROFILE_V3_INSUFFICIENT_WINDOWS_FOR_SD", f"no windows parsed in {scores_path}")

    return RunRecord(
        run_id=run_id,
        package=pkg,
        run_profile_raw=run_profile,
        phase=phase,
        device_fingerprint=device_fp,
        flags=flags,
    )


def compute_profile_v3_per_app(
    *,
    included_run_ids: list[str],
    evidence_root: Path,
    catalog: dict[str, dict[str, str]],
    allow_multi_model: bool,
    allow_manual_interaction: bool = False,
    allow_degenerate_metrics: bool = False,
) -> list[PerAppRow]:
    # Collect run records.
    runs: list[RunRecord] = []
    for run_id in included_run_ids:
        rid = str(run_id).strip()
        if not rid:
            continue
        run_dir = evidence_root / rid
        if not run_dir.exists():
            raise ProfileV3Error("PROFILE_V3_MISSING_RUN_DIR", f"missing run dir: {run_dir}")
        runs.append(
            compute_run_flags(
                run_dir=run_dir,
                run_id=rid,
                allow_multi_model=allow_multi_model,
                allow_manual_interaction=allow_manual_interaction,
            )
        )

    # Deterministic ordering for processing.
    def _run_sort_key(r: RunRecord) -> tuple:
        pkg = r.package
        meta = catalog.get(pkg)
        if meta is None:
            raise ProfileV3Error("PROFILE_V3_UNKNOWN_PACKAGE_NO_CATEGORY", f"package not in catalog: {pkg}")
        cat = meta["app_category"]
        phase = 0 if r.phase == "idle" else 1
        rp = r.run_profile_raw
        return (cat, pkg, phase, rp, r.run_id)

    runs.sort(key=_run_sort_key)

    # Group by app/package.
    by_pkg: dict[str, list[RunRecord]] = {}
    for r in runs:
        by_pkg.setdefault(r.package, []).append(r)

    out: list[PerAppRow] = []
    for pkg in sorted(by_pkg.keys(), key=lambda p: (catalog[p]["app_category"], p)):
        meta = catalog.get(pkg)
        if meta is None:
            raise ProfileV3Error("PROFILE_V3_UNKNOWN_PACKAGE_NO_CATEGORY", f"package not in catalog: {pkg}")
        idle = [r for r in by_pkg[pkg] if r.phase == "idle"]
        inter = [r for r in by_pkg[pkg] if r.phase == "interactive"]
        if not idle or not inter:
            raise ProfileV3Error("PROFILE_V3_MISSING_PHASE", f"missing idle/interactive for {pkg}")

        idle_run_means = [float(np.mean(r.flags)) for r in idle]
        inter_run_means = [float(np.mean(r.flags)) for r in inter]

        mu_idle = float(np.mean(idle_run_means))
        mu_inter = float(np.mean(inter_run_means))
        delta = float(mu_inter - mu_idle)

        pooled_idle_flags: list[int] = []
        for r in idle:
            pooled_idle_flags.extend(r.flags)
        if len(pooled_idle_flags) < 2:
            raise ProfileV3Error(
                "PROFILE_V3_INSUFFICIENT_WINDOWS_FOR_SD",
                f"need >=2 idle windows for pooled SD for {pkg}",
            )
        sigma_idle = float(np.std(np.array(pooled_idle_flags, dtype=float), ddof=1))
        if not allow_degenerate_metrics:
            if sigma_idle == 0.0:
                raise ProfileV3Error(
                    "PROFILE_V3_SIGMA_IDLE_ZERO",
                    f"sigma_idle is zero (degenerate idle dispersion) for {pkg}; rerun with --allow-degenerate-metrics to export null ISC/BSI",
                )
            if mu_idle <= 0.0:
                raise ProfileV3Error(
                    "PROFILE_V3_MU_IDLE_NONPOS",
                    f"mu_idle is non-positive for {pkg}; rerun with --allow-degenerate-metrics to export null BSI",
                )

        isc = None
        isc_reason = ""
        if sigma_idle == 0.0:
            isc_reason = "sigma_idle_zero"
        else:
            isc = float(delta / sigma_idle)

        bsi = None
        bsi_reason = ""
        if mu_idle <= 0.0:
            bsi_reason = "mu_idle_zero"
        else:
            cv_idle = float(sigma_idle / mu_idle)
            if cv_idle == 0.0:
                # This implies sigma==0 and mu!=0; BSI is infinite. Keep null with a reason.
                bsi_reason = "cv_idle_zero"
            else:
                bsi = float(1.0 / cv_idle)

        fps = sorted({r.device_fingerprint for r in by_pkg[pkg] if r.device_fingerprint})
        out.append(
            PerAppRow(
                package=pkg,
                app=meta["app"],
                app_category=meta["app_category"],
                n_idle_runs=len(idle),
                n_interactive_runs=len(inter),
                idle_windows_total=sum(len(r.flags) for r in idle),
                interactive_windows_total=sum(len(r.flags) for r in inter),
                mu_idle_rdi=mu_idle,
                sigma_idle_rdi=sigma_idle,
                mu_interactive_rdi=mu_inter,
                delta_rdi=delta,
                isc=isc,
                isc_reason=isc_reason,
                bsi=bsi,
                bsi_reason=bsi_reason,
                device_fingerprints=tuple(fps),
            )
        )

    return out


def env_allow_multi_model() -> bool:
    return str(os.environ.get("SCYTALEDROID_PROFILE_ALLOW_MULTI_MODEL") or "").strip() == "1"


__all__ = [
    "ENGINE_IFOREST",
    "ProfileV3Error",
    "PerAppRow",
    "inspect_window_scores_schema",
    "resolve_iforest_threshold",
    "resolve_iforest_threshold_with_source",
    "load_profile_v3_catalog",
    "load_profile_v3_manifest",
    "compute_profile_v3_per_app",
    "resolve_ml_schema_dir",
    "inspect_run_inputs",
    "env_allow_multi_model",
]
