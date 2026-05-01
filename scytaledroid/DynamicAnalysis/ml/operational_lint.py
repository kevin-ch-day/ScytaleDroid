"""Operational snapshot semantic lint (Phase F3).

This is a DB-free, deterministic consistency check for query-mode snapshots under:
  output/operational/<snapshot_id>/
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return [dict(r) for r in reader]


def _as_int(v: str | None) -> int | None:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        return int(float(s))
    except Exception:
        return None


def _as_float(v: str | None) -> float | None:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        return float(s)
    except Exception:
        return None


def _approx_eq(a: float, b: float, *, tol: float = 1e-6) -> bool:
    return abs(a - b) <= tol


@dataclass(frozen=True)
class OperationalLintResult:
    snapshot_dir: str
    ok: bool
    issues: list[str]


def lint_operational_snapshot(snapshot_dir: Path, *, tol_pct: float = 1e-6) -> OperationalLintResult:
    issues: list[str] = []
    tables = snapshot_dir / "tables"
    if not tables.exists():
        return OperationalLintResult(snapshot_dir=str(snapshot_dir), ok=False, issues=[f"missing_tables_dir:{tables}"])

    required = [
        "coverage_confidence_per_group.csv",
        "threshold_stability_per_group_model.csv",
        "dynamic_math_audit_per_group_model.csv",
        "risk_summary_per_group.csv",
        "anomaly_persistence_per_run.csv",
        "anomaly_prevalence_per_group_mode.csv",
    ]
    for f in required:
        if not (tables / f).exists():
            issues.append(f"missing_table:{f}")
    if issues:
        return OperationalLintResult(snapshot_dir=str(snapshot_dir), ok=False, issues=issues)

    stab = _read_csv(tables / "threshold_stability_per_group_model.csv")
    audit = _read_csv(tables / "dynamic_math_audit_per_group_model.csv")
    risk = _read_csv(tables / "risk_summary_per_group.csv")
    prev_gm = _read_csv(tables / "anomaly_prevalence_per_group_mode.csv")

    # Prevalence ratio checks.
    for r in prev_gm:
        w = _as_int(r.get("windows_total"))
        a = _as_int(r.get("anomalous_windows"))
        p = _as_float(r.get("anomalous_pct"))
        if w is None or a is None or p is None or w <= 0:
            continue
        expect = float(a) / float(w)
        if not _approx_eq(expect, float(p), tol=tol_pct):
            issues.append(f"pct_mismatch:{r.get('group_key')}:{r.get('model')}:{r.get('mode')}")

    # Threshold stability invariants.
    for r in stab:
        t = _as_float(r.get("threshold_value"))
        mn = _as_float(r.get("train_min"))
        mx = _as_float(r.get("train_max"))
        p95 = _as_float(r.get("train_p95"))
        if t is None or mn is None or mx is None:
            continue
        if not (mn - 1e-9 <= t <= mx + 1e-9):
            issues.append(f"threshold_out_of_range:{r.get('group_key')}:{r.get('model')}")
        if p95 is not None and p95 > mx + 1e-9:
            issues.append(f"p95_gt_max:{r.get('group_key')}:{r.get('model')}")

    # Audit aligns with interactive prevalence.
    prev_idx: dict[tuple[str, str], dict[str, str]] = {}
    for r in prev_gm:
        if r.get("mode") != "interactive":
            continue
        key = (r.get("group_key") or "", r.get("model") or "")
        prev_idx[key] = r
    for r in audit:
        gk = r.get("group_key") or ""
        model = r.get("model") or ""
        src = prev_idx.get((gk, model))
        if not src:
            continue
        a = _as_float(r.get("interactive_anomalous_pct"))
        b = _as_float(src.get("anomalous_pct"))
        if a is None or b is None:
            continue
        if not _approx_eq(a, b, tol=1e-9):
            issues.append(f"audit_prev_mismatch:{gk}:{model}")

    # Final labels consistent with exposure+deviation (IF primary).
    for r in risk:
        exp = (r.get("exposure_grade") or "Unknown").split()[0]
        dev = (r.get("deviation_grade_if") or "Unknown").split()[0]
        final_reg = r.get("final_regime_if") or ""
        final_grade = (r.get("final_grade_if") or "").strip()
        if exp == "Unknown" or dev == "Unknown":
            continue
        expect_reg = f"{exp} Exposure + {dev} Deviation"
        if final_reg != expect_reg:
            issues.append(f"final_regime_mismatch:{r.get('group_key')}")
            continue
        if exp == "Low" and dev == "Low":
            expect_grade = "Low"
        elif exp == "High" and dev == "High":
            expect_grade = "High"
        else:
            expect_grade = "Medium"
        if final_grade != expect_grade:
            issues.append(f"final_grade_mismatch:{r.get('group_key')}")

    # Score ranges in [0,100].
    for r in risk:
        for k in ("dynamic_deviation_score_if", "dynamic_deviation_score_oc", "static_exposure_score"):
            v = _as_float(r.get(k))
            if v is None:
                continue
            if not (0.0 <= v <= 100.0 + 1e-6):
                issues.append(f"score_out_of_range:{r.get('group_key')}:{k}")

    return OperationalLintResult(snapshot_dir=str(snapshot_dir), ok=(len(issues) == 0), issues=issues)


__all__ = ["OperationalLintResult", "lint_operational_snapshot"]

