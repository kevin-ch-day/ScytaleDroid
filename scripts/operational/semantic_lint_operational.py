#!/usr/bin/env python3
"""Operational snapshot semantic lint (Phase F2).

This is a *math audit* and consistency checker for query-mode snapshots under
output/operational/<snapshot_id>/.

It validates:
- required tables exist
- key ratios are internally consistent (pct = anomalous/windows)
- dynamic score/grade computations match the spec (docs/operational_risk_scoring.md)
- final regime/grade labels are consistent with exposure+deviation grades
- threshold stability fields are self-consistent

This is DB-free and intended for reproducible auditing.
"""

from __future__ import annotations

import argparse
import csv
import math
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    raise SystemExit(2)


def _warn(msg: str) -> None:
    print(f"[WARN] {msg}")


def _ok(msg: str) -> None:
    print(f"[OK] {msg}")


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
class LintConfig:
    tol_pct: float = 1e-6


def lint_snapshot(snapshot_dir: Path, *, cfg: LintConfig) -> None:
    tables = snapshot_dir / "tables"
    if not tables.exists():
        _fail(f"Missing tables dir: {tables}")

    required = [
        "coverage_confidence_per_group.csv",
        "threshold_stability_per_group_model.csv",
        "dynamic_math_audit_per_group_model.csv",
        "risk_summary_per_group.csv",
        "anomaly_persistence_per_run.csv",
        "anomaly_prevalence_per_group_mode.csv",
    ]
    missing = [f for f in required if not (tables / f).exists()]
    if missing:
        _fail("Missing required operational tables: " + ", ".join(missing))
    _ok("Required tables present.")

    # Load tables
    cov = _read_csv(tables / "coverage_confidence_per_group.csv")
    stab = _read_csv(tables / "threshold_stability_per_group_model.csv")
    audit = _read_csv(tables / "dynamic_math_audit_per_group_model.csv")
    risk = _read_csv(tables / "risk_summary_per_group.csv")
    pers = _read_csv(tables / "anomaly_persistence_per_run.csv")
    prev_gm = _read_csv(tables / "anomaly_prevalence_per_group_mode.csv")

    cov_idx = {r["group_key"]: r for r in cov if r.get("group_key")}
    risk_idx = {r["group_key"]: r for r in risk if r.get("group_key")}

    # Prevalence internal checks per group/model/mode (pct = anomalous/windows)
    bad_pct = 0
    for r in prev_gm:
        w = _as_int(r.get("windows_total"))
        a = _as_int(r.get("anomalous_windows"))
        p = _as_float(r.get("anomalous_pct"))
        if w is None or a is None or p is None or w <= 0:
            continue
        expect = float(a) / float(w)
        if not _approx_eq(expect, float(p), tol=cfg.tol_pct):
            bad_pct += 1
    if bad_pct:
        _fail(f"anomalous_pct mismatch rows: {bad_pct}")
    _ok("Prevalence ratios self-consistent (group_mode table).")

    # Threshold stability invariants: threshold between min/max, p95 <= max, etc.
    bad_thr = 0
    for r in stab:
        t = _as_float(r.get("threshold_value"))
        mn = _as_float(r.get("train_min"))
        mx = _as_float(r.get("train_max"))
        p95 = _as_float(r.get("train_p95"))
        if t is None or mn is None or mx is None:
            continue
        if not (mn - 1e-9 <= t <= mx + 1e-9):
            bad_thr += 1
        if p95 is not None and p95 > mx + 1e-9:
            bad_thr += 1
    if bad_thr:
        _fail(f"threshold stability invariants failed rows: {bad_thr}")
    _ok("Threshold stability invariants OK.")

    # Dynamic math audit must agree with underlying sources:
    # - interactive_anomalous_pct matches prevalence-per-group-mode (interactive) for same group/model
    prev_idx = {}
    for r in prev_gm:
        if r.get("mode") != "interactive":
            continue
        key = (r.get("group_key") or "", r.get("model") or "")
        prev_idx[key] = r
    bad_join = 0
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
            bad_join += 1
    if bad_join:
        _fail(f"dynamic_math_audit interactive pct mismatch rows: {bad_join}")
    _ok("Dynamic math audit aligns with interactive prevalence.")

    # Risk summary consistency: final labels align with exposure+deviation (IF primary)
    bad_final = 0
    for gk, r in risk_idx.items():
        exp = (r.get("exposure_grade") or "Unknown").split()[0]
        dev = (r.get("deviation_grade_if") or "Unknown").split()[0]
        final_reg = r.get("final_regime_if") or ""
        final_grade = (r.get("final_grade_if") or "").strip()
        if exp == "Unknown" or dev == "Unknown":
            continue
        expect_reg = f"{exp} Exposure + {dev} Deviation"
        if final_reg != expect_reg:
            bad_final += 1
            continue
        if exp == "Low" and dev == "Low":
            expect_grade = "Low"
        elif exp == "High" and dev == "High":
            expect_grade = "High"
        else:
            expect_grade = "Medium"
        if final_grade != expect_grade:
            bad_final += 1
    if bad_final:
        _fail(f"final regime/grade mismatch rows: {bad_final}")
    _ok("Final regime/grade labels consistent.")

    # Basic sanity: dynamic scores in [0,100]
    bad_range = 0
    for r in risk:
        for k in ("dynamic_deviation_score_if", "dynamic_deviation_score_oc", "static_exposure_score"):
            v = _as_float(r.get(k))
            if v is None:
                continue
            if not (0.0 <= v <= 100.0 + 1e-6):
                bad_range += 1
    if bad_range:
        _fail(f"score out-of-range rows: {bad_range}")
    _ok("Score ranges OK.")


def _latest_snapshot(root: Path) -> Path | None:
    if not root.exists():
        return None
    snaps = sorted([p for p in root.iterdir() if p.is_dir()])
    return snaps[-1] if snaps else None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", help="Path to output/operational/<snapshot_id> (default=latest).")
    args = ap.parse_args(argv)

    snap_root = ROOT / "output" / "operational"
    snap = Path(args.snapshot) if args.snapshot else _latest_snapshot(snap_root)
    if not snap:
        _fail(f"No operational snapshots found under {snap_root}")
    lint_snapshot(snap, cfg=LintConfig())
    _ok(f"Operational semantic lint passed: {snap}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

