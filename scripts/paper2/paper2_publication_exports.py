#!/usr/bin/env python3
"""Generate paper-facing cohort summary exports (Paper #2).

Outputs are written to stable manuscript-facing paths under `output/publication/`:
- tables/paper_cohort_summary_v1.csv
- tables/baseline_stability_summary.csv
- tables/interaction_delta_summary.csv
- tables/static_dynamic_correlation.csv
- manifests/paper_results_v1.json

Inputs:
- data/archive/dataset_freeze.json (canonical freeze anchor)
- output/_internal/paper2/baseline/tables/table_1_rdi_prevalence.csv (RDI prevalence by app/phase)
- output/_internal/paper2/baseline/tables/table_7_exposure_deviation_summary.csv (static-vs-dynamic)
- output/evidence/dynamic/<run_id>/run_manifest.json (window_count + run_profile)
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import platform
import statistics
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import scipy.stats

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Utils.IO.csv_with_provenance import read_csv_with_provenance

FREEZE = REPO_ROOT / "data" / "archive" / "dataset_freeze.json"
EVIDENCE_ROOT = REPO_ROOT / "output" / "evidence" / "dynamic"

PUB_ROOT = REPO_ROOT / "output" / "publication"
PUB_TABLES = PUB_ROOT / "tables"
PUB_MANIFESTS = PUB_ROOT / "manifests"

# Baseline bundle is the source-of-truth for internal baseline tables (Table 1-8).
# Publication outputs should stay minimal and paper-facing; do not depend on
# publication/ containing internal baseline tables.
INTERNAL_BASELINE_ROOT = REPO_ROOT / "output" / "_internal" / "paper2" / "baseline"

APP_ORDER = PUB_MANIFESTS / "app_ordering.json"
DISPLAY_MAP = PUB_MANIFESTS / "display_name_map.json"

TABLE_1 = INTERNAL_BASELINE_ROOT / "tables" / "table_1_rdi_prevalence.csv"
TABLE_7 = INTERNAL_BASELINE_ROOT / "tables" / "table_7_exposure_deviation_summary.csv"
APPENDIX_A1_OCSVM = PUB_TABLES / "appendix_table_a1_ocsvm_robustness.csv"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_csv_skip_comments(path: Path) -> list[dict[str, str]]:
    return read_csv_with_provenance(path).rows


def _write_csv_paper_facing(path: Path, *, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    """Write a plain CSV (no comment headers).

    Paper-facing CSVs should be directly sortable/filterable in standard tools
    (Excel/LibreOffice/pandas) without special provenance-aware parsing.

    Provenance lives in:
    - output/publication/manifests/paper_results_v1.json
    - output/publication/manifests/canonical_receipt.json
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


def _f(x: object) -> float:
    return float(str(x).strip())


def _i(x: object) -> int:
    return int(str(x).strip())


def _bootstrap_ci(values: list[float], *, statistic_fn, n: int = 10_000, alpha: float = 0.05, seed: int = 1337) -> tuple[float, float]:
    if not values:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    arr = np.array(values, dtype=float)
    stats = []
    for _ in range(int(n)):
        samp = rng.choice(arr, size=len(arr), replace=True)
        stats.append(float(statistic_fn(list(samp))))
    lo = float(np.quantile(stats, alpha / 2.0))
    hi = float(np.quantile(stats, 1.0 - alpha / 2.0))
    return lo, hi


def _bootstrap_spearman_ci(xs: list[float], ys: list[float], *, n: int = 10_000, alpha: float = 0.05, seed: int = 1337) -> tuple[float, float]:
    if len(xs) != len(ys) or not xs:
        return (float("nan"), float("nan"))
    rng = np.random.default_rng(seed)
    xs_a = np.array(xs, dtype=float)
    ys_a = np.array(ys, dtype=float)
    stats = []
    for _ in range(int(n)):
        idx = rng.integers(0, len(xs_a), size=len(xs_a), endpoint=False)
        r = scipy.stats.spearmanr(xs_a[idx], ys_a[idx]).statistic
        stats.append(float(r))
    lo = float(np.quantile(stats, alpha / 2.0))
    hi = float(np.quantile(stats, 1.0 - alpha / 2.0))
    return lo, hi


def _q(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    return float(np.quantile(np.array(values, dtype=float), q, method="linear"))


@dataclass(frozen=True)
class PaperResultsV1:
    schema_version: int
    generated_at_utc: str
    freeze_anchor: str
    freeze_sha256: str
    freeze_dataset_hash: str | None
    # Paper-facing metric name/units.
    metric_name: str
    metric_unit: str
    paper_contract_version: int | None
    freeze_contract_version: int | None
    n_apps: int
    n_runs_total: int
    n_runs_idle: int
    n_runs_interactive: int
    windows_total: int
    windows_idle_total: int
    windows_interactive_total: int
    windows_per_run_mean: float
    windows_per_run_min: int
    windows_per_run_max: int
    if_idle_mean: float
    if_idle_sd_sample: float
    if_delta_mean: float
    if_delta_pos_apps: int
    if_delta_pos_pct: float
    if_idle_mean_ci95: tuple[float, float]
    if_delta_mean_ci95: tuple[float, float]
    spearman_rho_static_vs_if_interactive: float
    spearman_p_static_vs_if_interactive: float
    spearman_rho_ci95: tuple[float, float]
    effect_size_cohens_dz: float
    wilcoxon_w_statistic: float | None
    wilcoxon_p_value: float | None
    per_app: list[dict[str, object]]
    notes: dict[str, object]
    toolchain: dict[str, str]
    host: dict[str, str]


def main() -> int:
    for p in (FREEZE, TABLE_1, TABLE_7):
        if not p.exists():
            raise SystemExit(f"Missing required input: {p}")

    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
    freeze_sha = _sha256_file(FREEZE)
    freeze_dataset_hash = freeze.get("freeze_dataset_hash")

    order = []
    if APP_ORDER.exists():
        try:
            order = json.loads(APP_ORDER.read_text(encoding="utf-8"))
        except Exception:
            order = []
    if not isinstance(order, list) or not order:
        order = sorted([str(k) for k in (freeze.get("apps") or {}).keys()])

    display = {}
    if DISPLAY_MAP.exists():
        try:
            display = json.loads(DISPLAY_MAP.read_text(encoding="utf-8"))
        except Exception:
            display = {}

    t1 = _read_csv_skip_comments(TABLE_1)
    t7 = _read_csv_skip_comments(TABLE_7)
    t1_by_app = {
        str(r.get("app") or "").strip(): r
        for r in t1
        if str(r.get("app") or "").strip()
    }
    t7_by_pkg = {
        str(r.get("package_name") or "").strip(): r
        for r in t7
        if str(r.get("package_name") or "").strip()
    }

    def _label_candidates(pkg: str) -> list[str]:
        cand: list[str] = []
        primary = str(display.get(pkg, "")).strip()
        if primary:
            cand.append(primary)
        t7_row = t7_by_pkg.get(pkg)
        if t7_row:
            t7_app = str(t7_row.get("app") or "").strip()
            if t7_app and t7_app not in cand:
                cand.append(t7_app)
        if pkg == "com.facebook.orca":
            for a in ("Facebook Messenger", "Facebook Msg"):
                if a not in cand:
                    cand.append(a)
        return cand

    def _t1_row_for_pkg(pkg: str) -> tuple[str, dict[str, str]]:
        for label in _label_candidates(pkg):
            if label in t1_by_app:
                return label, t1_by_app[label]
        raise SystemExit(f"Missing Table 1 row for package {pkg}; tried labels {_label_candidates(pkg)}")

    # Cohort-wide metrics from Table 1 (IF primary).
    if_idle = []
    if_interactive = []
    oc_idle = []
    oc_interactive = []
    idle_windows = []
    interactive_windows = []
    for pkg in order:
        app, r = _t1_row_for_pkg(pkg)
        if_idle.append(_f(r["if_idle"]))
        if_interactive.append(_f(r["if_interactive"]))
        oc_idle.append(_f(r["oc_idle"]))
        oc_interactive.append(_f(r["oc_interactive"]))
        idle_windows.append(_i(r["idle_windows"]))
        interactive_windows.append(_i(r["interactive_windows"]))

    if_delta = [b - a for a, b in zip(if_idle, if_interactive, strict=True)]
    n_apps = len(order)
    n_runs_idle = n_apps
    n_runs_interactive = n_apps * 2
    n_runs_total = n_runs_idle + n_runs_interactive
    windows_idle_total = int(sum(idle_windows))
    windows_interactive_total = int(sum(interactive_windows))
    windows_total = int(windows_idle_total + windows_interactive_total)

    if_idle_mean = float(statistics.mean(if_idle))
    if_idle_sd = float(statistics.stdev(if_idle))
    if_delta_mean = float(statistics.mean(if_delta))
    if_delta_pos_apps = int(sum(1 for d in if_delta if d > 0))
    if_delta_pos_pct = float(if_delta_pos_apps / float(n_apps) * 100.0)

    # Effect size (paired): Cohen's dz = mean(delta) / sd(delta).
    dz = float("nan")
    try:
        dz = float(if_delta_mean / statistics.stdev(if_delta))
    except Exception:
        dz = float("nan")

    # Static–dynamic correlation (from Table 7, IF interactive).
    xs = []
    ys = []
    for pkg in order:
        r = t7_by_pkg.get(pkg)
        if not r:
            raise SystemExit(f"Missing Table 7 row for package: {pkg}")
        xs.append(_f(r["static_exposure_score"]))
        ys.append(_f(r["rdi_if_interactive"]))
    sp = scipy.stats.spearmanr(xs, ys)

    # OCSVM robustness (Table 1 idle/scripted + Table 7 OC interactive for correlation).
    oc_delta = [b - a for a, b in zip(oc_idle, oc_interactive, strict=True)]
    oc_delta_mean = float(statistics.mean(oc_delta))
    oc_pos_apps = int(sum(1 for d in oc_delta if d > 0))
    oc_pos_pct = float(oc_pos_apps / float(n_apps) * 100.0) if n_apps else 0.0
    oc_rho = float("nan")
    oc_p = float("nan")
    try:
        oc_xs = []
        oc_ys = []
        for pkg in order:
            r = t7_by_pkg.get(pkg)
            if not r:
                raise RuntimeError(f"Missing Table 7 row for package: {pkg}")
            oc_xs.append(_f(r["static_exposure_score"]))
            oc_ys.append(_f(r["rdi_ocsvm_interactive"]))
        oc_sp = scipy.stats.spearmanr(oc_xs, oc_ys)
        oc_rho = float(oc_sp.statistic)
        oc_p = float(oc_sp.pvalue)
    except Exception:
        oc_rho = float("nan")
        oc_p = float("nan")

    # Wilcoxon signed-rank (paired, app-level).
    w_stat = None
    w_p = None
    try:
        w = scipy.stats.wilcoxon(
            if_idle,
            if_interactive,
            alternative="two-sided",
            zero_method="wilcox",
            method="auto",
        )
        w_stat = float(w.statistic) if w.statistic is not None else None
        w_p = float(w.pvalue) if w.pvalue is not None else None
    except Exception:
        w_stat = None
        w_p = None

    # Bootstrap CIs (small cohort, simple and reviewer-friendly).
    mu_ci = _bootstrap_ci(if_idle, statistic_fn=lambda v: statistics.mean(v))
    d_ci = _bootstrap_ci(if_delta, statistic_fn=lambda v: statistics.mean(v))
    rho_ci = _bootstrap_spearman_ci(xs, ys)

    # Build per-run window accounting from manifests (authoritative run-level count).
    included_run_ids = [str(x) for x in (freeze.get("included_run_ids") or [])]
    if len(included_run_ids) != 36:
        raise SystemExit(f"Unexpected included_run_ids count: {len(included_run_ids)} (expected 36)")

    runs_by_pkg: dict[str, dict[str, int]] = {pkg: {"idle": 0, "scripted": 0, "manual": 0, "other": 0} for pkg in order}
    windows_by_pkg: dict[str, dict[str, int]] = {pkg: {"idle": 0, "scripted": 0, "manual": 0, "other": 0} for pkg in order}
    per_run_windows: list[int] = []
    def _ml_window_count(run_id: str) -> int | None:
        """Preferred window count source: ML-scored windows (authoritative for RDI)."""
        p = EVIDENCE_ROOT / run_id / "analysis" / "ml" / "v1" / "anomaly_scores_iforest.csv"
        if not p.exists():
            return None
        try:
            # Count data rows; ignore header + blank lines.
            n = 0
            with p.open("r", encoding="utf-8") as f:
                for i, ln in enumerate(f):
                    if i == 0:
                        continue
                    if ln.strip():
                        n += 1
            return int(n)
        except Exception:
            return None

    for rid in included_run_ids:
        man_path = EVIDENCE_ROOT / rid / "run_manifest.json"
        man = json.loads(man_path.read_text(encoding="utf-8"))
        tgt = man.get("target") if isinstance(man.get("target"), dict) else {}
        pkg = str(tgt.get("package_name") or "").strip().lower()
        ds = man.get("dataset") if isinstance(man.get("dataset"), dict) else {}
        wc_i = _ml_window_count(rid)
        if wc_i is None:
            wc = ds.get("window_count")
            try:
                wc_i = int(wc) if wc not in (None, "") else 0
            except Exception:
                wc_i = 0
        per_run_windows.append(wc_i)
        op = man.get("operator") if isinstance(man.get("operator"), dict) else {}
        run_profile = str(op.get("run_profile") or ds.get("run_profile") or "").strip().lower()
        interaction_level = str(op.get("interaction_level") or ds.get("interaction_level") or "").strip().lower()

        bucket = "other"
        if run_profile.startswith("baseline"):
            bucket = "idle"
        elif "scripted" in run_profile or interaction_level == "scripted":
            bucket = "scripted"
        elif "manual" in run_profile or interaction_level == "manual":
            bucket = "manual"
        if pkg in runs_by_pkg:
            runs_by_pkg[pkg][bucket] += 1
            windows_by_pkg[pkg][bucket] += wc_i

    windows_per_run_mean = float(windows_total / float(n_runs_total)) if n_runs_total else 0.0
    windows_per_run_min = int(min(per_run_windows)) if per_run_windows else 0
    windows_per_run_max = int(max(per_run_windows)) if per_run_windows else 0
    runs_scripted_total = int(sum(runs_by_pkg[p]["scripted"] for p in order))
    runs_manual_total = int(sum(runs_by_pkg[p]["manual"] for p in order))
    runs_other_total = int(sum(runs_by_pkg[p]["other"] for p in order))
    runs_interactive_total = int(runs_scripted_total + runs_manual_total + runs_other_total)
    runs_idle_total_by_bucket = int(sum(runs_by_pkg[p]["idle"] for p in order))
    windows_scripted_total = int(sum(windows_by_pkg[p]["scripted"] for p in order))
    windows_manual_total = int(sum(windows_by_pkg[p]["manual"] for p in order))
    windows_other_total = int(sum(windows_by_pkg[p]["other"] for p in order))
    windows_interactive_total_by_bucket = int(windows_scripted_total + windows_manual_total + windows_other_total)
    windows_idle_total_by_bucket = int(sum(windows_by_pkg[p]["idle"] for p in order))

    # Export: paper_cohort_summary_v1.csv
    excluded_counts = freeze.get("excluded_reason_counts_by_app") if isinstance(freeze.get("excluded_reason_counts_by_app"), dict) else {}
    cohort_rows: list[dict[str, object]] = []
    for pkg in order:
        runs_interactive = int(runs_by_pkg[pkg]["scripted"] + runs_by_pkg[pkg]["manual"] + runs_by_pkg[pkg]["other"])
        windows_interactive = int(
            windows_by_pkg[pkg]["scripted"] + windows_by_pkg[pkg]["manual"] + windows_by_pkg[pkg]["other"]
        )
        cohort_rows.append(
            {
                "app": display.get(pkg, pkg),
                "package_name": pkg,
                "runs_idle": runs_by_pkg[pkg]["idle"],
                "runs_scripted": runs_by_pkg[pkg]["scripted"],
                "runs_manual": runs_by_pkg[pkg]["manual"],
                "runs_other": runs_by_pkg[pkg]["other"],
                "runs_interactive": runs_interactive,
                "runs_total": sum(runs_by_pkg[pkg].values()),
                "windows_idle": windows_by_pkg[pkg]["idle"],
                "windows_scripted": windows_by_pkg[pkg]["scripted"],
                "windows_manual": windows_by_pkg[pkg]["manual"],
                "windows_other": windows_by_pkg[pkg]["other"],
                "windows_interactive": windows_interactive,
                "windows_total": sum(windows_by_pkg[pkg].values()),
                "excluded_runs_total": int(sum((excluded_counts.get(pkg) or {}).values())) if isinstance(excluded_counts.get(pkg), dict) else 0,
                "excluded_reasons": json.dumps(excluded_counts.get(pkg) or {}, sort_keys=True),
            }
        )
    cohort_path = PUB_TABLES / "paper_cohort_summary_v1.csv"
    _write_csv_paper_facing(cohort_path, fieldnames=list(cohort_rows[0].keys()), rows=cohort_rows)

    # Export: baseline_stability_summary.csv (per-app + cohort summary).
    baseline_rows: list[dict[str, object]] = []
    for pkg in order:
        app, r = _t1_row_for_pkg(pkg)
        baseline_rows.append(
            {
                "app": app,
                "package_name": pkg,
                "if_idle_rdi": _f(r["if_idle"]),
                "oc_idle_rdi": _f(r["oc_idle"]),
                "idle_windows": _i(r["idle_windows"]),
                # Per-app std is undefined with 1 idle run; keep blank (reviewer-safe).
                "if_idle_sd_per_app": "",
            }
        )
    baseline_path = PUB_TABLES / "baseline_stability_summary.csv"
    _write_csv_paper_facing(baseline_path, fieldnames=list(baseline_rows[0].keys()), rows=baseline_rows)

    # Export: interaction_delta_summary.csv
    delta_rows: list[dict[str, object]] = []
    for pkg in order:
        app, r = _t1_row_for_pkg(pkg)
        idle = _f(r["if_idle"])
        inter = _f(r["if_interactive"])
        runs_interactive = int(runs_by_pkg[pkg]["scripted"] + runs_by_pkg[pkg]["manual"] + runs_by_pkg[pkg]["other"])
        delta_rows.append(
            {
                "app": app,
                "package_name": pkg,
                "if_idle_mean": idle,
                # NOTE: this is *interactive* mean (two interactive runs, may include scripted+manual depending on cohort).
                "if_interactive_mean": inter,
                "if_delta": inter - idle,
                "idle_windows": _i(r["idle_windows"]),
                "interactive_windows_total": _i(r["interactive_windows"]),
                "runs_interactive_total": runs_interactive,
                "runs_interactive_scripted": runs_by_pkg[pkg]["scripted"],
                "runs_interactive_manual": runs_by_pkg[pkg]["manual"],
                "runs_interactive_other": runs_by_pkg[pkg]["other"],
            }
        )
    delta_path = PUB_TABLES / "interaction_delta_summary.csv"
    _write_csv_paper_facing(delta_path, fieldnames=list(delta_rows[0].keys()), rows=delta_rows)

    # Export: Appendix Table A1 (OC-SVM robustness summary).
    oc_rows: list[dict[str, object]] = []
    for pkg in order:
        app, r = _t1_row_for_pkg(pkg)
        idle = _f(r["oc_idle"])
        inter = _f(r["oc_interactive"])
        runs_interactive = int(runs_by_pkg[pkg]["scripted"] + runs_by_pkg[pkg]["manual"] + runs_by_pkg[pkg]["other"])
        oc_rows.append(
            {
                "app": str(display.get(pkg, app) or app),
                "package_name": pkg,
                "oc_idle_mean": idle,
                "oc_interactive_mean": inter,
                "oc_delta": inter - idle,
                "idle_windows": _i(r["idle_windows"]),
                "interactive_windows_total": _i(r["interactive_windows"]),
                "runs_interactive_total": runs_interactive,
                "runs_interactive_scripted": runs_by_pkg[pkg]["scripted"],
                "runs_interactive_manual": runs_by_pkg[pkg]["manual"],
                "runs_interactive_other": runs_by_pkg[pkg]["other"],
            }
        )
    _write_csv_paper_facing(APPENDIX_A1_OCSVM, fieldnames=list(oc_rows[0].keys()), rows=oc_rows)

    # Export: static_dynamic_correlation.csv
    corr_rows: list[dict[str, object]] = []
    for pkg in order:
        r = t7_by_pkg[pkg]
        corr_rows.append(
            {
                # Always emit canonical manuscript display names.
                # Table 7 may contain legacy aliases (e.g., "Facebook Msg"), which we do not want
                # to leak into paper-facing exports.
                "app": str(display.get(pkg, pkg) or pkg),
                "package_name": pkg,
                "static_exposure_score": _f(r["static_exposure_score"]),
                "if_interactive_rdi_mean": _f(r["rdi_if_interactive"]),
                "runs_interactive_scripted": int(runs_by_pkg[pkg]["scripted"]),
                "runs_interactive_manual": int(runs_by_pkg[pkg]["manual"]),
            }
        )
    corr_path = PUB_TABLES / "static_dynamic_correlation.csv"
    _write_csv_paper_facing(corr_path, fieldnames=list(corr_rows[0].keys()), rows=corr_rows)

    # Export consolidated paper_results_v1.json (single source of truth for numbers).
    toolchain = {
        "python": sys.version.split()[0],
        "numpy": getattr(np, "__version__", "unknown"),
        "scipy": getattr(scipy, "__version__", "unknown"),
    }
    try:
        import sklearn

        toolchain["scikit_learn"] = getattr(sklearn, "__version__", "unknown")
    except Exception:
        toolchain["scikit_learn"] = "unknown"

    host = {
        "platform": platform.platform(),
        "os": os.name,
        "machine": platform.machine(),
    }

    # Per-app values + reviewer-facing notes.
    per_app: list[dict[str, object]] = []
    delta_negative = []
    delta_near_zero = []
    for pkg in order:
        app, r = _t1_row_for_pkg(pkg)
        idle = _f(r["if_idle"])
        inter = _f(r["if_interactive"])
        d = float(inter - idle)
        row = {
            "app": str(display.get(pkg, app) or app),
            "package_name": str(pkg),
            "idle_rdi_mean": float(idle),
            "interactive_rdi_mean": float(inter),
            # Back-compat alias.
            "scripted_rdi_mean": float(inter),
            "delta_rdi": float(d),
            "idle_windows": int(_i(r["idle_windows"])),
            "interactive_windows_total": int(_i(r["interactive_windows"])),
            # Back-compat alias.
            "scripted_windows_total": int(_i(r["interactive_windows"])),
            "runs_interactive_scripted": int(runs_by_pkg[pkg]["scripted"]),
            "runs_interactive_manual": int(runs_by_pkg[pkg]["manual"]),
            "runs_interactive_other": int(runs_by_pkg[pkg]["other"]),
        }
        per_app.append(row)
        if d < 0:
            delta_negative.append({"app": row["app"], "package_name": pkg, "delta_rdi": d})
        if abs(d) <= 0.01:
            delta_near_zero.append({"app": row["app"], "package_name": pkg, "delta_rdi": d})

    def _opt_int(x: object) -> int | None:
        try:
            s = str(x).strip()
            if not s:
                return None
            return int(s)
        except Exception:
            return None

    out = PaperResultsV1(
        schema_version=1,
        generated_at_utc=datetime.now(UTC).isoformat(),
        freeze_anchor=str(FREEZE.relative_to(REPO_ROOT)),
        freeze_sha256=freeze_sha,
        freeze_dataset_hash=str(freeze_dataset_hash) if freeze_dataset_hash else None,
        metric_name="RDI",
        metric_unit="ratio",
        paper_contract_version=_opt_int(freeze.get("paper_contract_version")),
        freeze_contract_version=_opt_int(freeze.get("freeze_contract_version")),
        n_apps=n_apps,
        n_runs_total=n_runs_total,
        n_runs_idle=n_runs_idle,
        n_runs_interactive=n_runs_interactive,
        windows_total=windows_total,
        windows_idle_total=windows_idle_total,
        windows_interactive_total=windows_interactive_total,
        windows_per_run_mean=windows_per_run_mean,
        windows_per_run_min=windows_per_run_min,
        windows_per_run_max=windows_per_run_max,
        if_idle_mean=if_idle_mean,
        if_idle_sd_sample=if_idle_sd,
        if_delta_mean=if_delta_mean,
        if_delta_pos_apps=if_delta_pos_apps,
        if_delta_pos_pct=if_delta_pos_pct,
        if_idle_mean_ci95=mu_ci,
        if_delta_mean_ci95=d_ci,
        spearman_rho_static_vs_if_interactive=float(sp.statistic),
        spearman_p_static_vs_if_interactive=float(sp.pvalue),
        spearman_rho_ci95=rho_ci,
        effect_size_cohens_dz=dz,
        wilcoxon_w_statistic=w_stat,
        wilcoxon_p_value=w_p,
        per_app=per_app,
        notes={
            "delta_negative_apps": delta_negative,
            "delta_near_zero_apps_abs_le_0_01": delta_near_zero,
            "spearman_observations_n": n_apps,
            "static_dynamic_fields": ["static_exposure_score", "interactive_rdi_mean"],
            "paired_design": "per-app means computed before cohort aggregation",
            "ocsvm_appendix_a1_path": str(APPENDIX_A1_OCSVM.relative_to(REPO_ROOT)),
            "ocsvm_delta_mean": oc_delta_mean,
            "ocsvm_pos_apps": oc_pos_apps,
            "ocsvm_pos_pct": oc_pos_pct,
            "ocsvm_pct_positive": oc_pos_pct,
            "ocsvm_spearman_rho_static_vs_oc_interactive": oc_rho,
            "ocsvm_spearman_p_static_vs_oc_interactive": oc_p,
            # Back-compat keys.
            "ocsvm_spearman_rho_static_vs_oc_scripted": oc_rho,
            "ocsvm_spearman_p_static_vs_oc_scripted": oc_p,
            "interaction_run_level_breakdown": {
                "runs_scripted_total": runs_scripted_total,
                "runs_manual_total": runs_manual_total,
                "runs_other_total": runs_other_total,
                "runs_interactive_total": runs_interactive_total,
                "runs_idle_total_by_bucket": runs_idle_total_by_bucket,
                "windows_scripted_total": windows_scripted_total,
                "windows_manual_total": windows_manual_total,
                "windows_other_total": windows_other_total,
                "windows_interactive_total_by_bucket": windows_interactive_total_by_bucket,
                "windows_idle_total_by_bucket": windows_idle_total_by_bucket,
            },
            # Distribution descriptors (reviewer-friendly).
            "idle_rdi_median": float(_q([float(r["idle_rdi_mean"]) for r in per_app], 0.5)),
            "idle_rdi_q25": float(_q([float(r["idle_rdi_mean"]) for r in per_app], 0.25)),
            "idle_rdi_q75": float(_q([float(r["idle_rdi_mean"]) for r in per_app], 0.75)),
            "idle_rdi_min": float(min(float(r["idle_rdi_mean"]) for r in per_app)),
            "idle_rdi_max": float(max(float(r["idle_rdi_mean"]) for r in per_app)),
            "interactive_rdi_median": float(_q([float(r["interactive_rdi_mean"]) for r in per_app], 0.5)),
            "interactive_rdi_q25": float(_q([float(r["interactive_rdi_mean"]) for r in per_app], 0.25)),
            "interactive_rdi_q75": float(_q([float(r["interactive_rdi_mean"]) for r in per_app], 0.75)),
            "delta_rdi_median": float(_q([float(r["delta_rdi"]) for r in per_app], 0.5)),
            "delta_rdi_q25": float(_q([float(r["delta_rdi"]) for r in per_app], 0.25)),
            "delta_rdi_q75": float(_q([float(r["delta_rdi"]) for r in per_app], 0.75)),
            "delta_rdi_min": float(min(float(r["delta_rdi"]) for r in per_app)),
            "delta_rdi_max": float(max(float(r["delta_rdi"]) for r in per_app)),
            "interactive_rdi_max": float(max(float(r["interactive_rdi_mean"]) for r in per_app)),
            "interactive_rdi_min": float(min(float(r["interactive_rdi_mean"]) for r in per_app)),
            "interactive_rdi_ge_0_95_apps": int(sum(1 for r in per_app if float(r["interactive_rdi_mean"]) >= 0.95)),
            # Back-compat duplicates (do not interpret as scripted-only unless manual_total==0).
            "scripted_rdi_median": float(_q([float(r["scripted_rdi_mean"]) for r in per_app], 0.5)),
            "scripted_rdi_q25": float(_q([float(r["scripted_rdi_mean"]) for r in per_app], 0.25)),
            "scripted_rdi_q75": float(_q([float(r["scripted_rdi_mean"]) for r in per_app], 0.75)),
            "scripted_rdi_max": float(max(float(r["scripted_rdi_mean"]) for r in per_app)),
            "scripted_rdi_min": float(min(float(r["scripted_rdi_mean"]) for r in per_app)),
            "scripted_rdi_ge_0_95_apps": int(sum(1 for r in per_app if float(r["scripted_rdi_mean"]) >= 0.95)),
        },
        toolchain=toolchain,
        host=host,
    )
    out_path = PUB_MANIFESTS / "paper_results_v1.json"
    out_path.write_text(json.dumps(asdict(out), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(str(cohort_path))
    print(str(baseline_path))
    print(str(delta_path))
    print(str(APPENDIX_A1_OCSVM))
    print(str(corr_path))
    print(str(out_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
