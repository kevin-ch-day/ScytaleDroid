#!/usr/bin/env python3
"""Generate publication-facing cohort summary exports (freeze-anchored).

Outputs are written to stable publication-facing paths under `output/publication/`:
- tables/publication_cohort_summary_v1.csv
- tables/baseline_stability_summary.csv
- tables/interaction_delta_summary.csv
- tables/static_dynamic_correlation.csv
- manifests/publication_results_v1.json

Inputs:
- data/archive/dataset_freeze.json (canonical freeze anchor)
- output/_internal/publication/baseline/tables/table_1_rdi_prevalence.csv (RDI prevalence by app/phase)
- output/_internal/publication/baseline/tables/table_7_exposure_deviation_summary.csv (static-vs-dynamic)
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

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Utils.IO.csv_with_provenance import read_csv_with_provenance
from scytaledroid.Utils.LatexUtils import LatexTableSpec, RawLatex, render_tabular_only, render_table_float
from scytaledroid.DynamicAnalysis.ml import deliverable_bundle_paths as bundle_paths

FREEZE = REPO_ROOT / "data" / "archive" / "dataset_freeze.json"
EVIDENCE_ROOT = REPO_ROOT / "output" / "evidence" / "dynamic"

PUB_ROOT = REPO_ROOT / "output" / "publication"
PUB_TABLES = PUB_ROOT / "tables"
PUB_MANIFESTS = PUB_ROOT / "manifests"
PUB_QA = PUB_ROOT / "qa"

    # Baseline bundle is the source-of-truth for internal baseline tables (Table 1-8).
# Publication outputs should stay minimal and paper-facing; do not depend on
# publication/ containing internal baseline tables.
INTERNAL_BASELINE_ROOT = bundle_paths.existing_phase_e_bundle_root()
PUBLICATION_RESULTS = PUB_MANIFESTS / "publication_results_v1.json"
LEGACY_PUBLICATION_RESULTS = PUB_MANIFESTS / "paper_results_v1.json"

APP_ORDER = PUB_MANIFESTS / "app_ordering.json"
DISPLAY_MAP = PUB_MANIFESTS / "display_name_map.json"

TABLE_1 = INTERNAL_BASELINE_ROOT / "tables" / "table_1_rdi_prevalence.csv"
TABLE_7 = INTERNAL_BASELINE_ROOT / "tables" / "table_7_exposure_deviation_summary.csv"
TABLE_5_MASVS = INTERNAL_BASELINE_ROOT / "tables" / "table_5_masvs_coverage.csv"
TABLE_6_STATIC = INTERNAL_BASELINE_ROOT / "tables" / "table_6_static_posture_scores.csv"
APPENDIX_A1_OCSVM = PUB_TABLES / "appendix_table_a1_ocsvm_robustness.csv"

TEX_DYNAMIC_SUMMARY = PUB_TABLES / "table_dynamic_summary_v1.tex"
TEX_STATIC_COMPONENTS = PUB_TABLES / "table_static_components_v1.tex"
TEX_OCSVM_ROBUSTNESS = PUB_TABLES / "table_appendix_a1_ocsvm_robustness_v1.tex"

CSV_DELTA_DISTRIBUTION = PUB_TABLES / "delta_distribution_summary.csv"
TEX_DELTA_DISTRIBUTION = PUB_TABLES / "table_delta_distribution_summary_v1.tex"
TEX_COHORT_VARIANCE = PUB_TABLES / "table_cohort_variance_summary_v1.tex"
CSV_STATIC_DYNAMIC_COMPOSITE = PUB_TABLES / "static_dynamic_composite_v1.csv"
TEX_STATIC_DYNAMIC_COMPOSITE = PUB_TABLES / "table_static_dynamic_composite_v1.tex"
TEX_EFFECT_SIZE = PUB_TABLES / "table_effect_size_summary_v1.tex"
TEX_INTERACTION_CONSISTENCY = PUB_TABLES / "table_interaction_consistency_v1.tex"
CSV_PHASE_DISPERSION_STATS = PUB_TABLES / "phase_dispersion_stats_summary.csv"
TEX_PHASE_DISPERSION_STATS = PUB_TABLES / "table_phase_dispersion_stats_v1.tex"

FIG_DELTA_DISTRIBUTION_PNG = PUB_ROOT / "figures" / "fig_delta_distribution.png"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_csv_skip_comments(path: Path) -> list[dict[str, str]]:
    return read_csv_with_provenance(path).rows


def _write_csv_publication_facing(path: Path, *, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    """Write a plain CSV (no comment headers).

    Publication-facing CSVs should be directly sortable/filterable in standard tools
    (Excel/LibreOffice/pandas) without special provenance-aware parsing.

    Provenance lives in:
    - output/publication/manifests/publication_results_v1.json
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


def _read_run_manifest(run_id: str) -> dict[str, object]:
    p = EVIDENCE_ROOT / run_id / "run_manifest.json"
    return json.loads(p.read_text(encoding="utf-8"))


def _run_profile_bucket(run_manifest: dict[str, object]) -> str:
    """Map a run manifest to one of: idle, scripted, manual, other."""
    man = run_manifest
    ds = man.get("dataset") if isinstance(man.get("dataset"), dict) else {}
    op = man.get("operator") if isinstance(man.get("operator"), dict) else {}
    run_profile = str(op.get("run_profile") or ds.get("run_profile") or "").strip().lower()
    interaction_level = str(op.get("interaction_level") or ds.get("interaction_level") or "").strip().lower()

    if run_profile.startswith("baseline") or "baseline" in run_profile or "idle" in run_profile:
        return "idle"
    if "scripted" in run_profile or interaction_level == "scripted":
        return "scripted"
    if "manual" in run_profile or interaction_level == "manual":
        return "manual"
    return "other"


def _read_rdi_from_anomaly_scores(run_id: str, *, model_label: str) -> tuple[float | None, int | None]:
    """Return (RDI, windows) from per-window anomaly score CSV written by Phase E."""
    p = EVIDENCE_ROOT / run_id / "analysis" / "ml" / "v1" / f"anomaly_scores_{model_label}.csv"
    if not p.exists():
        return None, None
    try:
        n = 0
        anom = 0
        with p.open(newline="", encoding="utf-8") as f:
            r = csv.DictReader(f)
            for row in r:
                n += 1
                v = str(row.get("is_anomalous") or "").strip().lower()
                if v in ("true", "1", "yes", "y", "t"):
                    anom += 1
        if n <= 0:
            return None, 0
        return float(anom) / float(n), int(n)
    except Exception:
        return None, None


def _weighted_mean(values_and_weights: list[tuple[float, int]]) -> float | None:
    if not values_and_weights:
        return None
    num = 0.0
    den = 0
    for v, w in values_and_weights:
        if w <= 0:
            continue
        num += float(v) * float(w)
        den += int(w)
    if den <= 0:
        return None
    return float(num) / float(den)


def _fmt_optional(x: float | None) -> object:
    return "" if x is None else float(x)


def _read_plain_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        rows = [dict(row) for row in r]
    return list(r.fieldnames or []), rows


def _fmt_float_cell(x: object, *, ndp: int = 4) -> str:
    s = str(x).strip()
    if not s:
        return ""
    try:
        return f"{float(s):.{int(ndp)}f}"
    except Exception:
        return s


def _bootstrap_ci(
    values: list[float],
    *,
    statistic_fn,
    n: int = 10_000,
    alpha: float = 0.05,
    seed: int = 1337,
) -> tuple[float, float]:
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


def _try_write_delta_distribution_figure(*, deltas: list[float]) -> None:
    """Best-effort cohort-level ΔD distribution visualization.

    This is optional for the paper; failure to render should not fail exports.
    """
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return

    if not deltas:
        return

    figs_dir = (PUB_ROOT / "figures")
    figs_dir.mkdir(parents=True, exist_ok=True)

    xs = np.array(deltas, dtype=float)
    fig = plt.figure(figsize=(4.0, 2.4))
    ax = fig.add_subplot(1, 1, 1)
    ax.boxplot(
        xs,
        vert=False,
        widths=0.6,
        patch_artist=True,
        boxprops={"facecolor": "#E9EEF6", "edgecolor": "#2B3A55", "linewidth": 1.0},
        medianprops={"color": "#2B3A55", "linewidth": 1.2},
        whiskerprops={"color": "#2B3A55", "linewidth": 1.0},
        capprops={"color": "#2B3A55", "linewidth": 1.0},
    )
    # Overlay points (n=12 is small enough to be readable).
    rng = np.random.default_rng(1337)
    jitter = rng.uniform(-0.08, 0.08, size=len(xs))
    ax.scatter(xs, 1.0 + jitter, s=18, color="#1F6FEB", alpha=0.85, linewidths=0.0)
    ax.axvline(0.0, color="#666666", linewidth=0.8, linestyle="--")
    ax.set_yticks([])
    ax.set_xlabel(r"$\Delta D$ (per-app)")
    ax.grid(axis="x", alpha=0.25, linewidth=0.6)
    fig.tight_layout()
    fig.savefig(FIG_DELTA_DISTRIBUTION_PNG, dpi=220, bbox_inches="tight")
    plt.close(fig)


def _write_publication_latex_tables(*, publication_results_payload: dict[str, object] | None = None) -> None:
    """Write minimal IEEE-friendly LaTeX tables for manuscript inclusion.

    CSVs remain the authoritative publication-facing exports; LaTeX is a rendering layer.
    """
    PUB_TABLES.mkdir(parents=True, exist_ok=True)

    # Table: Dynamic summary (primary paper table)
    _, delta_rows = _read_plain_csv(PUB_TABLES / "interaction_delta_summary.csv")
    headers = ["App", "RDI (Idle)", "RDI (Interactive)", RawLatex(r"$\Delta D$")]
    body = []
    for r in delta_rows:
        body.append(
            [
                r.get("app", ""),
                _fmt_float_cell(r.get("if_idle_mean", ""), ndp=4),
                _fmt_float_cell(r.get("if_interactive_mean", ""), ndp=4),
                _fmt_float_cell(r.get("delta_d", ""), ndp=4),
            ]
        )
    tab = render_tabular_only(headers=headers, rows=body, align="lrrr")
    TEX_DYNAMIC_SUMMARY.write_text(
        render_table_float(
            spec=LatexTableSpec(
                caption=RawLatex(
                    r"Per-application Runtime Deviation Index (RDI) under idle and interactive execution (Isolation Forest), "
                    r"where $\Delta D = RDI_{\mathrm{int}} - RDI_{\mathrm{idle}}$."
                ),
                label="tab:dynamic_summary",
                placement="t",
                size_cmd="\\scriptsize",
            ),
            tabular_tex=tab,
        ),
        encoding="utf-8",
    )

    # Table: Static component transparency (paper table; prevents black-box critique)
    _, static_rows = _read_plain_csv(PUB_TABLES / "static_feature_groups_v1.csv")
    headers = ["App", "Exported", "Dangerous", "Cleartext", "SDK", "Static Score"]
    body = []
    for r in static_rows:
        body.append(
            [
                r.get("app", ""),
                r.get("exported_components_raw", ""),
                r.get("dangerous_permissions_raw", ""),
                r.get("network_cleartext_flag", ""),
                _fmt_float_cell(r.get("sdk_tracker_score_raw", ""), ndp=3),
                _fmt_float_cell(r.get("static_exposure_score", ""), ndp=2),
            ]
        )
    tab = render_tabular_only(headers=headers, rows=body, align="lrrrrr")
    TEX_STATIC_COMPONENTS.write_text(
        render_table_float(
            spec=LatexTableSpec(
                caption="Static exposure score components (0--100) used for contextual reporting and static--dynamic visualization.",
                label="tab:static_components",
                placement="t",
                size_cmd="\\scriptsize",
            ),
            tabular_tex=tab,
        ),
        encoding="utf-8",
    )

    # Table: Appendix A1 (OC-SVM robustness summary)
    _, oc_rows = _read_plain_csv(PUB_TABLES / "appendix_table_a1_ocsvm_robustness.csv")
    headers = ["App", "RDI (Idle)", "RDI (Interactive)", RawLatex(r"$\Delta$")]
    body = []
    for r in oc_rows:
        body.append(
            [
                r.get("app", ""),
                _fmt_float_cell(r.get("oc_idle_mean", ""), ndp=4),
                _fmt_float_cell(r.get("oc_interactive_mean", ""), ndp=4),
                _fmt_float_cell(r.get("oc_delta", ""), ndp=4),
            ]
        )
    tab = render_tabular_only(headers=headers, rows=body, align="lrrr")
    TEX_OCSVM_ROBUSTNESS.write_text(
        render_table_float(
            spec=LatexTableSpec(
                caption="OC-SVM robustness summary (RDI under idle vs interactive execution).",
                label="tab:ocsvm_robustness",
                placement="t",
                size_cmd="\\scriptsize",
            ),
            tabular_tex=tab,
        ),
        encoding="utf-8",
    )

    # --- Additional cohort-level artifacts (non-invasive, interpretation/stats support) ---
    # These are derived summaries only; they do not alter freeze selection or ML.

    # Delta distribution summary (CSV + LaTeX)
    deltas = [float(r.get("delta_d") or 0.0) for r in delta_rows]
    if deltas:
        delta_mean = float(statistics.mean(deltas))
        delta_sd = float(statistics.stdev(deltas)) if len(deltas) > 1 else 0.0
        delta_median = float(_q(deltas, 0.5))
        delta_q25 = float(_q(deltas, 0.25))
        delta_q75 = float(_q(deltas, 0.75))
        delta_min = float(min(deltas))
        delta_max = float(max(deltas))
        delta_pos = int(sum(1 for d in deltas if d > 0.0))
        delta_neg = int(sum(1 for d in deltas if d < 0.0))

        dd_rows = [
            {
                "n_apps": str(len(deltas)),
                "mean": f"{delta_mean:.6f}",
                "median": f"{delta_median:.6f}",
                "q25": f"{delta_q25:.6f}",
                "q75": f"{delta_q75:.6f}",
                "min": f"{delta_min:.6f}",
                "max": f"{delta_max:.6f}",
                "sd_sample": f"{delta_sd:.6f}",
                "pos_apps": str(delta_pos),
                "neg_apps": str(delta_neg),
            }
        ]
        _write_csv_publication_facing(CSV_DELTA_DISTRIBUTION, fieldnames=list(dd_rows[0].keys()), rows=dd_rows)

        headers = ["n", "Mean", "Median", "Q1", "Q3", "Min", "Max", "SD", "+", "−"]
        body = [
            [
                str(len(deltas)),
                f"{delta_mean:.4f}",
                f"{delta_median:.4f}",
                f"{delta_q25:.4f}",
                f"{delta_q75:.4f}",
                f"{delta_min:.4f}",
                f"{delta_max:.4f}",
                f"{delta_sd:.4f}",
                str(delta_pos),
                str(delta_neg),
            ]
        ]
        tab = render_tabular_only(headers=headers, rows=body, align="lrrrrrrrrr")
        TEX_DELTA_DISTRIBUTION.write_text(
            render_table_float(
                spec=LatexTableSpec(
                    caption=RawLatex(r"Distribution summary of per-application deviation shifts $\Delta D$ (Isolation Forest)."),
                    label="tab:delta_distribution_summary",
                    placement="t",
                    size_cmd="\\scriptsize",
                ),
                tabular_tex=tab,
            ),
            encoding="utf-8",
        )

        _try_write_delta_distribution_figure(deltas=deltas)

    # Cohort-level variance comparison (idle vs interactive, across apps)
    idle_vals = [float(r.get("if_idle_mean") or 0.0) for r in delta_rows]
    int_vals = [float(r.get("if_interactive_mean") or 0.0) for r in delta_rows]
    if idle_vals and int_vals:
        idle_mu = float(statistics.mean(idle_vals))
        idle_sd = float(statistics.stdev(idle_vals)) if len(idle_vals) > 1 else 0.0
        int_mu = float(statistics.mean(int_vals))
        int_sd = float(statistics.stdev(int_vals)) if len(int_vals) > 1 else 0.0
        var_ratio = float((int_sd * int_sd) / (idle_sd * idle_sd)) if idle_sd > 0 else float("nan")

        headers = ["Metric", "Idle", "Interactive"]
        body = [
            ["Mean", f"{idle_mu:.4f}", f"{int_mu:.4f}"],
            ["SD (sample)", f"{idle_sd:.4f}", f"{int_sd:.4f}"],
            [RawLatex(r"Variance ratio ($\sigma^2_{\mathrm{int}}/\sigma^2_{\mathrm{idle}}$)"), "", f"{var_ratio:.2f}"],
        ]
        tab = render_tabular_only(headers=headers, rows=body, align="lrr")
        TEX_COHORT_VARIANCE.write_text(
            render_table_float(
                spec=LatexTableSpec(
                    caption="Cohort-level idle vs interactive summary statistics (across applications; Isolation Forest).",
                    label="tab:cohort_variance_summary",
                    placement="t",
                    size_cmd="\\scriptsize",
                ),
                tabular_tex=tab,
            ),
            encoding="utf-8",
        )

    # Effect size / inferential summary (pull from paper_results payload to avoid drift).
    # Keep this table app-level (n=12).
    if publication_results_payload is None:
        publication_results_payload = {}
        try:
            source = PUBLICATION_RESULTS if PUBLICATION_RESULTS.exists() else LEGACY_PUBLICATION_RESULTS
            publication_results_payload = json.loads(source.read_text(encoding="utf-8"))
        except Exception:
            publication_results_payload = {}

    dz = publication_results_payload.get("effect_size_cohens_dz")
    w_stat = publication_results_payload.get("wilcoxon_w_statistic")
    w_p = publication_results_payload.get("wilcoxon_p_value")
    delta_mean = publication_results_payload.get("if_delta_mean")
    delta_ci = publication_results_payload.get("if_delta_mean_ci95")

    # Hedges' g small-sample correction for paired dz (df=n-1).
    hedges_gz = None
    try:
        if dz is not None and deltas and len(deltas) >= 2:
            df = float(len(deltas) - 1)
            j = 1.0 - (3.0 / (4.0 * df - 1.0))
            hedges_gz = float(j * float(dz))
    except Exception:
        hedges_gz = None

    headers = ["Statistic", "Value"]
    body: list[list[str]] = []
    if w_stat is not None and w_p is not None:
        body.append([RawLatex(r"Wilcoxon signed-rank ($W$)"), f"{float(w_stat):.1f} (p={float(w_p):.6g})"])
    if dz is not None:
        body.append([RawLatex(r"Cohen's $d_z$ (paired)"), f"{float(dz):.4f}"])
    if hedges_gz is not None:
        body.append([RawLatex(r"Hedges' $g_z$ (paired)"), f"{float(hedges_gz):.4f}"])
    if delta_mean is not None and isinstance(delta_ci, list) and len(delta_ci) == 2:
        body.append(
            [
                RawLatex(r"$\Delta_{\mathrm{mean}}$ (paired)"),
                f"{float(delta_mean):.4f} (95% CI [{float(delta_ci[0]):.4f}, {float(delta_ci[1]):.4f}])",
            ]
        )
    tab = render_tabular_only(headers=headers, rows=body, align="lr")
    TEX_EFFECT_SIZE.write_text(
        render_table_float(
            spec=LatexTableSpec(
                caption="Inferential and effect size summary (Isolation Forest; application-level).",
                label="tab:effect_size_summary",
                placement="t",
                size_cmd="\\scriptsize",
            ),
            tabular_tex=tab,
        ),
        encoding="utf-8",
    )

    # Phase dispersion / distribution diagnostics (application-level; n=12).
    # These are descriptive and do not change any paper numbers.
    if idle_vals and int_vals and len(idle_vals) == len(int_vals):
        try:
            idle_mu = float(statistics.mean(idle_vals))
            idle_sd = float(statistics.stdev(idle_vals)) if len(idle_vals) > 1 else 0.0
            int_mu = float(statistics.mean(int_vals))
            int_sd = float(statistics.stdev(int_vals)) if len(int_vals) > 1 else 0.0

            # 95% CI for mean via t-interval (n small).
            n = len(idle_vals)
            tcrit = float(scipy.stats.t.ppf(0.975, df=n - 1)) if n > 1 else float("nan")
            idle_ci = (
                float(idle_mu - tcrit * idle_sd / math.sqrt(n)),
                float(idle_mu + tcrit * idle_sd / math.sqrt(n)),
            )
            int_ci = (
                float(int_mu - tcrit * int_sd / math.sqrt(n)),
                float(int_mu + tcrit * int_sd / math.sqrt(n)),
            )

            cv_idle = float(idle_sd / idle_mu) if idle_mu != 0 else float("nan")
            cv_int = float(int_sd / int_mu) if int_mu != 0 else float("nan")

            idle_skew = float(scipy.stats.skew(idle_vals, bias=False))
            idle_kurt = float(scipy.stats.kurtosis(idle_vals, fisher=True, bias=False))
            int_skew = float(scipy.stats.skew(int_vals, bias=False))
            int_kurt = float(scipy.stats.kurtosis(int_vals, fisher=True, bias=False))

            sh_idle = scipy.stats.shapiro(idle_vals)
            sh_int = scipy.stats.shapiro(int_vals)

            mad_int = float(scipy.stats.median_abs_deviation(int_vals, scale=1.0))

            # Dispersion comparison (Levene / Brown-Forsythe).
            lev = scipy.stats.levene(idle_vals, int_vals, center="mean")
            bf = scipy.stats.levene(idle_vals, int_vals, center="median")

            # Unpaired Cohen's d for phase mean separation (idle vs interactive across apps).
            pooled = float(math.sqrt(((n - 1) * idle_sd * idle_sd + (n - 1) * int_sd * int_sd) / (2 * n - 2))) if n > 2 else float("nan")
            d_unpaired = float((int_mu - idle_mu) / pooled) if pooled and pooled == pooled and pooled > 0 else float("nan")
            j_unpaired = 1.0 - (3.0 / (4.0 * (2 * n - 2) - 1.0)) if n > 2 else float("nan")
            g_unpaired = float(j_unpaired * d_unpaired) if d_unpaired == d_unpaired else float("nan")

            rows = [
                {
                    "n_apps": n,
                    "idle_mu": idle_mu,
                    "idle_mu_ci95_lo": idle_ci[0],
                    "idle_mu_ci95_hi": idle_ci[1],
                    "idle_sd_sample": idle_sd,
                    "idle_cv": cv_idle,
                    "idle_skew": idle_skew,
                    "idle_kurtosis_fisher": idle_kurt,
                    "idle_shapiro_w": float(sh_idle.statistic),
                    "idle_shapiro_p": float(sh_idle.pvalue),
                    "int_mu": int_mu,
                    "int_mu_ci95_lo": int_ci[0],
                    "int_mu_ci95_hi": int_ci[1],
                    "int_sd_sample": int_sd,
                    "int_cv": cv_int,
                    "int_skew": int_skew,
                    "int_kurtosis_fisher": int_kurt,
                    "int_shapiro_w": float(sh_int.statistic),
                    "int_shapiro_p": float(sh_int.pvalue),
                    "int_mad": mad_int,
                    "variance_ratio_int_over_idle": float((int_sd * int_sd) / (idle_sd * idle_sd)) if idle_sd > 0 else float("nan"),
                    "levene_f_center_mean": float(lev.statistic),
                    "levene_p_center_mean": float(lev.pvalue),
                    "brown_forsythe_f_center_median": float(bf.statistic),
                    "brown_forsythe_p_center_median": float(bf.pvalue),
                    "cohens_d_unpaired_phase_means": d_unpaired,
                    "hedges_g_unpaired_phase_means": g_unpaired,
                }
            ]
            _write_csv_publication_facing(
                CSV_PHASE_DISPERSION_STATS,
                fieldnames=list(rows[0].keys()),
                rows=rows,
            )

            headers = ["Metric", "Idle", "Interactive"]
            body = [
                [RawLatex(r"Mean $\mu$ (95\% CI)"), f"{idle_mu:.4f} [{idle_ci[0]:.4f}, {idle_ci[1]:.4f}]", f"{int_mu:.4f} [{int_ci[0]:.4f}, {int_ci[1]:.4f}]"],
                ["SD (sample)", f"{idle_sd:.4f}", f"{int_sd:.4f}"],
                ["CV (SD/Mean)", f"{cv_idle:.3f}", f"{cv_int:.3f}"],
                ["Skewness", f"{idle_skew:.3f}", f"{int_skew:.3f}"],
                [RawLatex(r"Kurtosis (Fisher)"), f"{idle_kurt:.3f}", f"{int_kurt:.3f}"],
                [RawLatex(r"Shapiro--Wilk ($W$, $p$)"), f"{float(sh_idle.statistic):.3f}, {float(sh_idle.pvalue):.3f}", f"{float(sh_int.statistic):.3f}, {float(sh_int.pvalue):.3f}"],
                ["MAD", "—", f"{mad_int:.4f}"],
                [RawLatex(r"Variance ratio $\sigma^2_{\mathrm{int}}/\sigma^2_{\mathrm{idle}}$"), "—", f"{float((int_sd*int_sd)/(idle_sd*idle_sd)):.2f}" if idle_sd > 0 else ""],
                [RawLatex(r"Levene (center=mean) ($F$, $p$)"), "—", f"{float(lev.statistic):.3f}, {float(lev.pvalue):.3g}"],
                [RawLatex(r"Brown--Forsythe (center=median) ($F$, $p$)"), "—", f"{float(bf.statistic):.3f}, {float(bf.pvalue):.3g}"],
                [RawLatex(r"Cohen's $d$ (unpaired)"), "—", f"{d_unpaired:.3f}" if d_unpaired == d_unpaired else ""],
                [RawLatex(r"Hedges' $g$ (unpaired)"), "—", f"{g_unpaired:.3f}" if g_unpaired == g_unpaired else ""],
            ]
            tab = render_tabular_only(headers=headers, rows=body, align="lrr")
            TEX_PHASE_DISPERSION_STATS.write_text(
                render_table_float(
                    spec=LatexTableSpec(
                        caption=RawLatex(
                            r"Phase-level distribution and dispersion diagnostics computed from per-application mean RDI values (Isolation Forest; $n=12$)."
                        ),
                        label="tab:phase_dispersion_stats",
                        placement="t",
                        size_cmd="\\scriptsize",
                    ),
                    tabular_tex=tab,
                ),
                encoding="utf-8",
            )
        except Exception:
            # Best-effort only; do not fail paper exports on stats diagnostics.
            pass

    # Interactive consistency (scripted vs manual) where both modes exist.
    # Use the per-app means (paired design; n apps).
    scripted: list[float] = []
    manual: list[float] = []
    for r in delta_rows:
        s = str(r.get("if_scripted_mean") or "").strip()
        m = str(r.get("if_manual_mean") or "").strip()
        if s and m:
            scripted.append(float(s))
            manual.append(float(m))

    rho = float("nan")
    pval = float("nan")
    if len(scripted) >= 2:
        try:
            sp = scipy.stats.spearmanr(scripted, manual)
            rho = float(sp.statistic)
            pval = float(sp.pvalue)
        except Exception:
            rho = float("nan")
            pval = float("nan")

    diffs = [(s - m) for s, m in zip(scripted, manual)]
    abs_diffs = [abs(d) for d in diffs]
    mean_abs = float(statistics.mean(abs_diffs)) if abs_diffs else float("nan")
    med_abs = float(statistics.median(abs_diffs)) if abs_diffs else float("nan")
    max_abs = float(max(abs_diffs)) if abs_diffs else float("nan")
    rmse = float(math.sqrt(statistics.mean([d * d for d in diffs]))) if diffs else float("nan")

    headers = [
        "n",
        RawLatex(r"Spearman $\rho$"),
        RawLatex(r"$p$"),
        RawLatex(r"Mean $|\Delta|$"),
        RawLatex(r"Median $|\Delta|$"),
        RawLatex(r"Max $|\Delta|$"),
        "RMSE",
    ]
    body = [
        [
            str(len(diffs)),
            f"{rho:.3f}" if rho == rho else "",
            ("<0.001" if (pval == pval and pval < 0.001) else (f"{pval:.3f}" if pval == pval else "")),
            f"{mean_abs:.4f}" if mean_abs == mean_abs else "",
            f"{med_abs:.4f}" if med_abs == med_abs else "",
            f"{max_abs:.4f}" if max_abs == max_abs else "",
            f"{rmse:.4f}" if rmse == rmse else "",
        ]
    ]
    tab = render_tabular_only(headers=headers, rows=body, align="lrrrrrr")
    TEX_INTERACTION_CONSISTENCY.write_text(
        render_table_float(
            spec=LatexTableSpec(
                caption=RawLatex(
                    r"Scripted vs.\ manual interactive comparison (Isolation Forest; descriptive) for applications where both modes were executed ($n$ apps). "
                    r"Differences are computed per application using mean interactive RDI per mode."
                ),
                label="tab:interaction_consistency",
                placement="t",
                size_cmd="\\scriptsize",
                pre_tabular_tex="\\setlength{\\tabcolsep}{4pt}",
            ),
            tabular_tex=tab,
        ),
        encoding="utf-8",
    )

    # Static–dynamic composite table (explicitly exploratory; derived only)
    # Composite = 0.5 * StaticScore + 0.5 * DeltaNorm100, where DeltaNorm100 is min-max scaled in-cohort.
    _, static_rows = _read_plain_csv(PUB_TABLES / "static_feature_groups_v1.csv")
    static_by_app = {r.get("app", ""): r for r in static_rows}
    delta_min = min(deltas) if deltas else 0.0
    delta_max = max(deltas) if deltas else 0.0
    comp_rows = []
    for r in delta_rows:
        app = r.get("app", "")
        st = static_by_app.get(app, {})
        static_score = float(str(st.get("static_exposure_score") or "0").strip() or 0.0)
        d = float(r.get("delta_d") or 0.0)
        if delta_max > delta_min:
            d_norm = 100.0 * (d - delta_min) / (delta_max - delta_min)
        else:
            d_norm = 0.0
        comp = 0.5 * static_score + 0.5 * d_norm
        comp_rows.append(
            {
                "app": app,
                "package_name": r.get("package_name", ""),
                "static_score_0_100": f"{static_score:.2f}",
                "rdi_idle": _fmt_float_cell(r.get("if_idle_mean", ""), ndp=4),
                "rdi_interactive": _fmt_float_cell(r.get("if_interactive_mean", ""), ndp=4),
                "delta_d": _fmt_float_cell(r.get("delta_d", ""), ndp=4),
                "delta_d_norm_0_100": f"{d_norm:.2f}",
                "composite_0_100": f"{comp:.2f}",
            }
        )
    # Rank by composite descending for convenience.
    comp_rows.sort(key=lambda rr: (-float(rr.get("composite_0_100") or 0.0), str(rr.get("app") or "")))
    _write_csv_publication_facing(CSV_STATIC_DYNAMIC_COMPOSITE, fieldnames=list(comp_rows[0].keys()), rows=comp_rows)

    headers = ["App", "Static", RawLatex(r"$\Delta D$"), RawLatex(r"$\Delta D$ (norm)"), "Composite"]
    body = [
        [
            rr["app"],
            rr["static_score_0_100"],
            rr["delta_d"],
            rr["delta_d_norm_0_100"],
            rr["composite_0_100"],
        ]
        for rr in comp_rows
    ]
    tab = render_tabular_only(headers=headers, rows=body, align="lrrrr")
    TEX_STATIC_DYNAMIC_COMPOSITE.write_text(
        render_table_float(
            spec=LatexTableSpec(
                caption=RawLatex(
                    r"Exploratory static--dynamic composite ranking (interpretive only): "
                    r"Composite $=0.5\cdot S + 0.5\cdot \Delta D_{\mathrm{norm}}$, "
                    r"where $S$ is the static exposure score (0--100) and $\Delta D_{\mathrm{norm}}$ is min--max scaled within cohort."
                ),
                label="tab:static_dynamic_composite",
                placement="t",
                size_cmd="\\scriptsize",
            ),
            tabular_tex=tab,
        ),
        encoding="utf-8",
    )


@dataclass(frozen=True)
class PublicationResultsV1:
    schema_version: int
    generated_at_utc: str
    freeze_anchor: str
    freeze_sha256: str
    freeze_dataset_hash: str | None
    # Report-facing metric name/units.
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


def generate_publication_exports() -> int:
    for p in (FREEZE, TABLE_1, TABLE_5_MASVS, TABLE_6_STATIC, TABLE_7):
        if not p.exists():
            raise SystemExit(f"Missing required input: {p}")

    PUB_TABLES.mkdir(parents=True, exist_ok=True)
    PUB_MANIFESTS.mkdir(parents=True, exist_ok=True)

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
    t5 = _read_csv_skip_comments(TABLE_5_MASVS)
    t6 = _read_csv_skip_comments(TABLE_6_STATIC)
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
    t5_by_pkg = {
        str(r.get("package_name") or "").strip(): r
        for r in t5
        if str(r.get("package_name") or "").strip()
    }
    t6_by_pkg = {
        str(r.get("package_name") or "").strip(): r
        for r in t6
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
    # Per-app IF RDI means derived from per-run scored windows (scripted/manual split).
    if_rdi_by_pkg: dict[str, dict[str, list[tuple[float, int]]]] = {pkg: {"idle": [], "scripted": [], "manual": [], "other": []} for pkg in order}

    for rid in included_run_ids:
        man = _read_run_manifest(rid)
        tgt = man.get("target") if isinstance(man.get("target"), dict) else {}
        pkg = str(tgt.get("package_name") or "").strip().lower()
        ds = man.get("dataset") if isinstance(man.get("dataset"), dict) else {}
        bucket = _run_profile_bucket(man)

        rdi_if, wc_i = _read_rdi_from_anomaly_scores(rid, model_label="iforest")
        if wc_i is None:
            wc = ds.get("window_count")
            try:
                wc_i = int(wc) if wc not in (None, "") else 0
            except Exception:
                wc_i = 0
        per_run_windows.append(int(wc_i))
        if pkg in runs_by_pkg:
            runs_by_pkg[pkg][bucket] += 1
            windows_by_pkg[pkg][bucket] += int(wc_i)
            if rdi_if is not None and wc_i is not None:
                if_rdi_by_pkg[pkg][bucket].append((float(rdi_if), int(wc_i)))

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

    # Export: publication_cohort_summary_v1.csv
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
    cohort_path = PUB_TABLES / "publication_cohort_summary_v1.csv"
    _write_csv_publication_facing(cohort_path, fieldnames=list(cohort_rows[0].keys()), rows=cohort_rows)

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
    _write_csv_publication_facing(baseline_path, fieldnames=list(baseline_rows[0].keys()), rows=baseline_rows)

    # Export: interaction_delta_summary.csv
    delta_rows: list[dict[str, object]] = []
    for pkg in order:
        app, r = _t1_row_for_pkg(pkg)
        idle = _f(r["if_idle"])
        inter_t1 = _f(r["if_interactive"])
        if_scripted_mean = _weighted_mean(if_rdi_by_pkg[pkg]["scripted"])
        if_manual_mean = _weighted_mean(if_rdi_by_pkg[pkg]["manual"])
        if_interactive_mean = _weighted_mean(
            if_rdi_by_pkg[pkg]["scripted"] + if_rdi_by_pkg[pkg]["manual"] + if_rdi_by_pkg[pkg]["other"]
        )
        # Fail-safe: if we could not derive it from per-run ML windows, fall back to Table 1.
        if_interactive_mean = if_interactive_mean if if_interactive_mean is not None else inter_t1
        delta_d = float(if_interactive_mean - idle)
        abs_scripted_minus_manual: float | None = None
        if if_scripted_mean is not None and if_manual_mean is not None:
            abs_scripted_minus_manual = float(abs(if_scripted_mean - if_manual_mean))
        runs_interactive = int(runs_by_pkg[pkg]["scripted"] + runs_by_pkg[pkg]["manual"] + runs_by_pkg[pkg]["other"])
        delta_rows.append(
            {
                "app": app,
                "package_name": pkg,
                "if_idle_mean": idle,
                "if_scripted_mean": _fmt_optional(if_scripted_mean),
                "if_manual_mean": _fmt_optional(if_manual_mean),
                # NOTE: this is the *interactive* mean across two interactive runs (scripted/manual mix allowed).
                "if_interactive_mean": float(if_interactive_mean),
    # Interaction sensitivity scalar for the frozen cohort.
                "delta_d": float(delta_d),
                # Consistency check (only defined when both buckets present).
                "abs_rdi_scripted_minus_manual": _fmt_optional(abs_scripted_minus_manual),
                "idle_windows": _i(r["idle_windows"]),
                "interactive_windows_total": _i(r["interactive_windows"]),
                "scripted_windows_total": int(windows_by_pkg[pkg]["scripted"]),
                "manual_windows_total": int(windows_by_pkg[pkg]["manual"]),
                "runs_interactive_total": runs_interactive,
                "runs_interactive_scripted": runs_by_pkg[pkg]["scripted"],
                "runs_interactive_manual": runs_by_pkg[pkg]["manual"],
                "runs_interactive_other": runs_by_pkg[pkg]["other"],
            }
        )
    delta_path = PUB_TABLES / "interaction_delta_summary.csv"
    _write_csv_publication_facing(delta_path, fieldnames=list(delta_rows[0].keys()), rows=delta_rows)

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
    _write_csv_publication_facing(APPENDIX_A1_OCSVM, fieldnames=list(oc_rows[0].keys()), rows=oc_rows)

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
    _write_csv_publication_facing(corr_path, fieldnames=list(corr_rows[0].keys()), rows=corr_rows)

    # Export: static_feature_groups_v1.csv (structured static groups; static context support).
    # This is a paper-facing convenience export that aggregates the existing baseline bundle tables:
    # - Table 6 (static posture components + scalar)
    # - Table 5 (MASVS-domain grouped finding counts)
    static_rows: list[dict[str, object]] = []
    for pkg in order:
        t6r = t6_by_pkg.get(pkg)
        t5r = t5_by_pkg.get(pkg)
        if not t6r or not t5r:
            raise SystemExit(f"Missing static inputs for package {pkg}: t6={bool(t6r)} t5={bool(t5r)}")
        static_rows.append(
            {
                "app": str(display.get(pkg, pkg) or pkg),
                "package_name": pkg,
                # Static posture groups (Table 6 inputs)
                "exported_components_raw": _i(t6r.get("exported_raw") or 0),
                "dangerous_permissions_raw": _i(t6r.get("dangerous_raw") or 0),
                "network_cleartext_flag": _i(t6r.get("cleartext_flag") or 0),
                "sdk_tracker_score_raw": _f(t6r.get("sdk_score") or 0.0),
                # Final scalar used in Spearman / Fig B4 (0-100).
                "static_exposure_score": _f(t6r.get("static_posture_score") or 0.0),
                # MASVS-domain grouped finding counts (Table 5)
                "masvs_finding_count_total": _i(t5r.get("finding_count_total") or 0),
                "masvs_finding_count_p0": _i(t5r.get("finding_count_p0") or 0),
                "masvs_finding_count_p1": _i(t5r.get("finding_count_p1") or 0),
                "masvs_finding_count_p2": _i(t5r.get("finding_count_p2") or 0),
                "masvs_finding_count_note": _i(t5r.get("finding_count_note") or 0),
                "masvs_finding_count_platform": _i(t5r.get("finding_count_platform") or 0),
                "masvs_finding_count_network": _i(t5r.get("finding_count_network") or 0),
                "masvs_finding_count_privacy": _i(t5r.get("finding_count_privacy") or 0),
                "masvs_finding_count_storage": _i(t5r.get("finding_count_storage") or 0),
                "masvs_finding_count_crypto": _i(t5r.get("finding_count_crypto") or 0),
                "masvs_finding_count_resilience": _i(t5r.get("finding_count_resilience") or 0),
                "masvs_finding_count_other": _i(t5r.get("finding_count_other") or 0),
            }
        )
    static_groups_path = PUB_TABLES / "static_feature_groups_v1.csv"
    _write_csv_publication_facing(static_groups_path, fieldnames=list(static_rows[0].keys()), rows=static_rows)

    # Export: stimulus_coverage_v1.csv (what interaction stimulus was actually exercised).
    #
    # This is intentionally factual and derived from run manifests:
    # - scripted runs surface script_name (when present)
    # - manual runs surface messaging_activity / run_context fields
    #
    # We do not attempt to infer "login/media/link-out" unless the protocol explicitly records it.
    stim_by_pkg: dict[str, dict[str, set[str]]] = {pkg: {"script_names": set(), "manual_activity": set(), "scenario_ids": set()} for pkg in order}
    for rid in included_run_ids:
        man = _read_run_manifest(rid)
        tgt = man.get("target") if isinstance(man.get("target"), dict) else {}
        pkg = str(tgt.get("package_name") or "").strip().lower()
        if pkg not in stim_by_pkg:
            continue
        bucket = _run_profile_bucket(man)
        if bucket == "idle":
            continue
        op = man.get("operator") if isinstance(man.get("operator"), dict) else {}
        ctx = op.get("run_context") if isinstance(op.get("run_context"), dict) else {}
        scenario_id = str(ctx.get("scenario_id") or (man.get("scenario") or {}).get("id") or "").strip()
        if scenario_id:
            stim_by_pkg[pkg]["scenario_ids"].add(scenario_id)
        if bucket == "scripted":
            s = str(op.get("script_name") or "").strip()
            if s:
                stim_by_pkg[pkg]["script_names"].add(s)
        if bucket == "manual":
            a = str(op.get("messaging_activity") or ctx.get("messaging_activity") or "").strip()
            if a:
                stim_by_pkg[pkg]["manual_activity"].add(a)

    stim_rows: list[dict[str, object]] = []
    for pkg in order:
        t6r = t6_by_pkg.get(pkg) or {}
        stim_rows.append(
            {
                "app": str(display.get(pkg, pkg) or pkg),
                "package_name": pkg,
                "runs_interactive_scripted": int(runs_by_pkg[pkg]["scripted"]),
                "runs_interactive_manual": int(runs_by_pkg[pkg]["manual"]),
                "script_names": ",".join(sorted(stim_by_pkg[pkg]["script_names"])),
                "manual_activity_tags": ",".join(sorted(stim_by_pkg[pkg]["manual_activity"])),
                "scenario_ids": ",".join(sorted(stim_by_pkg[pkg]["scenario_ids"])),
                "static_reason_notes": str(t6r.get("notes") or ""),
            }
        )
    stim_path = PUB_TABLES / "stimulus_coverage_v1.csv"
    _write_csv_publication_facing(stim_path, fieldnames=list(stim_rows[0].keys()), rows=stim_rows)

    # Export: qa_interactive_consistency.csv (per-app scripted vs manual consistency, where applicable).
    # This supports reviewer questions without changing the frozen cohort.
    cons_rows: list[dict[str, object]] = []
    for pkg in order:
        t1_app, t1r = _t1_row_for_pkg(pkg)
        if_scripted_mean = _weighted_mean(if_rdi_by_pkg[pkg]["scripted"])
        if_manual_mean = _weighted_mean(if_rdi_by_pkg[pkg]["manual"])
        abs_scripted_minus_manual = None
        if if_scripted_mean is not None and if_manual_mean is not None:
            abs_scripted_minus_manual = float(abs(if_scripted_mean - if_manual_mean))
        cons_rows.append(
            {
                "app": str(display.get(pkg, t1_app) or t1_app),
                "package_name": pkg,
                "if_scripted_mean": _fmt_optional(if_scripted_mean),
                "if_manual_mean": _fmt_optional(if_manual_mean),
                "abs_rdi_scripted_minus_manual": _fmt_optional(abs_scripted_minus_manual),
                "runs_interactive_scripted": int(runs_by_pkg[pkg]["scripted"]),
                "runs_interactive_manual": int(runs_by_pkg[pkg]["manual"]),
                "scripted_windows_total": int(windows_by_pkg[pkg]["scripted"]),
                "manual_windows_total": int(windows_by_pkg[pkg]["manual"]),
            }
        )
    PUB_QA.mkdir(parents=True, exist_ok=True)
    cons_path = PUB_QA / "qa_interactive_consistency.csv"
    _write_csv_publication_facing(cons_path, fieldnames=list(cons_rows[0].keys()), rows=cons_rows)

    # Export consolidated publication_results_v1.json (single source of truth for numbers).
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
        inter_t1 = _f(r["if_interactive"])
        if_scripted_mean = _weighted_mean(if_rdi_by_pkg[pkg]["scripted"])
        if_manual_mean = _weighted_mean(if_rdi_by_pkg[pkg]["manual"])
        if_interactive_mean = _weighted_mean(
            if_rdi_by_pkg[pkg]["scripted"] + if_rdi_by_pkg[pkg]["manual"] + if_rdi_by_pkg[pkg]["other"]
        )
        if_interactive_mean = if_interactive_mean if if_interactive_mean is not None else inter_t1
        d = float(if_interactive_mean - idle)
        abs_scripted_minus_manual = None
        if if_scripted_mean is not None and if_manual_mean is not None:
            abs_scripted_minus_manual = float(abs(if_scripted_mean - if_manual_mean))
        row = {
            "app": str(display.get(pkg, app) or app),
            "package_name": str(pkg),
            "idle_rdi_mean": float(idle),
            "interactive_rdi_mean": float(if_interactive_mean),
            "scripted_rdi_mean": float(if_scripted_mean) if if_scripted_mean is not None else float(if_interactive_mean),
            "manual_rdi_mean": float(if_manual_mean) if if_manual_mean is not None else None,
            "delta_rdi": float(d),
            "delta_d": float(d),
            "abs_rdi_scripted_minus_manual": float(abs_scripted_minus_manual) if abs_scripted_minus_manual is not None else None,
            "idle_windows": int(_i(r["idle_windows"])),
            "interactive_windows_total": int(_i(r["interactive_windows"])),
            # Back-compat alias.
            "scripted_windows_total": int(_i(r["interactive_windows"])),
            "manual_windows_total": int(windows_by_pkg[pkg]["manual"]),
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

    out = PublicationResultsV1(
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
    out_path = PUB_MANIFESTS / "publication_results_v1.json"
    out_path.write_text(json.dumps(asdict(out), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # LaTeX renderings for manuscript inclusion.
    _write_publication_latex_tables()

    print(str(cohort_path))
    print(str(baseline_path))
    print(str(delta_path))
    print(str(APPENDIX_A1_OCSVM))
    print(str(corr_path))
    print(str(out_path))
    return 0


def main() -> int:
    return generate_publication_exports()


if __name__ == "__main__":
    raise SystemExit(main())
