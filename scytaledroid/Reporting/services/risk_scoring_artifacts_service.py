#!/usr/bin/env python3
"""Generate exploratory risk/exposure fusion artifacts (freeze-anchored).

This does NOT claim maliciousness or harm. These are interpretable, deterministic
scores for static exposure + dynamic deviation prevalence under controlled runs.

Outputs:
  output/experimental/analysis/risk_scoring/risk_scores_v1.csv
  output/experimental/analysis/risk_scoring/risk_scores_v1.json
  output/experimental/analysis/risk_scoring/risk_scores_v1.tex
  output/experimental/analysis/risk_scoring/scatter_static_vs_dynamic_scores.pdf + .png
  output/experimental/analysis/risk_scoring/ranked_fused_scores.pdf + .png
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import matplotlib.pyplot as plt

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Utils.LatexUtils import RawLatex, render_tabular_only
from scytaledroid.Utils.IO.csv_with_provenance import read_csv_with_provenance

PUB_ROOT = REPO_ROOT / "output" / "publication"
PUBLICATION_RESULTS = PUB_ROOT / "manifests" / "publication_results_v1.json"
LEGACY_PUBLICATION_RESULTS = PUB_ROOT / "manifests" / "paper_results_v1.json"
FREEZE = REPO_ROOT / "data" / "archive" / "dataset_freeze.json"
TABLE_6 = PUB_ROOT / "tables" / "table_6_static_posture_scores.csv"
TABLE_5 = PUB_ROOT / "tables" / "table_5_masvs_coverage.csv"
PCAP_FEATURES = REPO_ROOT / "data" / "archive" / "pcap_features.csv"

DEFAULT_OUT_DIR = REPO_ROOT / "output" / "experimental" / "analysis" / "risk_scoring"
LEGACY_OUT_DIR = REPO_ROOT / "output" / "experimental" / "paper2"


def _read_csv_skip_comments(path: Path) -> list[dict[str, str]]:
    return read_csv_with_provenance(path).rows


def _clip(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _grade_4(x: float) -> str:
    # Low/Medium/High/Critical (paper-friendly and simple).
    if x < 25:
        return "Low"
    if x < 50:
        return "Medium"
    if x < 75:
        return "High"
    return "Critical"

def _norm_minmax(values: dict[str, float]) -> tuple[dict[str, float], dict[str, float]]:
    if not values:
        return {}, {"min": float("nan"), "max": float("nan")}
    vs = list(values.values())
    lo = float(min(vs))
    hi = float(max(vs))
    if hi - lo <= 1e-12:
        return {k: 0.0 for k in values}, {"min": lo, "max": hi}
    return {k: (float(v) - lo) / (hi - lo) for k, v in values.items()}, {"min": lo, "max": hi}


def _safe_log1p(x: float) -> float:
    return math.log1p(max(0.0, float(x)))


def _row_by_pkg(rows: list[dict[str, str]], key: str = "package_name") -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for r in rows:
        pkg = str(r.get(key) or "").strip().lower()
        if pkg:
            out[pkg] = r
    return out


def _mean_in_runs(runs: list[dict[str, str]], col: str) -> float:
    vals: list[float] = []
    for rr in runs:
        v = rr.get(col)
        if v in (None, ""):
            continue
        try:
            vals.append(float(v))
        except Exception:
            continue
    return float(sum(vals) / len(vals)) if vals else 0.0


@dataclass(frozen=True)
class Row:
    app: str
    package_name: str
    srs_static_exposure: float
    srs_grade: str
    rdi_idle_if: float
    rdi_scripted_if: float
    delta_if: float
    drs_dynamic_deviation: float
    drs_grade: str
    frs_fused: float
    frs_grade: str
    exposure_runs_n: int

@dataclass(frozen=True)
class RiskScoresV1:
    schema_version: int
    generated_at_utc: str
    freeze_dataset_hash: str
    guardrail: str
    static: dict[str, object]
    dynamic: dict[str, object]
    fusion: dict[str, object]
    normalization: dict[str, object]
    rows: list[dict[str, object]]


def _render_tabular_tex(rows: list[Row]) -> str:
    # Tabular-only; exploratory. Manuscript owns float/caption/label.
    headers = [
        "App",
        "SRS",
        "DRS",
        "FRS",
        RawLatex("$\\mathrm{RDI}_{idle}$"),
        RawLatex("$\\mathrm{RDI}_{interactive}$"),
    ]
    body = [
        [
            r.app,
            f"{r.srs_static_exposure:.1f}",
            f"{r.drs_dynamic_deviation:.1f}",
            f"{r.frs_fused:.1f}",
            f"{r.rdi_idle_if:.3f}",
            f"{r.rdi_scripted_if:.3f}",
        ]
        for r in rows
    ]
    return render_tabular_only(
        headers=headers,
        rows=body,
        align="lrrrrr",
        comment_lines=[
            "Exploratory risk scoring (tabular-only).",
            "Guardrail: scores represent exposure/deviation under controlled interaction; not malware/harm.",
        ],
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Exploratory risk scoring artifacts (freeze-anchored)")
    parser.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help="Output directory for exploratory artifacts.",
    )
    parser.add_argument(
        "--legacy-output-dir",
        action="store_true",
        help="Write to legacy output/experimental/paper2 for backward compatibility.",
    )
    args = parser.parse_args(argv)
    out_dir = LEGACY_OUT_DIR if args.legacy_output_dir else Path(args.out_dir)

    OUT_TABLE_CSV = out_dir / "risk_scores_v1.csv"
    OUT_TABLE_JSON = out_dir / "risk_scores_v1.json"
    OUT_TABLE_TEX = out_dir / "risk_scores_v1.tex"
    OUT_SORTED_BY_FRS = out_dir / "risk_scores_v1_sorted_by_frs.csv"
    OUT_SORTED_BY_DRS = out_dir / "risk_scores_v1_sorted_by_drs.csv"
    OUT_SORTED_BY_SRS = out_dir / "risk_scores_v1_sorted_by_srs.csv"
    FIG_SCATTER_PDF = out_dir / "scatter_static_vs_dynamic_scores.pdf"
    FIG_SCATTER_PNG = out_dir / "scatter_static_vs_dynamic_scores.png"
    FIG_RANK_PDF = out_dir / "ranked_fused_scores.pdf"
    FIG_RANK_PNG = out_dir / "ranked_fused_scores.png"

    results_path = PUBLICATION_RESULTS if PUBLICATION_RESULTS.exists() else LEGACY_PUBLICATION_RESULTS
    for p in (TABLE_6, TABLE_5, PCAP_FEATURES, results_path, FREEZE):
        if not p.exists():
            raise SystemExit(f"Missing required input: {p}")

    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
    freeze_hash = str(freeze.get("freeze_dataset_hash") or "")

    t6_by_pkg = _row_by_pkg(_read_csv_skip_comments(TABLE_6))
    t5_by_pkg = _row_by_pkg(_read_csv_skip_comments(TABLE_5))
    pcap_rows = _read_csv_skip_comments(PCAP_FEATURES)

    pr = json.loads(results_path.read_text(encoding="utf-8"))
    per_app = pr.get("per_app") or []
    if not isinstance(per_app, list) or len(per_app) != 12:
        raise SystemExit(
            f"Unexpected per_app length in {results_path.name}: {len(per_app) if isinstance(per_app, list) else 'non-list'}"
        )

    # Dynamic aggregations from pcap_features (interactive runs, per app).
    # IMPORTANT: "interactive" here mirrors the freeze/profile RDI aggregation inputs.
    # (scripted + manual), not just scripted-only runs. We still compute a
    # scripted-only view for exploration, but we do not default to it unless the
    # paper cohort is strictly scripted.
    interactive_by_pkg: dict[str, list[dict[str, str]]] = {}
    scripted_by_pkg: dict[str, list[dict[str, str]]] = {}
    for r in pcap_rows:
        pkg = str(r.get("package_name_lc") or r.get("package_name") or "").strip().lower()
        if not pkg:
            continue
        ilvl = str(r.get("interaction_level") or "").strip().lower()
        if ilvl == "scripted":
            scripted_by_pkg.setdefault(pkg, []).append(r)
            interactive_by_pkg.setdefault(pkg, []).append(r)
        elif ilvl == "manual":
            interactive_by_pkg.setdefault(pkg, []).append(r)

    # Compute raw dynamic exposure factors per app (interactive mean: scripted + manual).
    raw_domains = {}
    raw_dns = {}
    raw_out = {}
    raw_clear = {}
    for item in per_app:
        pkg = str(item.get("package_name") or "").strip().lower()
        runs = interactive_by_pkg.get(pkg) or []
        # proxies_unique_domains_topn is a stable proxy for "unique domains".
        # If missing, fallback to 0.
        raw_domains[pkg] = _mean_in_runs(runs, "proxies_unique_domains_topn")
        raw_dns[pkg] = _mean_in_runs(runs, "proxies_unique_dns_qname_count")
        # Prefer bytes_out if present; otherwise fall back to total bytes.
        out = _mean_in_runs(runs, "metrics_bytes_out_per_sec")
        if out <= 0.0:
            out = _mean_in_runs(runs, "metrics_bytes_per_sec")
        raw_out[pkg] = out
        # "cleartext attempts": use nsc_cleartext_permitted from static context in pcap_features if present,
        # but for runtime we can only claim "cleartext permitted statically" here; do not overclaim runtime HTTP.
        # Keep as binary and label clearly.
        clear = 0.0
        for rr in runs:
            v = str(rr.get("nsc_cleartext_permitted") or "").strip().lower()
            if v in {"1", "true", "yes"}:
                clear = 1.0
                break
        raw_clear[pkg] = clear

    # Normalize exposure factors cohort-relative (min-max of log1p).
    norm_domains, dom_meta = _norm_minmax({k: _safe_log1p(v) for k, v in raw_domains.items()})
    norm_dns, dns_meta = _norm_minmax({k: _safe_log1p(v) for k, v in raw_dns.items()})
    norm_out, out_meta = _norm_minmax({k: _safe_log1p(v) for k, v in raw_out.items()})

    # Static: MASVS severity-weighted risk (from Table 5 counts).
    # Use P0/P1/P2 buckets as High/Med/Low proxies (deterministic, reviewer-friendly).
    masvs_risk = {}
    for item in per_app:
        pkg = str(item.get("package_name") or "").strip().lower()
        r = t5_by_pkg.get(pkg) or {}
        p0 = float(r.get("finding_count_p0") or 0)
        p1 = float(r.get("finding_count_p1") or 0)
        p2 = float(r.get("finding_count_p2") or 0)
        # Weighted score in [0,1] by normalizing against the cohort max.
        masvs_risk[pkg] = 3.0 * p0 + 2.0 * p1 + 1.0 * p2
    masvs_norm, masvs_meta = _norm_minmax(masvs_risk)

    # Static exposure surface (use table_6 static_posture_score (0-100) as stable SRS base).
    srs_base = {}
    for item in per_app:
        pkg = str(item.get("package_name") or "").strip().lower()
        r = t6_by_pkg.get(pkg) or {}
        srs_base[pkg] = float(r.get("static_posture_score") or 0.0)

    # Compute scores.
    # SRS_v1 = 100*clip(0.65*(static_posture_score/100) + 0.35*masvs_norm, 0, 1)
    # DRS_v1 = 100*clip(0.40*rdi + 0.20*delta + 0.15*domains + 0.10*dns + 0.10*out + 0.05*clear, 0, 1)
    # FRS_v1 = 0.55*DRS + 0.45*SRS
    weights_drs = {"rdi": 0.40, "delta": 0.20, "domains": 0.15, "dns": 0.10, "out": 0.10, "cleartext_permitted_static": 0.05}
    weights_srs = {"static_posture_score": 0.65, "masvs_weighted_findings_norm": 0.35}
    weights_frs = {"drs": 0.55, "srs": 0.45}

    out_rows: list[Row] = []

    for item in per_app:
        app = str(item.get("app") or "").strip()
        pkg = str(item.get("package_name") or "").strip().lower()
        if not app or not pkg:
            raise SystemExit(f"{results_path.name} per_app row missing app/package_name")
        rdi_idle = float(item["idle_rdi_mean"])
        rdi_scripted = float(item["scripted_rdi_mean"])
        delta = float(item["delta_rdi"])

        # Static: combine posture score (0-100) with MASVS weighted findings (cohort-normalized).
        posture_ratio = float(srs_base.get(pkg, 0.0)) / 100.0
        srs_ratio = (
            weights_srs["static_posture_score"] * _clip(posture_ratio, 0.0, 1.0)
            + weights_srs["masvs_weighted_findings_norm"] * _clip(float(masvs_norm.get(pkg, 0.0)), 0.0, 1.0)
        )
        srs = 100.0 * _clip(srs_ratio, 0.0, 1.0)

        # Dynamic: combine RDI + exposure expansion proxies.
        drs_ratio = (
            weights_drs["rdi"] * _clip(rdi_scripted, 0.0, 1.0)
            + weights_drs["delta"] * _clip(delta, 0.0, 1.0)
            + weights_drs["domains"] * _clip(float(norm_domains.get(pkg, 0.0)), 0.0, 1.0)
            + weights_drs["dns"] * _clip(float(norm_dns.get(pkg, 0.0)), 0.0, 1.0)
            + weights_drs["out"] * _clip(float(norm_out.get(pkg, 0.0)), 0.0, 1.0)
            + weights_drs["cleartext_permitted_static"] * _clip(float(raw_clear.get(pkg, 0.0)), 0.0, 1.0)
        )
        drs = 100.0 * _clip(drs_ratio, 0.0, 1.0)

        frs = weights_frs["drs"] * drs + weights_frs["srs"] * srs

        out_rows.append(
            Row(
                app=app,
                package_name=pkg,
                srs_static_exposure=srs,
                srs_grade=_grade_4(srs),
                rdi_idle_if=rdi_idle,
                rdi_scripted_if=rdi_scripted,
                delta_if=delta,
                drs_dynamic_deviation=drs,
                drs_grade=_grade_4(drs),
                frs_fused=frs,
                frs_grade=_grade_4(frs),
                exposure_runs_n=int(len(interactive_by_pkg.get(pkg) or [])),
            )
        )

    # Deterministic ordering for exploration: descending FRS, tie-break by app name.
    out_rows = sorted(out_rows, key=lambda r: (-r.frs_fused, r.app.lower()))

    def _write_csv(path: Path, rows: list[Row]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as f:
            f.write(f"# freeze_dataset_hash: {freeze_hash}\n")
            f.write("# guardrail: scores represent exposure/deviation under controlled interaction; not malware/harm.\n")
            f.write("# SRS_v1 = 100*clip(0.65*(static_posture_score/100) + 0.35*masvs_weighted_findings_norm,0,1)\n")
            f.write("# DRS_v1 = 100*clip(0.40*rdi + 0.20*delta + 0.15*domains + 0.10*dns + 0.10*out + 0.05*cleartext_permitted_static,0,1)\n")
            f.write("# FRS_v1 = 0.55*DRS + 0.45*SRS\n")
            f.write("# note: domains/dns/out are cohort-normalized (min-max of log1p).\n")
            f.write(
                "# note: domains/dns/out are computed from interactive runs (scripted + manual) to match publication_results_v1.json aggregation.\n"
            )
            f.write(f"# generated_at_utc: {datetime.now(UTC).isoformat()}\n")
            w = csv.DictWriter(
                f,
                fieldnames=[
                    "app",
                    "package_name",
                    "srs_static_exposure",
                    "srs_grade",
                    "rdi_idle_if",
                    "rdi_scripted_if",
                    "delta_if",
                    "drs_dynamic_deviation",
                    "drs_grade",
                    "frs_fused",
                    "frs_grade",
                    "exposure_runs_n",
                    "masvs_weighted_findings_norm",
                    "domains_log1p_norm",
                    "dns_log1p_norm",
                    "bytes_out_log1p_norm",
                    "cleartext_permitted_static",
                ],
            )
            w.writeheader()
            for r in rows:
                w.writerow(
                    {
                        "app": r.app,
                        "package_name": r.package_name,
                        "srs_static_exposure": f"{r.srs_static_exposure:.2f}",
                        "srs_grade": r.srs_grade,
                        "rdi_idle_if": f"{r.rdi_idle_if:.6f}",
                        "rdi_scripted_if": f"{r.rdi_scripted_if:.6f}",
                        "delta_if": f"{r.delta_if:.6f}",
                        "drs_dynamic_deviation": f"{r.drs_dynamic_deviation:.2f}",
                        "drs_grade": r.drs_grade,
                        "frs_fused": f"{r.frs_fused:.2f}",
                        "frs_grade": r.frs_grade,
                        "exposure_runs_n": int(r.exposure_runs_n),
                        "masvs_weighted_findings_norm": f"{float(masvs_norm.get(r.package_name, 0.0)):.6f}",
                        "domains_log1p_norm": f"{float(norm_domains.get(r.package_name, 0.0)):.6f}",
                        "dns_log1p_norm": f"{float(norm_dns.get(r.package_name, 0.0)):.6f}",
                        "bytes_out_log1p_norm": f"{float(norm_out.get(r.package_name, 0.0)):.6f}",
                        "cleartext_permitted_static": int(raw_clear.get(r.package_name, 0.0)),
                    }
                )

    # Write primary + sorted views (so reviewers/authors can explore without re-sorting).
    _write_csv(OUT_TABLE_CSV, out_rows)
    _write_csv(OUT_SORTED_BY_FRS, out_rows)
    _write_csv(OUT_SORTED_BY_DRS, sorted(out_rows, key=lambda r: (-r.drs_dynamic_deviation, r.app.lower())))
    _write_csv(OUT_SORTED_BY_SRS, sorted(out_rows, key=lambda r: (-r.srs_static_exposure, r.app.lower())))

    # Write LaTeX tabular-only.
    OUT_TABLE_TEX.write_text(_render_tabular_tex(out_rows), encoding="utf-8")

    # Write JSON metadata (weights + normalization ranges) for reproducibility and exploration.
    payload = RiskScoresV1(
        schema_version=1,
        generated_at_utc=datetime.now(UTC).isoformat(),
        freeze_dataset_hash=freeze_hash,
        guardrail="Scores quantify exposure and deviation prevalence under controlled interaction and do not constitute malware detection or proof of harm.",
        static={
            "srs_definition": "SRS_v1",
            "inputs": ["table_6_static_posture_scores.static_posture_score", "table_5_masvs_coverage.finding_count_p0/p1/p2"],
            "weights": weights_srs,
        },
        dynamic={
            "drs_definition": "DRS_v1",
            "inputs": ["RDI_scripted_if", "delta_if", "pcap_features proxies_unique_domains_topn, proxies_unique_dns_qname_count, metrics_bytes_per_sec, nsc_cleartext_permitted"],
            "weights": weights_drs,
        },
        fusion={
            "frs_definition": "FRS_v1",
            "weights": weights_frs,
        },
        normalization={
            "domains_log1p_minmax": dom_meta,
            "dns_log1p_minmax": dns_meta,
            "bytes_out_log1p_minmax": out_meta,
            "masvs_weighted_findings_minmax": masvs_meta,
        },
        rows=[asdict(r) for r in out_rows],
    )
    OUT_TABLE_JSON.write_text(json.dumps(asdict(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Exploratory scatter: SRS vs DRS.
    xs = [r.srs_static_exposure for r in out_rows]
    ys = [r.drs_dynamic_deviation for r in out_rows]
    labels = [r.app for r in out_rows]

    plt.figure(figsize=(6.2, 4.2))
    plt.scatter(xs, ys, s=55, alpha=0.9)
    for x, y, lab in zip(xs, ys, labels, strict=True):
        plt.annotate(lab, (x, y), textcoords="offset points", xytext=(4, 3), fontsize=8)
    plt.xlabel("Static Exposure Score (SRS, 0-100)")
    plt.ylabel("Dynamic Deviation Score (DRS, 0-100)")
    plt.title("Static vs Dynamic Score (SRS vs DRS)")
    plt.grid(True, alpha=0.25)
    FIG_SCATTER_PDF.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(FIG_SCATTER_PDF)
    plt.savefig(FIG_SCATTER_PNG, dpi=200)
    plt.close()

    # Exploratory: ranked FRS bar chart.
    names = [r.app for r in out_rows]
    vals = [r.frs_fused for r in out_rows]
    plt.figure(figsize=(7.0, 4.2))
    plt.bar(range(len(vals)), vals)
    plt.xticks(range(len(vals)), names, rotation=45, ha="right", fontsize=8)
    plt.ylabel("Fused Score (FRS, 0-100)")
    plt.title("Fused Static+Dynamic Score (FRS) by App")
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()
    plt.savefig(FIG_RANK_PDF)
    plt.savefig(FIG_RANK_PNG, dpi=200)
    plt.close()

    print(OUT_TABLE_CSV)
    print(OUT_TABLE_JSON)
    print(OUT_TABLE_TEX)
    print(FIG_SCATTER_PDF)
    print(FIG_SCATTER_PNG)
    print(FIG_RANK_PDF)
    print(FIG_RANK_PNG)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
