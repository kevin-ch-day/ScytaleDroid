#!/usr/bin/env python3
"""Profile v3 publication exports (freeze/profile mode, fail-closed).

This exporter is read-only over evidence packs and per-run ML artifacts:
- It does not retrain models.
- It does not backfill/repair missing derived state.
- Publication outputs fail closed if any included run is incomplete.

Outputs:
- output/publication/profile_v3/tables/per_app_dynamic_summary_v3.csv + .tex
- output/publication/profile_v3/tables/per_category_summary_v3.csv + .tex
- output/publication/profile_v3/qa/profile_v3_category_tests.json
- output/publication/profile_v3/manifests/profile_v3_manifest.json

Exploratory outputs:
- output/experimental/profile_v3/clustering_input_v3.csv
- output/experimental/profile_v3/clustering_report_v3.json
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Publication.profile_v3_metrics import (  # noqa: E402
    ENGINE_IFOREST,
    ProfileV3Error,
    compute_profile_v3_per_app,
    env_allow_multi_model,
    inspect_run_inputs,
    load_profile_v3_catalog,
    load_profile_v3_manifest,
)
from scytaledroid.Utils.LatexUtils import LatexTableSpec, RawLatex, render_tabular_only, render_table_float  # noqa: E402
from scytaledroid.Publication.profile_v3_contract import lint_profile_v3_bundle  # noqa: E402


def _sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            out = {}
            for k in fieldnames:
                v = r.get(k, "")
                if v is None:
                    v = ""
                out[k] = v
            w.writerow(out)


def _epsilon_squared_kw(H: float, n: int, k: int) -> float:
    # Epsilon-squared effect size for Kruskal-Wallis:
    # ε² = (H - k + 1) / (n - k)
    denom = (n - k)
    if denom <= 0:
        return float("nan")
    return float((H - k + 1.0) / float(denom))


def _category_tests(per_app_rows: list[dict[str, object]], *, metrics: list[str]) -> dict[str, object]:
    try:
        import scipy.stats  # type: ignore
    except Exception as exc:  # noqa: BLE001
        return {
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "engine": ENGINE_IFOREST,
            "stats_available": False,
            "reason": f"scipy_unavailable:{type(exc).__name__}",
            "metrics": {},
        }

    by_cat: dict[str, list[dict[str, object]]] = {}
    for r in per_app_rows:
        by_cat.setdefault(str(r["app_category"]), []).append(r)
    cats = sorted(by_cat.keys())
    out: dict[str, object] = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "engine": ENGINE_IFOREST,
        "stats_available": True,
        "n_apps": len(per_app_rows),
        "categories": {c: len(by_cat[c]) for c in cats},
        "metrics": {},
    }
    for m in metrics:
        groups: list[list[float]] = []
        group_names: list[str] = []
        for c in cats:
            xs = []
            for r in by_cat[c]:
                v = r.get(m)
                if v in (None, ""):
                    continue
                try:
                    xs.append(float(v))
                except Exception:
                    continue
            if xs:
                groups.append(xs)
                group_names.append(c)
        if len(groups) < 2:
            out["metrics"][m] = {"kruskal_wallis": None, "reason": "insufficient_groups"}
            continue
        H, p = scipy.stats.kruskal(*groups)
        n = sum(len(g) for g in groups)
        k = len(groups)
        eps2 = _epsilon_squared_kw(float(H), int(n), int(k))
        out["metrics"][m] = {
            "kruskal_wallis": {
                "H": float(H),
                "p": float(p),
                "epsilon2": float(eps2),
                "n_total": int(n),
                "groups": {name: int(len(g)) for name, g in zip(group_names, groups, strict=True)},
            }
        }

    # Cross-metric structural insight (low-cost, high-value): sigma_idle vs ISC.
    xs = []
    ys = []
    for r in per_app_rows:
        sigma = r.get("sigma_idle_rdi")
        isc = r.get("isc")
        if sigma in (None, "") or isc in (None, ""):
            continue
        try:
            xs.append(float(sigma))
            ys.append(float(isc))
        except Exception:
            continue
    if len(xs) >= 3:
        rho, p = scipy.stats.spearmanr(xs, ys)
        out["correlations"] = {
            "sigma_idle_vs_isc": {
                "method": "spearman",
                "rho": float(rho),
                "p": float(p),
                "n": int(len(xs)),
            }
        }
    else:
        out["correlations"] = {"sigma_idle_vs_isc": {"reason": "insufficient_nonnull_apps", "n": int(len(xs))}}
    return out


def _write_correlations(pub_qa: Path, *, per_app_rows: list[dict[str, object]]) -> dict[str, object]:
    """Write supporting correlations CSV under qa/ (diagnostic, not a core claim)."""
    try:
        import scipy.stats  # type: ignore
    except Exception as exc:  # noqa: BLE001
        note = f"scipy_unavailable:{type(exc).__name__}"
        (pub_qa / "profile_v3_correlations_unavailable.txt").write_text(note, encoding="utf-8")
        return {"available": False, "reason": note}

    pairs = [
        ("isc", "sigma_idle_rdi"),
        ("bsi", "sigma_idle_rdi"),
        ("isc", "delta_rdi"),
        ("mu_idle_rdi", "sigma_idle_rdi"),
    ]
    rows: list[dict[str, object]] = []
    for a, b in pairs:
        xs: list[float] = []
        ys: list[float] = []
        for r in per_app_rows:
            va = r.get(a)
            vb = r.get(b)
            if va in (None, "") or vb in (None, ""):
                continue
            try:
                xs.append(float(va))
                ys.append(float(vb))
            except Exception:
                continue
        if len(xs) < 3:
            rows.append(
                {
                    "metric_x": a,
                    "metric_y": b,
                    "method": "spearman",
                    "rho": "",
                    "p": "",
                    "n": int(len(xs)),
                    "note": "insufficient_nonnull_apps",
                }
            )
            continue
        rho, p = scipy.stats.spearmanr(xs, ys)
        rows.append(
            {
                "metric_x": a,
                "metric_y": b,
                "method": "spearman",
                "rho": float(rho),
                "p": float(p),
                "n": int(len(xs)),
                "note": "",
            }
        )

    path = pub_qa / "profile_v3_correlations.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["metric_x", "metric_y", "method", "rho", "p", "n", "note"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return {"available": True, "path": str(path.relative_to(REPO_ROOT))}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Profile v3 publication exports (fail-closed)")
    p.add_argument(
        "--manifest",
        default=str(REPO_ROOT / "data" / "archive" / "profile_v3_manifest.json"),
        help="Path to Profile v3 manifest (self-contained included_run_ids).",
    )
    p.add_argument(
        "--catalog",
        default=str(REPO_ROOT / "profiles" / "profile_v3_app_catalog.json"),
        help="Path to Profile v3 app catalog (package -> app/category).",
    )
    p.add_argument(
        "--evidence-root",
        default=str(REPO_ROOT / "output" / "evidence" / "dynamic"),
        help="Dynamic evidence root containing run directories.",
    )
    p.add_argument(
        "--out-publication",
        default=str(REPO_ROOT / "output" / "publication" / "profile_v3"),
        help="Output root for publication-facing v3 artifacts.",
    )
    p.add_argument(
        "--out-experimental",
        default=str(REPO_ROOT / "output" / "experimental" / "profile_v3"),
        help="Output root for exploratory v3 artifacts.",
    )
    p.add_argument(
        "--require-single-device",
        action="store_true",
        help="Fail if included runs span multiple device fingerprints.",
    )
    p.add_argument(
        "--allow-manual-interaction",
        action="store_true",
        help="Allow interaction_manual runs in the v3 manifest (default: excluded, fail-closed).",
    )
    p.add_argument(
        "--allow-degenerate-metrics",
        action="store_true",
        help="Allow sigma_idle==0 or mu_idle<=0 by exporting null ISC/BSI (default: fail-closed).",
    )
    args = p.parse_args(argv)

    manifest_path = Path(args.manifest)
    catalog_path = Path(args.catalog)
    evidence_root = Path(args.evidence_root)
    out_pub = Path(args.out_publication)
    out_exp = Path(args.out_experimental)

    manifest = load_profile_v3_manifest(manifest_path)
    # Fill generated_at_utc if the canonical manifest uses a placeholder.
    if str(manifest.get("generated_at_utc") or "").strip() in {"", "REPLACE_ME"}:
        manifest = dict(manifest)
        manifest["generated_at_utc"] = datetime.now(UTC).isoformat()

    included = [str(r).strip() for r in (manifest.get("included_run_ids") or []) if str(r).strip()]
    catalog = load_profile_v3_catalog(catalog_path)

    allow_multi = env_allow_multi_model()

    # Inspect per-run inputs for provenance and early fail-closed errors.
    run_inspections: dict[str, dict[str, object]] = {}
    for rid in included:
        run_dir = evidence_root / rid
        run_inspections[rid] = inspect_run_inputs(run_dir=run_dir, allow_multi_model=allow_multi)

    per_app = compute_profile_v3_per_app(
        included_run_ids=included,
        evidence_root=evidence_root,
        catalog=catalog,
        allow_multi_model=allow_multi,
        allow_manual_interaction=bool(args.allow_manual_interaction),
        allow_degenerate_metrics=bool(args.allow_degenerate_metrics),
    )

    # Multi-device warning / strict mode.
    device_fps = sorted({fp for row in per_app for fp in row.device_fingerprints})
    if len(device_fps) > 1:
        msg = f"Profile v3 includes multiple device fingerprints: {device_fps}"
        if args.require_single_device:
            raise SystemExit(f"PROFILE_V3_MULTI_DEVICE: {msg}")
        print(f"[WARN] {msg}")

    # Publication outputs.
    pub_tables = out_pub / "tables"
    pub_manifests = out_pub / "manifests"
    pub_qa = out_pub / "qa"
    for d in (pub_tables, pub_manifests, pub_qa):
        d.mkdir(parents=True, exist_ok=True)

    per_app_rows = []
    for row in per_app:
        r = asdict(row)
        r["profile_id"] = "profile_v3_structural"
        # CSV contract: null numeric fields are empty string.
        if r.get("isc") is None:
            r["isc"] = ""
        if r.get("bsi") is None:
            r["bsi"] = ""
        per_app_rows.append(r)

    per_app_csv = pub_tables / "per_app_dynamic_summary_v3.csv"
    per_app_tex = pub_tables / "per_app_dynamic_summary_v3.tex"
    fields = [
        "profile_id",
        "package",
        "app",
        "app_category",
        "n_idle_runs",
        "n_interactive_runs",
        "idle_windows_total",
        "interactive_windows_total",
        "mu_idle_rdi",
        "sigma_idle_rdi",
        "mu_interactive_rdi",
        "delta_rdi",
        "isc",
        "isc_reason",
        "bsi",
        "bsi_reason",
    ]
    _write_csv(per_app_csv, fields, per_app_rows)

    # Compact LaTeX: omit window totals to keep it narrow.
    headers = [
        "App",
        RawLatex("$\\mu_{idle}$"),
        RawLatex("$\\sigma_{idle}$"),
        RawLatex("$\\mu_{int}$"),
        RawLatex("$\\Delta$"),
        "ISC",
        "BSI",
    ]
    body = []
    for r in per_app_rows:
        body.append(
            [
                str(r["app"]),
                f"{float(r['mu_idle_rdi']):.4f}",
                f"{float(r['sigma_idle_rdi']):.4f}",
                f"{float(r['mu_interactive_rdi']):.4f}",
                f"{float(r['delta_rdi']):.4f}",
                ("" if r["isc"] == "" else f"{float(r['isc']):.3f}"),
                ("" if r["bsi"] == "" else f"{float(r['bsi']):.3f}"),
            ]
        )
    tab = render_tabular_only(headers=headers, rows=body, align="lrrrrrr")
    per_app_tex.write_text(
        render_table_float(
            spec=LatexTableSpec(
                caption=RawLatex(
                    r"Per-application summary (Profile v3, Isolation Forest): run-balanced phase means and pooled idle SD (ddof=1). "
                    r"ISC$=\Delta/\\sigma_{idle}$ and BSI$=1/(\\sigma_{idle}/\\mu_{idle})$."
                ),
                label="tab:profile_v3_per_app",
                placement="t",
                size_cmd="\\scriptsize",
            ),
            tabular_tex=tab,
        ),
        encoding="utf-8",
    )

    # Category summary.
    cats = sorted({r["app_category"] for r in per_app_rows})
    per_cat_rows = []
    for c in cats:
        rs = [r for r in per_app_rows if r["app_category"] == c]
        def _mean(vals: list[float]) -> float:
            return float(np.mean(np.array(vals, dtype=float))) if vals else float("nan")
        def _sd(vals: list[float]) -> float:
            if len(vals) < 2:
                return float("nan")
            return float(np.std(np.array(vals, dtype=float), ddof=1))
        idle = [float(r["mu_idle_rdi"]) for r in rs]
        inter = [float(r["mu_interactive_rdi"]) for r in rs]
        delta = [float(r["delta_rdi"]) for r in rs]
        isc = [float(r["isc"]) for r in rs if r["isc"] not in (None, "")]
        bsi = [float(r["bsi"]) for r in rs if r["bsi"] not in (None, "")]
        per_cat_rows.append(
            {
                "app_category": c,
                "n_apps": len(rs),
                "mean_mu_idle_rdi": _mean(idle),
                "sd_mu_idle_rdi": _sd(idle),
                "mean_mu_interactive_rdi": _mean(inter),
                "sd_mu_interactive_rdi": _sd(inter),
                "mean_delta_rdi": _mean(delta),
                "sd_delta_rdi": _sd(delta),
                "n_isc": len(isc),
                "mean_isc": _mean(isc),
                "n_bsi": len(bsi),
                "mean_bsi": _mean(bsi),
            }
        )

    per_cat_csv = pub_tables / "per_category_summary_v3.csv"
    per_cat_tex = pub_tables / "per_category_summary_v3.tex"
    per_cat_med_csv = pub_tables / "per_category_medians_v3.csv"
    per_cat_med_tex = pub_tables / "per_category_medians_v3.tex"
    cat_fields = [
        "app_category",
        "n_apps",
        "mean_mu_idle_rdi",
        "sd_mu_idle_rdi",
        "mean_mu_interactive_rdi",
        "sd_mu_interactive_rdi",
        "mean_delta_rdi",
        "sd_delta_rdi",
        "n_isc",
        "mean_isc",
        "n_bsi",
        "mean_bsi",
    ]
    _write_csv(per_cat_csv, cat_fields, per_cat_rows)
    headers = ["Category", "n", RawLatex("$\\mu_{idle}$"), RawLatex("$\\mu_{int}$"), RawLatex("$\\Delta$")]
    body = []
    for r in per_cat_rows:
        body.append(
            [
                str(r["app_category"]),
                str(int(r["n_apps"])),
                f"{float(r['mean_mu_idle_rdi']):.4f}",
                f"{float(r['mean_mu_interactive_rdi']):.4f}",
                f"{float(r['mean_delta_rdi']):.4f}",
            ]
        )
    tab = render_tabular_only(headers=headers, rows=body, align="lrrrr")
    per_cat_tex.write_text(
        render_table_float(
            spec=LatexTableSpec(
                caption=RawLatex("Category-level means (Profile v3, Isolation Forest)."),
                label="tab:profile_v3_per_category",
                placement="t",
                size_cmd="\\scriptsize",
            ),
            tabular_tex=tab,
        ),
        encoding="utf-8",
    )

    # Optional but high-value: per-category medians for key structural metrics.
    per_cat_med_rows = []
    for c in cats:
        rs = [r for r in per_app_rows if r["app_category"] == c]
        def _median(vals: list[float]) -> float:
            return float(np.median(np.array(vals, dtype=float))) if vals else float("nan")
        sigma = [float(r["sigma_idle_rdi"]) for r in rs]
        isc = [float(r["isc"]) for r in rs if r["isc"] not in (None, "")]
        bsi = [float(r["bsi"]) for r in rs if r["bsi"] not in (None, "")]
        per_cat_med_rows.append(
            {
                "app_category": c,
                "n_apps": len(rs),
                "median_sigma_idle_rdi": _median(sigma),
                "n_isc": len(isc),
                "median_isc": _median(isc),
                "n_bsi": len(bsi),
                "median_bsi": _median(bsi),
            }
        )
    _write_csv(
        per_cat_med_csv,
        ["app_category", "n_apps", "median_sigma_idle_rdi", "n_isc", "median_isc", "n_bsi", "median_bsi"],
        per_cat_med_rows,
    )
    headers = ["Category", "n", RawLatex("$\\mathrm{median}(\\sigma_{idle})$"), "median(ISC)", "median(BSI)"]
    body = []
    for r in per_cat_med_rows:
        body.append(
            [
                str(r["app_category"]),
                str(int(r["n_apps"])),
                f"{float(r['median_sigma_idle_rdi']):.4f}",
                ("" if math.isnan(float(r["median_isc"])) else f"{float(r['median_isc']):.3f}"),
                ("" if math.isnan(float(r["median_bsi"])) else f"{float(r['median_bsi']):.3f}"),
            ]
        )
    tab = render_tabular_only(headers=headers, rows=body, align="lrrrr")
    per_cat_med_tex.write_text(
        render_table_float(
            spec=LatexTableSpec(
                caption=RawLatex("Category-level medians for baseline stability and interaction sensitivity (Profile v3)."),
                label="tab:profile_v3_category_medians",
                placement="t",
                size_cmd="\\scriptsize",
            ),
            tabular_tex=tab,
        ),
        encoding="utf-8",
    )

    # Category tests JSON.
    tests = _category_tests(
        per_app_rows,
        metrics=["mu_idle_rdi", "mu_interactive_rdi", "delta_rdi", "isc", "bsi"],
    )
    tests_path = pub_qa / "profile_v3_category_tests.json"
    tests_path.write_text(json.dumps(tests, indent=2, sort_keys=True), encoding="utf-8")
    if not bool(tests.get("stats_available", True)):
        (pub_qa / "profile_v3_stats_unavailable.txt").write_text(
            str(tests.get("reason") or "stats_unavailable"),
            encoding="utf-8",
        )
    corr_meta = _write_correlations(pub_qa, per_app_rows=per_app_rows)

    # Manifest output (receipt-ish).
    out_manifest = {
        "schema_version": 1,
        "profile_id": "profile_v3_structural",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "inputs": {
            "manifest_path": str(manifest_path),
            "manifest_sha256": _sha256_file(manifest_path),
            "catalog_path": str(catalog_path),
            "catalog_sha256": _sha256_file(catalog_path),
            "catalog_n_packages": int(len(catalog)),
            "catalog_packages": sorted(catalog.keys()),
            "evidence_root": str(evidence_root),
        },
        "locks": {
            "engine": ENGINE_IFOREST,
            "allow_multi_model": bool(allow_multi),
            "allow_manual_interaction": bool(args.allow_manual_interaction),
            "allow_degenerate_metrics": bool(args.allow_degenerate_metrics),
            "ddof": 1,
            "exceedance_operator": ">",
            "aggregation": "run_balanced_means_pooled_idle_sd",
        },
        "claims": {
            "paper_claim": (
                "Baseline-relative deviation exhibits measurable differences in interaction sensitivity and baseline stability across functional categories under controlled execution."
            ),
            "metrics_primary": ["isc", "bsi"],
            "metrics_secondary": ["sigma_idle_rdi", "delta_rdi"],
            "clustering_is_exploratory": True,
        },
        "provenance": {"run_input_schemas": run_inspections},
        "counts": {
            "n_apps": len(per_app_rows),
            "n_included_runs": len(included),
        },
        "outputs": {
            "per_app_csv": str(per_app_csv.relative_to(REPO_ROOT)),
            "per_app_tex": str(per_app_tex.relative_to(REPO_ROOT)),
            "per_category_csv": str(per_cat_csv.relative_to(REPO_ROOT)),
            "per_category_tex": str(per_cat_tex.relative_to(REPO_ROOT)),
            "category_tests_json": str(tests_path.relative_to(REPO_ROOT)),
            "correlations": corr_meta,
        },
    }
    (pub_manifests / "profile_v3_manifest.json").write_text(
        json.dumps(out_manifest, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    # Exploratory clustering inputs (no clustering implementation yet; just inputs + stub report).
    out_exp.mkdir(parents=True, exist_ok=True)
    cluster_in = out_exp / "clustering_input_v3.csv"
    _write_csv(
        cluster_in,
        ["package", "app", "app_category", "mu_idle_rdi", "mu_interactive_rdi", "delta_rdi", "sigma_idle_rdi", "isc", "bsi"],
        per_app_rows,
    )
    cluster_report: dict[str, object] = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "profile_id": "profile_v3_structural",
        "note": "Exploratory only. No inferential claims.",
        "inputs": {"clustering_input_csv": str(cluster_in.relative_to(REPO_ROOT))},
    }
    # Optional clustering: compute silhouette if sklearn is available.
    try:
        from sklearn.cluster import KMeans
        from sklearn.metrics import silhouette_score
        from sklearn.preprocessing import StandardScaler

        feats = []
        labels = []
        used = []
        for r in per_app_rows:
            if r.get("isc") in ("", None) or r.get("bsi") in ("", None):
                continue
            feats.append(
                [
                    float(r["mu_idle_rdi"]),
                    float(r["mu_interactive_rdi"]),
                    float(r["isc"]),
                    float(r["bsi"]),
                ]
            )
            used.append({"package": r["package"], "app": r["app"], "app_category": r["app_category"]})
        X = np.array(feats, dtype=float)
        if X.shape[0] >= 3:
            Xs = StandardScaler().fit_transform(X)
            best = {"k": None, "silhouette": None}
            best_labels = None
            max_k = min(6, Xs.shape[0] - 1)
            for k in range(2, max_k + 1):
                km = KMeans(n_clusters=k, random_state=1337, n_init=10)
                y = km.fit_predict(Xs)
                s = float(silhouette_score(Xs, y))
                if best["silhouette"] is None or s > float(best["silhouette"]):
                    best = {"k": int(k), "silhouette": float(s)}
                    best_labels = [int(x) for x in y]
            cluster_report["clustering"] = {
                "features": ["mu_idle_rdi", "mu_interactive_rdi", "isc", "bsi"],
                "algorithm": "kmeans",
                "k_search": {"min_k": 2, "max_k": int(max_k)},
                "best": best,
                "n_used_apps": int(X.shape[0]),
                "assignments": (
                    [
                        dict(used[i], cluster=int(best_labels[i]))  # type: ignore[index]
                        for i in range(len(used))
                    ]
                    if best_labels is not None
                    else []
                ),
            }
        else:
            cluster_report["clustering"] = {"reason": "insufficient_nonnull_apps", "n_used_apps": int(X.shape[0])}
    except Exception as exc:  # noqa: BLE001
        cluster_report["clustering"] = {"reason": f"clustering_unavailable:{type(exc).__name__}"}
    (out_exp / "clustering_report_v3.json").write_text(
        json.dumps(cluster_report, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    lint = lint_profile_v3_bundle(out_pub)
    if not lint.ok:
        print(f"[FAIL] Profile v3 bundle lint failed: {out_pub}")
        for e in lint.errors:
            print(f"- {e}")
        return 2

    print(f"[OK] Wrote: {per_app_csv}")
    print(f"[OK] Wrote: {per_cat_csv}")
    print(f"[OK] Wrote: {tests_path}")
    print(f"[OK] Profile v3 bundle lint: PASS ({out_pub})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
