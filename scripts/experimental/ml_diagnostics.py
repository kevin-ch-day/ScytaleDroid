#!/usr/bin/env python3
"""Exploratory ML diagnostics for freeze-anchored cohorts.

This script generates additional exploratory tables to help interpret the ML results
without changing any frozen methodology (windowing/thresholding/features).

Outputs (neutral names, for exploration/review only):
  output/experimental/diagnostics/ml/ml_time_bucketed_rdi_iforest.csv
  output/experimental/diagnostics/ml/ml_interactive_run_consistency_iforest.csv
  output/experimental/diagnostics/ml/ml_threshold_sensitivity_iforest.csv
  output/experimental/diagnostics/ml/network_expansion_idle_vs_interactive.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
FREEZE = REPO_ROOT / "data" / "archive" / "dataset_freeze.json"
EVIDENCE_ROOT = REPO_ROOT / "output" / "evidence" / "dynamic"
RUN_SUMMARY = REPO_ROOT / "data" / "archive" / "dynamic_run_summary.csv"

DEFAULT_OUT_DIR = REPO_ROOT / "output" / "experimental" / "diagnostics" / "ml"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _rjson(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_csv_dict(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _bucket_from_manifest(man: dict) -> str:
    ds = man.get("dataset") if isinstance(man.get("dataset"), dict) else {}
    op = man.get("operator") if isinstance(man.get("operator"), dict) else {}
    run_profile = str(op.get("run_profile") or ds.get("run_profile") or "").strip().lower()
    interaction_level = str(op.get("interaction_level") or ds.get("interaction_level") or "").strip().lower()
    if run_profile.startswith("baseline"):
        return "idle"
    if interaction_level:
        return interaction_level
    if "manual" in run_profile:
        return "manual"
    if "scripted" in run_profile:
        return "scripted"
    return "interactive"


def _read_iforest_scores(run_dir: Path) -> list[dict[str, str]]:
    p = run_dir / "analysis" / "ml" / "v1" / "anomaly_scores_iforest.csv"
    with p.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _baseline_tau(run_dir: Path) -> float:
    p = run_dir / "analysis" / "ml" / "v1" / "baseline_threshold.json"
    obj = _rjson(p)
    models = obj.get("models") if isinstance(obj.get("models"), dict) else {}
    if_thr = models.get("isolation_forest") if isinstance(models.get("isolation_forest"), dict) else {}
    return float(if_thr.get("threshold_value"))


def _load_included_runs(freeze: dict) -> list[str]:
    return [str(x) for x in (freeze.get("included_run_ids") or [])]


def _build_run_index(included: list[str]) -> dict[str, dict]:
    by_id: dict[str, dict] = {}
    for rid in included:
        run_dir = EVIDENCE_ROOT / rid
        man = _rjson(run_dir / "run_manifest.json")
        by_id[rid] = man
    return by_id


def _write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str], *, header_lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        for ln in header_lines:
            f.write(f"# {ln}\n")
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Exploratory ML diagnostics (freeze-anchored)")
    parser.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help="Output directory for exploratory diagnostics artifacts.",
    )
    args = parser.parse_args(argv)
    out_dir = Path(args.out_dir)

    if not FREEZE.exists():
        raise SystemExit(f"Missing freeze anchor: {FREEZE}")
    freeze = _rjson(FREEZE)
    freeze_sha = _sha256_file(FREEZE)
    freeze_hash = str(freeze.get("freeze_dataset_hash") or "")

    included = _load_included_runs(freeze)
    if not included:
        raise SystemExit("Freeze has no included_run_ids")

    # --- A) Time-bucketed RDI within each run (IF) ---
    bucket_s = 60.0
    time_rows: list[dict[str, object]] = []
    for rid in included:
        run_dir = EVIDENCE_ROOT / rid
        man = _rjson(run_dir / "run_manifest.json")
        tgt = man.get("target") if isinstance(man.get("target"), dict) else {}
        pkg = str(tgt.get("package_name") or "").strip().lower()
        bucket = _bucket_from_manifest(man)
        scores = _read_iforest_scores(run_dir)
        if not scores:
            continue
        # Scores already include per-row threshold + is_anomalous.
        by_bucket: dict[int, list[int]] = defaultdict(list)
        for row in scores:
            try:
                ws = float(row.get("window_start_s") or 0.0)
                is_anom = str(row.get("is_anomalous") or "").strip().lower() in {"1", "true", "yes"}
            except Exception:
                continue
            idx = int(math.floor(ws / bucket_s))
            by_bucket[idx].append(1 if is_anom else 0)
        for idx in sorted(by_bucket):
            vals = by_bucket[idx]
            if not vals:
                continue
            rdi = float(sum(vals)) / float(len(vals))
            time_rows.append(
                {
                    "run_id": rid,
                    "package_name": pkg,
                    "bucket": bucket,
                    "bucket_index": idx,
                    "bucket_start_s": int(idx * bucket_s),
                    "bucket_windows": int(len(vals)),
                    "bucket_rdi": round(rdi, 6),
                }
            )

    _write_csv(
        out_dir / "ml_time_bucketed_rdi_iforest.csv",
        time_rows,
        [
            "run_id",
            "package_name",
            "bucket",
            "bucket_index",
            "bucket_start_s",
            "bucket_windows",
            "bucket_rdi",
        ],
        header_lines=[
            f"freeze_anchor: {FREEZE.relative_to(REPO_ROOT)}",
            f"freeze_sha256: {freeze_sha}",
            f"freeze_dataset_hash: {freeze_hash}",
            f"generated_at_utc: {datetime.now(UTC).isoformat()}",
            f"bucket_seconds: {bucket_s}",
            "note: IF is_anomalous is computed using the baseline-derived tau (P95) stored in each run's ML outputs.",
        ],
    )

    # --- B) Per-app interactive run consistency (IF), using baseline tau ---
    apps = freeze.get("apps") if isinstance(freeze.get("apps"), dict) else {}
    consistency_rows: list[dict[str, object]] = []
    for pkg, entry in sorted(apps.items(), key=lambda kv: kv[0]):
        if not isinstance(entry, dict):
            continue
        base_ids = [str(x) for x in (entry.get("baseline_run_ids") or [])]
        int_ids = [str(x) for x in (entry.get("interactive_run_ids") or [])]
        if len(base_ids) != 1 or len(int_ids) != 2:
            continue
        base_dir = EVIDENCE_ROOT / base_ids[0]
        tau = _baseline_tau(base_dir)

        def _rdi_for_run(rid: str) -> tuple[float, int]:
            rows = _read_iforest_scores(EVIDENCE_ROOT / rid)
            scores = [float(r["score"]) for r in rows if "score" in r]
            n = len(scores)
            if n <= 0:
                return 0.0, 0
            return float(sum(1 for s in scores if s >= tau) / n), n

        idle_rdi, idle_n = _rdi_for_run(base_ids[0])
        r1, n1 = _rdi_for_run(int_ids[0])
        r2, n2 = _rdi_for_run(int_ids[1])
        mean_int = (r1 * n1 + r2 * n2) / (n1 + n2) if (n1 + n2) else float("nan")
        sd_int = statistics.pstdev([r1, r2]) if all(isinstance(x, float) for x in (r1, r2)) else float("nan")
        consistency_rows.append(
            {
                "package_name": pkg,
                "baseline_run_id": base_ids[0],
                "interactive_run_id_1": int_ids[0],
                "interactive_run_id_2": int_ids[1],
                "tau_value": round(float(tau), 12),
                "idle_rdi": round(float(idle_rdi), 6),
                "interactive_rdi_run_1": round(float(r1), 6),
                "interactive_rdi_run_2": round(float(r2), 6),
                "interactive_rdi_mean_weighted": round(float(mean_int), 6) if mean_int == mean_int else "",
                "interactive_rdi_sd_pop_2runs": round(float(sd_int), 6) if sd_int == sd_int else "",
                "interactive_rdi_range": round(float(max(r1, r2) - min(r1, r2)), 6),
            }
        )

    _write_csv(
        out_dir / "ml_interactive_run_consistency_iforest.csv",
        consistency_rows,
        [
            "package_name",
            "baseline_run_id",
            "interactive_run_id_1",
            "interactive_run_id_2",
            "tau_value",
            "idle_rdi",
            "interactive_rdi_run_1",
            "interactive_rdi_run_2",
            "interactive_rdi_mean_weighted",
            "interactive_rdi_sd_pop_2runs",
            "interactive_rdi_range",
        ],
        header_lines=[
            f"freeze_anchor: {FREEZE.relative_to(REPO_ROOT)}",
            f"freeze_sha256: {freeze_sha}",
            f"freeze_dataset_hash: {freeze_hash}",
            f"generated_at_utc: {datetime.now(UTC).isoformat()}",
            "note: interactive RDI is computed against the baseline-derived tau from the app's baseline run.",
        ],
    )

    # --- C) Threshold sensitivity (IF) for p90/p95/p97.5, per app ---
    pcts = [90.0, 95.0, 97.5]
    sens_rows: list[dict[str, object]] = []
    for pkg, entry in sorted(apps.items(), key=lambda kv: kv[0]):
        if not isinstance(entry, dict):
            continue
        base_ids = [str(x) for x in (entry.get("baseline_run_ids") or [])]
        int_ids = [str(x) for x in (entry.get("interactive_run_ids") or [])]
        if len(base_ids) != 1 or len(int_ids) != 2:
            continue
        base_scores = _read_iforest_scores(EVIDENCE_ROOT / base_ids[0])
        base_vals = np.array([float(r["score"]) for r in base_scores if "score" in r], dtype=float)
        if base_vals.size <= 0:
            continue
        # Use NumPy percentile method 'linear' (locked profile behavior).
        for pct in pcts:
            tau = float(np.percentile(base_vals, pct, method="linear"))

            def _rdi(rid: str) -> float:
                rows = _read_iforest_scores(EVIDENCE_ROOT / rid)
                vals = [float(r["score"]) for r in rows if "score" in r]
                if not vals:
                    return float("nan")
                return float(sum(1 for s in vals if s >= tau) / len(vals))

            idle = _rdi(base_ids[0])
            r1 = _rdi(int_ids[0])
            r2 = _rdi(int_ids[1])
            # weighted mean by window count
            n1 = len(_read_iforest_scores(EVIDENCE_ROOT / int_ids[0]))
            n2 = len(_read_iforest_scores(EVIDENCE_ROOT / int_ids[1]))
            inter = (r1 * n1 + r2 * n2) / (n1 + n2) if (n1 + n2) else float("nan")
            sens_rows.append(
                {
                    "package_name": pkg,
                    "percentile": pct,
                    "tau_value": round(tau, 12),
                    "idle_rdi": round(float(idle), 6) if idle == idle else "",
                    "interactive_rdi_mean_weighted": round(float(inter), 6) if inter == inter else "",
                    "delta": round(float(inter - idle), 6) if (idle == idle and inter == inter) else "",
                }
            )

    _write_csv(
        out_dir / "ml_threshold_sensitivity_iforest.csv",
        sens_rows,
        ["package_name", "percentile", "tau_value", "idle_rdi", "interactive_rdi_mean_weighted", "delta"],
        header_lines=[
            f"freeze_anchor: {FREEZE.relative_to(REPO_ROOT)}",
            f"freeze_sha256: {freeze_sha}",
            f"freeze_dataset_hash: {freeze_hash}",
            f"generated_at_utc: {datetime.now(UTC).isoformat()}",
            "note: sensitivity check only; does not change paper's locked percentile (P95).",
        ],
    )

    # --- D) Network expansion summary (idle vs interactive) from freeze-anchored run summary ---
    if RUN_SUMMARY.exists():
        rows = _read_csv_dict(RUN_SUMMARY)
        include_set = set(included)
        # Minimal metrics that tend to be reviewer-friendly.
        metrics = [
            ("unique_domains", "unique_domains"),
            ("bytes_per_sec", "bytes_per_sec"),
            ("packets_per_sec", "packets_per_sec"),
            ("tls_ratio", "tls_ratio"),
            ("quic_ratio", "quic_ratio"),
            ("udp_ratio", "udp_ratio"),
        ]

        per_app_phase: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
        for r in rows:
            rid = str(r.get("run_id") or r.get("dynamic_run_id") or "").strip()
            if rid not in include_set:
                continue
            pkg = str(r.get("package_name_lc") or r.get("package_name") or "").strip().lower()
            lvl = str(r.get("interaction_level") or "").strip().lower()
            phase = "idle" if lvl in {"idle", "baseline", ""} and "baseline" in str(r.get("run_profile") or "").lower() else ("idle" if lvl == "idle" else "interactive")
            if phase != "idle":
                phase = "interactive"
            per_app_phase[(pkg, phase)].append(r)

        out_rows: list[dict[str, object]] = []
        for pkg in sorted({k[0] for k in per_app_phase.keys()}):
            idle_rows = per_app_phase.get((pkg, "idle"), [])
            int_rows = per_app_phase.get((pkg, "interactive"), [])
            if not idle_rows or not int_rows:
                continue

            def _mean(rows2: list[dict[str, str]], key: str) -> float:
                vals: list[float] = []
                for rr in rows2:
                    v = rr.get(key)
                    if v in (None, "", "nan"):
                        continue
                    try:
                        vals.append(float(v))
                    except Exception:
                        continue
                return float(statistics.mean(vals)) if vals else float("nan")

            row_out: dict[str, object] = {"package_name": pkg}
            for _, key in metrics:
                idle_m = _mean(idle_rows, key)
                int_m = _mean(int_rows, key)
                row_out[f"{key}_idle_mean"] = round(idle_m, 6) if idle_m == idle_m else ""
                row_out[f"{key}_interactive_mean"] = round(int_m, 6) if int_m == int_m else ""
                if idle_m == idle_m and int_m == int_m:
                    row_out[f"{key}_delta"] = round(int_m - idle_m, 6)
                else:
                    row_out[f"{key}_delta"] = ""
            out_rows.append(row_out)

        # Deterministic column order.
        fields = ["package_name"]
        for _, key in metrics:
            fields += [f"{key}_idle_mean", f"{key}_interactive_mean", f"{key}_delta"]

        _write_csv(
            out_dir / "network_expansion_idle_vs_interactive.csv",
            out_rows,
            fields,
            header_lines=[
                f"freeze_anchor: {FREEZE.relative_to(REPO_ROOT)}",
                f"freeze_sha256: {freeze_sha}",
                f"freeze_dataset_hash: {freeze_hash}",
                f"generated_at_utc: {datetime.now(UTC).isoformat()}",
                f"source: {RUN_SUMMARY.relative_to(REPO_ROOT)}",
                "note: exploratory only; summarizes network-proxy metrics from freeze-anchored run summary.",
            ],
        )

    print(str(out_dir / "ml_time_bucketed_rdi_iforest.csv"))
    print(str(out_dir / "ml_interactive_run_consistency_iforest.csv"))
    print(str(out_dir / "ml_threshold_sensitivity_iforest.csv"))
    if (out_dir / "network_expansion_idle_vs_interactive.csv").exists():
        print(str(out_dir / "network_expansion_idle_vs_interactive.csv"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
