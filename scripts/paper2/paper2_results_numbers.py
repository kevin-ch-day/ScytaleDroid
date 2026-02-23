#!/usr/bin/env python3
"""Compute Paper #2 Results-section numbers from the canonical publication bundle.

Inputs (stable, publication-facing):
- output/publication/tables/table_1_rdi_prevalence.csv
- output/publication/tables/table_7_exposure_deviation_summary.csv
- data/archive/dataset_freeze.json

Outputs:
- output/publication/manifests/paper2_results_numbers.json
- output/publication/appendix/results_section_V.md
"""

from __future__ import annotations

import csv
import json
import math
import statistics
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import scipy.stats

REPO_ROOT = Path(__file__).resolve().parents[2]

PUB_ROOT = REPO_ROOT / "output" / "publication"
TABLE_1 = PUB_ROOT / "tables" / "table_1_rdi_prevalence.csv"
TABLE_7 = PUB_ROOT / "tables" / "table_7_exposure_deviation_summary.csv"
FREEZE = REPO_ROOT / "data" / "archive" / "dataset_freeze.json"


def _read_csv_skip_comments(path: Path) -> list[dict[str, str]]:
    lines: list[str] = []
    for ln in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if not ln.strip():
            continue
        if ln.lstrip().startswith("#"):
            continue
        lines.append(ln + "\n")
    rdr = csv.DictReader(lines)
    return [dict(r) for r in rdr]


def _f(x: str) -> float:
    return float(str(x).strip())


def _i(x: str) -> int:
    return int(str(x).strip())


@dataclass(frozen=True)
class ResultsNumbers:
    generated_at_utc: str
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
    if_interactive_mean: float
    if_delta_mean: float
    if_delta_pos_apps: int
    if_delta_pos_pct: float
    oc_idle_mean: float
    oc_idle_sd_sample: float
    oc_interactive_mean: float
    oc_delta_mean: float
    spearman_rho_static_vs_if_interactive: float
    spearman_p_static_vs_if_interactive: float
    freeze_dataset_hash: str | None
    freeze_manifest_sha256: str | None


def main() -> int:
    if not TABLE_1.exists():
        raise SystemExit(f"Missing: {TABLE_1}")
    if not TABLE_7.exists():
        raise SystemExit(f"Missing: {TABLE_7}")
    if not FREEZE.exists():
        raise SystemExit(f"Missing: {FREEZE}")

    t1 = _read_csv_skip_comments(TABLE_1)
    t7 = _read_csv_skip_comments(TABLE_7)
    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))

    if len(t1) != 12:
        raise SystemExit(f"Unexpected Table 1 row count: {len(t1)} (expected 12)")
    if len(t7) != 12:
        raise SystemExit(f"Unexpected Table 7 row count: {len(t7)} (expected 12)")

    if_idle = [_f(r["if_idle"]) for r in t1]
    if_interactive = [_f(r["if_interactive"]) for r in t1]
    if_delta = [b - a for a, b in zip(if_idle, if_interactive, strict=True)]

    oc_idle = [_f(r["oc_idle"]) for r in t1]
    oc_interactive = [_f(r["oc_interactive"]) for r in t1]
    oc_delta = [b - a for a, b in zip(oc_idle, oc_interactive, strict=True)]

    idle_windows = [_i(r["idle_windows"]) for r in t1]
    interactive_windows = [_i(r["interactive_windows"]) for r in t1]

    n_apps = len(t1)
    n_runs_idle = n_apps
    n_runs_interactive = n_apps * 2
    n_runs_total = n_runs_idle + n_runs_interactive

    windows_idle_total = sum(idle_windows)
    windows_interactive_total = sum(interactive_windows)
    windows_total = windows_idle_total + windows_interactive_total

    # Per-run windows: Table 1 gives interactive windows aggregated over 2 interactive runs per app.
    per_run_windows = [w for w in idle_windows] + [math.floor(w / 2) for w in interactive_windows for _ in (0, 1)]
    per_run_windows = [int(x) for x in per_run_windows if int(x) >= 0]
    if len(per_run_windows) != n_runs_total:
        # Fallback to cohort mean only.
        per_run_windows = []

    xs = [_f(r["static_exposure_score"]) for r in t7]
    ys = [_f(r["rdi_if_interactive"]) for r in t7]
    sp = scipy.stats.spearmanr(xs, ys)

    res = ResultsNumbers(
        generated_at_utc=datetime.now(UTC).isoformat(),
        n_apps=n_apps,
        n_runs_total=n_runs_total,
        n_runs_idle=n_runs_idle,
        n_runs_interactive=n_runs_interactive,
        windows_total=windows_total,
        windows_idle_total=windows_idle_total,
        windows_interactive_total=windows_interactive_total,
        windows_per_run_mean=(windows_total / float(n_runs_total)) if n_runs_total > 0 else 0.0,
        windows_per_run_min=min(per_run_windows) if per_run_windows else 0,
        windows_per_run_max=max(per_run_windows) if per_run_windows else 0,
        if_idle_mean=statistics.mean(if_idle),
        if_idle_sd_sample=statistics.stdev(if_idle),
        if_interactive_mean=statistics.mean(if_interactive),
        if_delta_mean=statistics.mean(if_delta),
        if_delta_pos_apps=sum(1 for d in if_delta if d > 0),
        if_delta_pos_pct=(sum(1 for d in if_delta if d > 0) / float(n_apps) * 100.0) if n_apps else 0.0,
        oc_idle_mean=statistics.mean(oc_idle),
        oc_idle_sd_sample=statistics.stdev(oc_idle),
        oc_interactive_mean=statistics.mean(oc_interactive),
        oc_delta_mean=statistics.mean(oc_delta),
        spearman_rho_static_vs_if_interactive=float(sp.statistic),
        spearman_p_static_vs_if_interactive=float(sp.pvalue),
        freeze_dataset_hash=freeze.get("freeze_dataset_hash"),
        freeze_manifest_sha256=freeze.get("freeze_manifest_sha256"),
    )

    out_json = PUB_ROOT / "manifests" / "paper2_results_numbers.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(asdict(res), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    out_md = PUB_ROOT / "appendix" / "results_section_V.md"
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(
        "\n".join(
            [
                "# Paper #2 Results Numbers (Generated)",
                "",
                f"- generated_at_utc: `{res.generated_at_utc}`",
                f"- freeze_dataset_hash: `{res.freeze_dataset_hash or ''}`",
                "",
                "## Cohort Summary",
                f"- N_apps: {res.n_apps}",
                f"- Runs: idle={res.n_runs_idle}, scripted={res.n_runs_interactive}, total={res.n_runs_total}",
                f"- Windows: idle={res.windows_idle_total}, scripted={res.windows_interactive_total}, total={res.windows_total}",
                f"- Windows/run (mean): {res.windows_per_run_mean:.2f}",
                "",
                "## Baseline Stability (IF primary)",
                f"- mu_baseline (IF idle mean): {res.if_idle_mean:.3f}",
                f"- sigma_baseline (IF idle sd, sample): {res.if_idle_sd_sample:.3f}",
                "",
                "## Interaction-Induced Deviation (IF primary)",
                f"- mean_delta (IF scripted - idle): {res.if_delta_mean:.3f}",
                f"- % apps where scripted > idle: {res.if_delta_pos_pct:.1f}% ({res.if_delta_pos_apps}/{res.n_apps})",
                "",
                "## Static–Dynamic Relationship",
                f"- Spearman rho(static_exposure_score, IF scripted RDI): {res.spearman_rho_static_vs_if_interactive:.3f}",
                f"- p-value: {res.spearman_p_static_vs_if_interactive:.3f}",
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    print(out_json)
    print(out_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

