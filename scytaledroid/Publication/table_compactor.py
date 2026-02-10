"""Presentation-only compaction helpers for Table 4 (signature deltas).

This module is intentionally paper-facing only:
- It reads already-emitted `table_4_signature_deltas.csv` (no recomputation).
- It rewrites a narrower LaTeX table variant suitable for IEEE two-column fit.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Table4Row:
    app: str
    bytes_p50_delta: float
    bytes_p95_delta: float
    pps_p50_delta: float
    pps_p95_delta: float
    pkt_size_p50_delta: float
    pkt_size_p95_delta: float


def _as_float(x: str | None) -> float:
    if x is None:
        return 0.0
    s = str(x).strip()
    if not s:
        return 0.0
    try:
        return float(s)
    except Exception:
        return 0.0


def load_table_4_csv(csv_path: Path) -> list[Table4Row]:
    """Load the canonical Table 4 CSV emitted by Phase E bundle writer."""

    rows: list[Table4Row] = []
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(
                Table4Row(
                    app=str((r.get("app") or "").strip() or "—"),
                    bytes_p50_delta=_as_float(r.get("bytes_p50_delta")),
                    bytes_p95_delta=_as_float(r.get("bytes_p95_delta")),
                    pps_p50_delta=_as_float(r.get("pps_p50_delta")),
                    pps_p95_delta=_as_float(r.get("pps_p95_delta")),
                    pkt_size_p50_delta=_as_float(r.get("pkt_size_p50_delta")),
                    pkt_size_p95_delta=_as_float(r.get("pkt_size_p95_delta")),
                )
            )
    return rows


def write_table_4_compact_tex(
    *,
    src_csv: Path,
    dst_tex: Path,
    top_n_metrics_per_app: int = 2,
) -> None:
    """Write a compact, IEEE-friendly Table 4 LaTeX table.

    Strategy:
    - For each app, pick the top-N metrics by |Δ p95| across {Bytes/s, PPS, PktSz}.
    - Emit one row per (app, metric) with both Δp50 and Δp95.

    This reduces column count at the cost of some extra rows and is usually more
    robust for IEEE two-column layout.
    """

    if top_n_metrics_per_app < 1:
        raise ValueError("top_n_metrics_per_app must be >= 1")

    rows = load_table_4_csv(src_csv)

    # Stable metric order for deterministic tie-breaking.
    metrics = [
        ("Bytes/s", "bytes_p50_delta", "bytes_p95_delta"),
        ("PPS", "pps_p50_delta", "pps_p95_delta"),
        ("PktSz", "pkt_size_p50_delta", "pkt_size_p95_delta"),
    ]

    out_lines: list[str] = []
    out_lines.append("% Table 4 (compact): Behavioral signature deltas (idle vs interactive).")
    out_lines.append("% NOTE: Presentation-only rewrite from table_4_signature_deltas.csv; no recomputation.")
    out_lines.append("\\begin{table}[t]")
    out_lines.append("\\centering")
    out_lines.append("\\scriptsize")
    out_lines.append("\\begin{tabular}{llrr}")
    out_lines.append("\\toprule")
    out_lines.append("App & Metric & $\\Delta p50$ & $\\Delta p95$ \\\\")
    out_lines.append("\\midrule")

    for tr in rows:
        scored: list[tuple[float, str, str, str]] = []
        for label, k50, k95 in metrics:
            v50 = getattr(tr, k50)
            v95 = getattr(tr, k95)
            scored.append((abs(float(v95)), label, f"{v50:g}", f"{v95:g}"))
        scored.sort(key=lambda t: (-t[0], t[1]))
        pick = scored[: min(top_n_metrics_per_app, len(scored))]
        first = True
        for _, label, v50_s, v95_s in pick:
            app_cell = tr.app if first else ""
            first = False
            out_lines.append(f"{app_cell} & {label} & {v50_s} & {v95_s} \\\\")
        out_lines.append("\\addlinespace[2pt]")

    out_lines.append("\\bottomrule")
    out_lines.append("\\end{tabular}")
    out_lines.append("\\caption{Behavioral signature deltas (idle vs interactive), shown as median ($\\Delta p50$) and tail ($\\Delta p95$) shifts.}")
    out_lines.append("\\label{tab:signature_deltas}")
    out_lines.append("\\end{table}")
    out_lines.append("")

    dst_tex.parent.mkdir(parents=True, exist_ok=True)
    dst_tex.write_text("\n".join(out_lines), encoding="utf-8")

