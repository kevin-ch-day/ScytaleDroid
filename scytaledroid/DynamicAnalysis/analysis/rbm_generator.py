"""Run Behavioral Map (RBM) generator."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import matplotlib.pyplot as plt


@dataclass(frozen=True)
class RBMPoint:
    ts: float
    state: str
    confidence: float
    bytes_in: float
    bytes_out: float
    cpu_pct: float


def generate_rbm(run_id: str, points: Iterable[RBMPoint], output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    point_list = list(points)
    json_path = output_dir / f"{run_id}_rbm.json"
    json_path.write_text(
        json.dumps([point.__dict__ for point in point_list], indent=2, sort_keys=True),
        encoding="utf-8",
    )
    png_path = output_dir / f"{run_id}_rbm.png"
    _plot_rbm(point_list, png_path)
    html_path = output_dir / f"{run_id}_rbm.html"
    html_path.write_text(_render_html(point_list, png_path.name), encoding="utf-8")
    return {"json": json_path, "png": png_path, "html": html_path}


def _plot_rbm(points: list[RBMPoint], png_path: Path) -> None:
    if not points:
        return
    ts = [p.ts for p in points]
    throughput = [p.bytes_in + p.bytes_out for p in points]
    cpu = [p.cpu_pct for p in points]
    fig, axes = plt.subplots(2, 1, figsize=(8, 4), sharex=True)
    axes[0].plot(ts, throughput, color="tab:blue")
    axes[0].set_ylabel("bytes")
    axes[1].plot(ts, cpu, color="tab:orange")
    axes[1].set_ylabel("cpu%")
    axes[1].set_xlabel("time")
    plt.tight_layout()
    fig.savefig(png_path, dpi=150)
    plt.close(fig)


def _render_html(points: list[RBMPoint], png_name: str) -> str:
    rows = "\n".join(
        f"<tr><td>{p.ts}</td><td>{p.state}</td><td>{p.confidence:.2f}</td></tr>" for p in points
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>RBM</title></head>
<body>
<h1>Run Behavioral Map</h1>
<img src="{png_name}" alt="RBM plot">
<table border="1" cellpadding="4">
<tr><th>Timestamp</th><th>State</th><th>Confidence</th></tr>
{rows}
</table>
</body>
</html>"""


__all__ = ["RBMPoint", "generate_rbm"]
