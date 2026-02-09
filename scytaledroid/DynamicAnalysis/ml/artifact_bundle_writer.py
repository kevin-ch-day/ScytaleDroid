"""Generate Phase E (Paper #2) deliverable bundle under output/.

This does NOT mutate evidence packs and does NOT change the freeze anchor.
It packages already-derived tables and generates one flagship figure (Fig B1),
plus a reproducibility appendix snippet and a manifest with hashes.
"""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt

from scytaledroid.Config import app_config

from . import ml_parameters_paper2 as config
from .deliverable_bundle_paths import (
    dataset_tables_dir,
    freeze_anchor_path,
    output_paper_appendix_dir,
    output_paper_artifacts_manifest_path,
    output_paper_figures_dir,
    output_paper_freeze_copy_path,
    output_paper_manifest_dir,
    output_paper_readme_path,
    output_paper_root,
    output_paper_tables_dir,
)
from .pcap_window_features import build_window_features, extract_packet_timeline
from .evidence_pack_ml_preflight import get_sampling_duration_seconds, load_run_inputs
from .telemetry_windowing import WindowSpec


@dataclass(frozen=True)
class PhaseEArtifacts:
    out_root: Path
    fig_b1_png: Path
    fig_b1_pdf: Path
    table_1_csv: Path
    table_2_csv: Path
    table_3_csv: Path
    repro_appendix_md: Path
    artifacts_manifest_json: Path
    generated_at: str


def write_phase_e_deliverables_bundle(
    *,
    fig_b1_run_id: str,
    interaction_tag: str | None = None,
) -> PhaseEArtifacts:
    """Write Phase E deliverables under output/paper/paper2/phase_e/.

    Assumes:
    - Freeze anchor exists and is checksummed.
    - Runner already generated canonical dataset CSVs under data/.
    - ML v1 outputs exist for the exemplar run (anomaly_scores_*).
    """

    out_root = output_paper_root()
    figs_dir = output_paper_figures_dir()
    tables_dir = output_paper_tables_dir()
    appendix_dir = output_paper_appendix_dir()
    manifest_dir = output_paper_manifest_dir()
    for d in (out_root, figs_dir, tables_dir, appendix_dir, manifest_dir):
        d.mkdir(parents=True, exist_ok=True)

    # Tables: copy canonical CSVs into paper-named files.
    table_1_csv = tables_dir / "table_1_anomaly_prevalence.csv"
    table_2_csv = tables_dir / "table_2_transport_mix.csv"
    table_3_csv = tables_dir / "table_3_model_overlap.csv"
    _copy_required(dataset_tables_dir() / "anomaly_prevalence_per_app_phase.csv", table_1_csv)
    _copy_required(dataset_tables_dir() / "transport_mix_by_phase.csv", table_2_csv)
    _copy_required(dataset_tables_dir() / "model_overlap_per_run.csv", table_3_csv)

    # Freeze anchor copy (convenience; canonical stays in data/archive/).
    _copy_required(freeze_anchor_path(), output_paper_freeze_copy_path())

    # Fig B1 timeline plot.
    fig_b1_png, fig_b1_pdf = _write_fig_b1(fig_b1_run_id, figs_dir, interaction_tag=interaction_tag)

    # Repro appendix snippet.
    repro_appendix_md = appendix_dir / "repro_appendix_phase_e.md"
    if not repro_appendix_md.exists():
        repro_appendix_md.write_text(_render_repro_appendix(), encoding="utf-8")

    # Bundle README.
    readme = output_paper_readme_path()
    if not readme.exists():
        readme.write_text(_render_bundle_readme(fig_b1_run_id), encoding="utf-8")

    # Bundle manifest (hashes + versions + pointers).
    artifacts_manifest_json = output_paper_artifacts_manifest_path()
    _write_bundle_manifest(
        artifacts_manifest_json,
        fig_b1_run_id=fig_b1_run_id,
        fig_b1_png=fig_b1_png,
        fig_b1_pdf=fig_b1_pdf,
        table_1_csv=table_1_csv,
        table_2_csv=table_2_csv,
        table_3_csv=table_3_csv,
        repro_appendix_md=repro_appendix_md,
    )

    return PhaseEArtifacts(
        out_root=out_root,
        fig_b1_png=fig_b1_png,
        fig_b1_pdf=fig_b1_pdf,
        table_1_csv=table_1_csv,
        table_2_csv=table_2_csv,
        table_3_csv=table_3_csv,
        repro_appendix_md=repro_appendix_md,
        artifacts_manifest_json=artifacts_manifest_json,
        generated_at=datetime.now(UTC).isoformat(),
    )


def _write_fig_b1(fig_run_id: str, figs_dir: Path, *, interaction_tag: str | None) -> tuple[Path, Path]:
    stem = f"fig_b1_timeline_{fig_run_id[:8]}"
    png = figs_dir / f"{stem}.png"
    pdf = figs_dir / f"{stem}.pdf"
    if png.exists() and pdf.exists():
        return png, pdf

    run_dir = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic" / fig_run_id
    inputs = load_run_inputs(run_dir)
    if not inputs:
        raise RuntimeError(f"Fig B1 run missing run_manifest.json: {fig_run_id}")
    if not inputs.pcap_path or not inputs.pcap_path.exists():
        raise RuntimeError(f"Fig B1 run missing PCAP: {fig_run_id}")

    duration_s = get_sampling_duration_seconds(inputs)
    if duration_s is None or duration_s <= 0:
        raise RuntimeError(f"Fig B1 run missing sampling duration: {fig_run_id}")

    spec = WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S)
    packets = extract_packet_timeline(inputs.pcap_path)
    rows, dropped = build_window_features(packets, duration_s=float(duration_s), spec=spec)
    if not rows:
        raise RuntimeError(f"Fig B1 run produced 0 windows: {fig_run_id}")

    denom = float(spec.window_size_s) if spec.window_size_s > 0 else 1.0
    xs = [(float(r["window_start_s"]) + float(r["window_end_s"])) / 2.0 for r in rows]
    bytes_ps = [float(r["byte_count"]) / denom for r in rows]
    pkts_ps = [float(r["packet_count"]) / denom for r in rows]

    # Load anomaly flags from both models (v1 outputs).
    out_dir = run_dir / "analysis" / "ml" / config.ML_SCHEMA_LABEL
    if_csv = out_dir / "anomaly_scores_iforest.csv"
    oc_csv = out_dir / "anomaly_scores_ocsvm.csv"
    if not if_csv.exists() or not oc_csv.exists():
        raise RuntimeError(f"Fig B1 run missing v1 anomaly score CSVs: {fig_run_id}")
    if_flags = _read_flags(if_csv)
    oc_flags = _read_flags(oc_csv)
    if len(if_flags) != len(xs) or len(oc_flags) != len(xs):
        if_flags = [False for _ in xs]
        oc_flags = [False for _ in xs]

    pkg = inputs.package_name or "<unknown>"
    tag = interaction_tag or _interaction_tag(inputs.manifest) or "interactive"
    title = f"Fig B1: {pkg} ({tag})"

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10.5, 6.5), sharex=True)
    fig.suptitle(title, fontsize=12)

    ax1.plot(xs, bytes_ps, color="#0B3C5D", linewidth=1.5)
    ax1.set_ylabel("Bytes/sec")
    ax1.grid(True, alpha=0.25)

    ax2.plot(xs, pkts_ps, color="#328CC1", linewidth=1.5)
    ax2.set_ylabel("Packets/sec")
    ax2.set_xlabel("Time (s, relative to capture start)")
    ax2.grid(True, alpha=0.25)

    def _overlay(ax, ys, flags, marker, color, label):
        y_max = max(ys) if ys else 0.0
        y_plot = y_max * 1.02 if y_max > 0 else 1.0
        xs_f = [x for x, f in zip(xs, flags, strict=True) if f]
        ax.scatter(xs_f, [y_plot for _ in xs_f], s=22, marker=marker, color=color, alpha=0.85, label=label)

    _overlay(ax1, bytes_ps, if_flags, marker="^", color="#D1495B", label="IF (flagged)")
    _overlay(ax1, bytes_ps, oc_flags, marker="o", color="#00798C", label="OC-SVM (flagged)")
    ax1.legend(loc="upper right", fontsize=8, frameon=False)

    note = f"dropped_partial_windows={dropped} window={spec.window_size_s}s stride={spec.stride_s}s"
    ax2.text(0.01, 0.02, note, transform=ax2.transAxes, fontsize=8, alpha=0.8)

    fig.tight_layout(rect=[0, 0.02, 1, 0.95])
    fig.savefig(png, dpi=200)
    fig.savefig(pdf)
    plt.close(fig)
    return png, pdf


def _render_repro_appendix() -> str:
    # Keep it simple; this is a paper snippet, not a full report.
    freeze = freeze_anchor_path()
    sha = _sha256_stream(freeze)
    return (
        "# Phase E Reproducibility (Generated)\n\n"
        f"- Freeze anchor: `{freeze}`\n"
        f"- Freeze sha256: `{sha}`\n"
        f"- Windowing: `{config.WINDOW_SIZE_S}s` window / `{config.WINDOW_STRIDE_S}s` stride (drop partials)\n"
        f"- MIN_WINDOWS_BASELINE: `{config.MIN_WINDOWS_BASELINE}`\n"
        f"- Thresholding: `{config.THRESHOLD_PERCENTILE}th percentile` per model×app\n"
        "- Score semantics: higher = more anomalous (normalized)\n"
        "- Selection/training/scoring: DB-free; evidence packs + freeze anchor only\n"
    )


def _render_bundle_readme(fig_run_id: str) -> str:
    return (
        "# Paper #2 Phase E Deliverables Bundle\n\n"
        "This folder is operator/paper-facing. It is intended to be zipped and shared.\n\n"
        "Authoritative inputs:\n"
        "- Evidence packs under `output/evidence/dynamic/<run_id>/...`\n"
        f"- Freeze anchor (canonical): `{freeze_anchor_path()}`\n"
        "- Copy of freeze anchor is included under `manifest/dataset_freeze.json` for convenience.\n\n"
        "Contents:\n"
        f"- figures/: Fig B1 timeline for exemplar run `{fig_run_id}`\n"
        "- tables/: Table 1–3 CSVs used in the paper\n"
        "- appendix/: reproducibility snippet\n"
        "- manifest/: bundle manifest with hashes and pointers\n"
    )


def _write_bundle_manifest(
    path: Path,
    *,
    fig_b1_run_id: str,
    fig_b1_png: Path,
    fig_b1_pdf: Path,
    table_1_csv: Path,
    table_2_csv: Path,
    table_3_csv: Path,
    repro_appendix_md: Path,
) -> None:
    if path.exists():
        return
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "freeze_anchor": str(freeze_anchor_path()),
        "freeze_sha256": _sha256_stream(freeze_anchor_path()),
        "fig_b1_run_id": fig_b1_run_id,
        "files": {
            "fig_b1_png": {"path": str(fig_b1_png), "sha256": _sha256_stream(fig_b1_png)},
            "fig_b1_pdf": {"path": str(fig_b1_pdf), "sha256": _sha256_stream(fig_b1_pdf)},
            "table_1": {"path": str(table_1_csv), "sha256": _sha256_stream(table_1_csv)},
            "table_2": {"path": str(table_2_csv), "sha256": _sha256_stream(table_2_csv)},
            "table_3": {"path": str(table_3_csv), "sha256": _sha256_stream(table_3_csv)},
            "repro_appendix": {"path": str(repro_appendix_md), "sha256": _sha256_stream(repro_appendix_md)},
            "freeze_copy": {
                "path": str(output_paper_freeze_copy_path()),
                "sha256": _sha256_stream(output_paper_freeze_copy_path()),
            },
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _copy_required(src: Path, dest: Path) -> None:
    if not src.exists():
        raise RuntimeError(f"Missing required input for bundle: {src}")
    if dest.exists():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(src.read_bytes())


def _sha256_stream(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _interaction_tag(manifest: dict[str, Any]) -> str | None:
    op = manifest.get("operator") if isinstance(manifest.get("operator"), dict) else {}
    msg = str(op.get("messaging_activity") or "").strip().lower()
    if msg:
        return msg
    inter = str(op.get("interaction_level") or "").strip().lower()
    return inter or None


def _read_flags(path: Path) -> list[bool]:
    out: list[bool] = []
    with path.open("r", newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            v = str(row.get("is_anomalous") or "").strip().lower()
            out.append(v in ("1", "true", "t", "yes", "y"))
    return out
