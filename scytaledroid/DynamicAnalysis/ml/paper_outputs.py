"""Paper #2 Phase E: generate paper-ready artifacts from frozen ML outputs.

This module is intentionally DB-free and evidence-pack-first:
- Uses the canonical checksummed freeze manifest to anchor the dataset.
- Reads per-run ML v1 outputs under each evidence pack.
- Generates derived (non-frozen) paper artifacts under data/.
"""

from __future__ import annotations

import csv
import json
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt

from scytaledroid.Config import app_config

from . import config
from .pcap_windows import build_window_features, extract_packet_timeline
from .preflight import get_sampling_duration_seconds, load_run_inputs
from .windowing import WindowSpec


FREEZE_DIR = Path(app_config.DATA_DIR) / "archive"
CANON_FREEZE_PATH = FREEZE_DIR / config.FREEZE_CANONICAL_FILENAME
PAPER_ARTIFACTS_PATH = FREEZE_DIR / "paper_artifacts.json"


@dataclass(frozen=True)
class PhaseEPaperOutputs:
    out_dir: Path
    fig_b1_png: Path
    fig_b1_pdf: Path
    repro_appendix_md: Path
    tables_dir: Path
    generated_at: str


def generate_phase_e_paper_outputs(
    *,
    out_dir: Path | None = None,
    freeze_manifest_path: Path | None = None,
    paper_artifacts_path: Path | None = None,
) -> PhaseEPaperOutputs:
    """Generate paper-ready Phase E artifacts.

    Outputs are derived and do not mutate evidence packs.
    """

    out_base = out_dir or (Path(app_config.DATA_DIR) / "paper2" / "phase_e")
    out_base.mkdir(parents=True, exist_ok=True)
    tables_dir = out_base / "tables"
    figs_dir = out_base / "figures"
    tables_dir.mkdir(parents=True, exist_ok=True)
    figs_dir.mkdir(parents=True, exist_ok=True)

    freeze_path = freeze_manifest_path or CANON_FREEZE_PATH
    if not freeze_path.exists():
        raise RuntimeError(f"Freeze anchor missing (fail-closed): {freeze_path}")
    paper_path = paper_artifacts_path or PAPER_ARTIFACTS_PATH
    if not paper_path.exists():
        raise RuntimeError(f"paper_artifacts.json missing (run ML runner first): {paper_path}")

    freeze = _load_json(freeze_path)
    included = freeze.get("included_run_ids") or []
    if not isinstance(included, list) or len(included) != 36:
        raise RuntimeError(f"Freeze included_run_ids invalid (expected 36): {freeze_path}")

    paper = _load_json(paper_path)
    fig_run_id = str(paper.get("fig_B1_run_id") or "").strip()
    if not fig_run_id:
        raise RuntimeError(f"paper_artifacts.json missing fig_B1_run_id: {paper_path}")

    # Copy the three canonical dataset-level tables into a paper folder (no rewriting).
    _copy_required_table("anomaly_prevalence_per_app_phase.csv", tables_dir / "table1_anomaly_prevalence.csv")
    _copy_required_table("model_overlap_per_run.csv", tables_dir / "table2_model_overlap.csv")
    _copy_required_table("transport_mix_by_phase.csv", tables_dir / "table3_transport_mix.csv")

    # Fig B1: generate a paper-ready timeline plot from the exemplar run.
    fig_b1_png, fig_b1_pdf = _write_fig_b1(fig_run_id, figs_dir)

    # Repro appendix snippet (markdown).
    repro_appendix_md = _write_repro_appendix(
        out_base=out_base,
        freeze_path=freeze_path,
        paper_path=paper_path,
        included_run_ids=[str(x) for x in included if isinstance(x, str)],
    )

    return PhaseEPaperOutputs(
        out_dir=out_base,
        fig_b1_png=fig_b1_png,
        fig_b1_pdf=fig_b1_pdf,
        repro_appendix_md=repro_appendix_md,
        tables_dir=tables_dir,
        generated_at=datetime.now(UTC).isoformat(),
    )


def _write_fig_b1(fig_run_id: str, figs_dir: Path) -> tuple[Path, Path]:
    stem = f"fig_B1_timeline_{fig_run_id[:8]}"
    png = figs_dir / f"{stem}.png"
    pdf = figs_dir / f"{stem}.pdf"
    # Do not overwrite: derived artifacts should be stable once generated.
    if png.exists() and pdf.exists():
        return png, pdf

    run_dir = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic" / fig_run_id
    inputs = load_run_inputs(run_dir)
    if not inputs:
        raise RuntimeError(f"Fig B1 run is missing run_manifest.json: {fig_run_id}")
    if not inputs.pcap_path or not inputs.pcap_path.exists():
        raise RuntimeError(f"Fig B1 run missing PCAP: {fig_run_id}")

    duration_s = get_sampling_duration_seconds(inputs)
    if duration_s is None or duration_s <= 0:
        raise RuntimeError(f"Fig B1 run missing sampling duration: {fig_run_id}")

    # Recompute window timeline from canonical PCAP (derived; does not mutate packs).
    spec = WindowSpec(window_size_s=config.WINDOW_SIZE_S, stride_s=config.WINDOW_STRIDE_S)
    packets = extract_packet_timeline(inputs.pcap_path)
    rows, dropped = build_window_features(packets, duration_s=float(duration_s), spec=spec)
    if not rows:
        raise RuntimeError(f"Fig B1 run produced 0 windows: {fig_run_id}")

    denom = float(spec.window_size_s) if spec.window_size_s > 0 else 1.0
    xs = [(float(r["window_start_s"]) + float(r["window_end_s"])) / 2.0 for r in rows]
    bytes_ps = [float(r["byte_count"]) / denom for r in rows]
    pkts_ps = [float(r["packet_count"]) / denom for r in rows]

    # Load anomaly flags from both models (v1 outputs must exist for frozen dataset).
    out_dir = run_dir / "analysis" / "ml" / config.ML_SCHEMA_LABEL
    if_csv = out_dir / "anomaly_scores_iforest.csv"
    oc_csv = out_dir / "anomaly_scores_ocsvm.csv"
    if not if_csv.exists() or not oc_csv.exists():
        raise RuntimeError(f"Fig B1 run missing v1 anomaly score CSVs: {fig_run_id}")

    if_flags = _read_flags(if_csv)
    oc_flags = _read_flags(oc_csv)
    if len(if_flags) != len(xs) or len(oc_flags) != len(xs):
        # Defensive: if alignment differs, we still plot series but omit markers.
        if_flags = [False for _ in xs]
        oc_flags = [False for _ in xs]

    interaction_tag = _interaction_tag(inputs.manifest)
    title = f"Fig B1 Exemplar: {inputs.package_name or '<unknown>'} ({interaction_tag or 'interactive'})"

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10.5, 6.5), sharex=True)
    fig.suptitle(title, fontsize=12)

    ax1.plot(xs, bytes_ps, color="#0B3C5D", linewidth=1.5)
    ax1.set_ylabel("Bytes/sec")
    ax1.grid(True, alpha=0.25)

    ax2.plot(xs, pkts_ps, color="#328CC1", linewidth=1.5)
    ax2.set_ylabel("Packets/sec")
    ax2.set_xlabel("Time (s, relative to capture start)")
    ax2.grid(True, alpha=0.25)

    # Overlay anomaly flags as markers at the top of each axis.
    def _overlay(ax, ys, flags, marker, color, label):
        if not flags:
            return
        y_max = max(ys) if ys else 0.0
        y_plot = y_max * 1.02 if y_max > 0 else 1.0
        xs_f = [x for x, f in zip(xs, flags, strict=True) if f]
        ys_f = [y_plot for _ in xs_f]
        ax.scatter(xs_f, ys_f, s=22, marker=marker, color=color, alpha=0.85, label=label)

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


def _write_repro_appendix(*, out_base: Path, freeze_path: Path, paper_path: Path, included_run_ids: list[str]) -> Path:
    # Pull tool versions + key settings from one exemplar model_manifest (first available).
    any_manifest = None
    root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    for rid in included_run_ids:
        p = root / rid / "analysis" / "ml" / config.ML_SCHEMA_LABEL / "model_manifest.json"
        if p.exists():
            any_manifest = p
            break

    meta: dict[str, Any] = {}
    if any_manifest:
        meta = _load_json(any_manifest)

    low_signal = 0
    reasons: dict[str, int] = {}
    for rid in included_run_ids:
        m = _load_json(root / rid / "run_manifest.json")
        ds = m.get("dataset") if isinstance(m.get("dataset"), dict) else {}
        if ds.get("low_signal") is True:
            low_signal += 1
            for r in (ds.get("low_signal_reasons") or []):
                reasons[str(r)] = reasons.get(str(r), 0) + 1

    lines = []
    lines.append("# Paper #2 Phase E Reproducibility Appendix (Generated)\n")
    lines.append(f"- Generated at: `{datetime.now(UTC).isoformat()}`")
    def sha256_stream(p: Path) -> str:
        h=hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    lines.append(f"- Freeze anchor: `{freeze_path}`")
    lines.append(f"- Freeze sha256: `{sha256_stream(freeze_path)}`")
    lines.append(f"- paper_artifacts: `{paper_path}`")
    lines.append(f"- Included runs: `{len(included_run_ids)}` (expected 36)")
    lines.append(f"- Low-signal included runs: `{low_signal}` ({reasons})")
    lines.append("")
    lines.append("## Determinism")
    lines.append(f"- Windowing: `{config.WINDOW_SIZE_S}s` window, `{config.WINDOW_STRIDE_S}s` stride, drop partial windows")
    lines.append(f"- MIN_WINDOWS_BASELINE: `{config.MIN_WINDOWS_BASELINE}`")
    lines.append(f"- Threshold: `{config.THRESHOLD_PERCENTILE}th percentile of training distribution` per model×app")
    lines.append("- Score semantics: `higher_is_more_anomalous` (normalized)")
    lines.append("")
    lines.append("## Toolchain (sample from v1 manifest)")
    env = (meta.get("environment") or {}) if isinstance(meta.get("environment"), dict) else {}
    pyv = env.get("python_version")
    deps = env.get("deps") if isinstance(env.get("deps"), dict) else {}
    tools = env.get("host_tools") if isinstance(env.get("host_tools"), dict) else {}
    lines.append(f"- Python: `{pyv}`")
    lines.append(f"- numpy: `{deps.get('numpy')}`")
    lines.append(f"- sklearn: `{deps.get('sklearn')}`")
    tshark = tools.get("tshark") if isinstance(tools.get("tshark"), dict) else {}
    capinfos = tools.get("capinfos") if isinstance(tools.get("capinfos"), dict) else {}
    lines.append(f"- tshark: `{tshark.get('version')}`")
    lines.append(f"- capinfos: `{capinfos.get('version')}`")
    lines.append("")
    lines.append("## Evidence-only boundary")
    lines.append("- Phase E selection/training/scoring is DB-free and uses only `included_run_ids` from the checksummed freeze anchor.")
    lines.append("- Evidence packs remain authoritative; derived outputs are versioned under `analysis/ml/v<k>/` and never overwrite prior versions.")
    lines.append("")

    path = out_base / "repro_appendix_phase_e.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


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


def _copy_required_table(src_name: str, dest: Path) -> None:
    src = Path(app_config.DATA_DIR) / src_name
    if not src.exists():
        raise RuntimeError(f"Missing dataset-level output: {src}")
    if dest.exists():
        return
    dest.write_bytes(src.read_bytes())


def _load_json(path: Path) -> dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Failed to read JSON: {path} ({exc})") from exc
    if not isinstance(obj, dict):
        raise RuntimeError(f"Expected JSON object: {path}")
    return obj
