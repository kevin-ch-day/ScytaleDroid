"""Write a single canonical `output/paper/` directory for paper assembly.

The canonical directory has stable, paper-facing paths:
  output/paper/tables/
  output/paper/figures/
  output/paper/appendix/
  output/paper/manifests/

Phase/snapshot details are stored under output/paper/internal/ so the paper
writer doesn't need to navigate phase trees.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.ml import deliverable_bundle_paths as paper_paths


def _sha256_file(p: Path) -> str:
    h = sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _copy(src: Path, dst: Path, *, overwrite: bool) -> None:
    if not src.exists():
        raise FileNotFoundError(str(src))
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() and not overwrite:
        return
    dst.write_bytes(src.read_bytes())


def _copytree(src: Path, dst: Path, *, overwrite: bool) -> None:
    if not src.exists():
        raise FileNotFoundError(str(src))
    if dst.exists():
        if not overwrite:
            return
        shutil.rmtree(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst)


def _clean_dir(dir_path: Path, *, keep: set[str]) -> None:
    if not dir_path.exists():
        return
    for p in dir_path.iterdir():
        if p.name in keep:
            continue
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()


def _pick_one(dir_path: Path, glob_pat: str) -> Path:
    matches = sorted(dir_path.glob(glob_pat))
    if len(matches) != 1:
        raise RuntimeError(f"Expected 1 match for {glob_pat!r} under {dir_path}, got {len(matches)}")
    return matches[0]


@dataclass(frozen=True)
class CanonicalPaperResult:
    paper_root: Path
    baseline_bundle_root: Path
    snapshot_id: str | None
    snapshot_source_dir: Path | None
    ok: bool


def write_canonical_paper_directory(
    *,
    baseline_bundle_root: Path,
    snapshot_dir: Path | None,
    snapshot_id: str | None,
    overwrite: bool,
) -> CanonicalPaperResult:
    """Surface baseline + (optional) operational snapshot into output/paper/.

    `baseline_bundle_root` is expected to be the Phase E internal bundle
    directory (output/paper/internal/baseline/).
    `snapshot_dir` is expected to be output/operational/<snapshot_id>/.
    """

    paper_root = paper_paths.output_paper_root()
    tables_dir = paper_paths.output_paper_tables_dir()
    figs_dir = paper_paths.output_paper_figures_dir()
    appendix_dir = paper_paths.output_paper_appendix_dir()
    manifests_dir = paper_paths.output_paper_manifests_dir()
    internal_prov = paper_paths.output_paper_internal_provenance_dir()
    internal_snaps = paper_paths.output_paper_internal_snapshots_root()

    for d in (paper_root, tables_dir, figs_dir, appendix_dir, manifests_dir, internal_prov, internal_snaps):
        d.mkdir(parents=True, exist_ok=True)

    # Keep the canonical surface clean: only stable paper-facing filenames live here.
    _clean_dir(
        tables_dir,
        keep={
            # Phase E (tex/csv are stable; xlsx stays internal).
            "table_1_rdi_prevalence.tex",
            "table_2_transport_mix.tex",
            "table_3_model_agreement.tex",
            "table_4_signature_deltas.tex",
            "table_5_masvs_coverage.tex",
            "table_6_static_posture_scores.tex",
            "table_7_exposure_deviation_summary.tex",
            "table_1_rdi_prevalence.csv",
            "table_2_transport_mix.csv",
            "table_3_model_agreement.csv",
            "table_4_signature_deltas.csv",
            "table_5_masvs_coverage.csv",
            "table_6_static_posture_scores.csv",
            "table_7_exposure_deviation_summary.csv",
            # Phase F surfaced snapshot tables.
            "risk_summary_per_group.csv",
            "dynamic_math_audit_per_group_model.csv",
        },
    )
    _clean_dir(
        figs_dir,
        keep={
            "fig_b1_timeline.pdf",
            "fig_b1_timeline.png",
            "fig_b2_rdi_by_app.pdf",
            "fig_b2_rdi_by_app.png",
            "fig_b4_static_vs_rdi.pdf",
            "fig_b4_static_vs_rdi.png",
        },
    )
    _clean_dir(appendix_dir, keep={"repro_appendix.md"})
    _clean_dir(
        manifests_dir,
        keep={
            "dataset_freeze.json",
            "selection_manifest.json",
            "freeze_manifest.json",
            "model_registry.json",
            "toolchain.txt",
            "phase_e_closure_record.json",
            "paper_snapshot_id.txt",
        },
    )

    # Surface Phase E tables (csv + tex).
    base_tables = baseline_bundle_root / "tables"
    for stem in (
        "table_1_rdi_prevalence",
        "table_2_transport_mix",
        "table_3_model_agreement",
        "table_4_signature_deltas",
        "table_5_masvs_coverage",
        "table_6_static_posture_scores",
        "table_7_exposure_deviation_summary",
    ):
        _copy(base_tables / f"{stem}.tex", tables_dir / f"{stem}.tex", overwrite=overwrite)
        _copy(base_tables / f"{stem}.csv", tables_dir / f"{stem}.csv", overwrite=overwrite)

    # Surface Phase E figures with stable paper names (strip run-id suffix).
    base_figs = baseline_bundle_root / "figures"
    b1_pdf = _pick_one(base_figs, "fig_b1_timeline_*.pdf")
    b1_png = _pick_one(base_figs, "fig_b1_timeline_*.png")
    _copy(b1_pdf, figs_dir / "fig_b1_timeline.pdf", overwrite=overwrite)
    _copy(b1_png, figs_dir / "fig_b1_timeline.png", overwrite=overwrite)
    _copy(base_figs / "fig_b2_rdi_by_app.pdf", figs_dir / "fig_b2_rdi_by_app.pdf", overwrite=overwrite)
    _copy(base_figs / "fig_b2_rdi_by_app.png", figs_dir / "fig_b2_rdi_by_app.png", overwrite=overwrite)
    _copy(base_figs / "fig_b4_static_vs_rdi.pdf", figs_dir / "fig_b4_static_vs_rdi.pdf", overwrite=overwrite)
    _copy(base_figs / "fig_b4_static_vs_rdi.png", figs_dir / "fig_b4_static_vs_rdi.png", overwrite=overwrite)

    # Surface repro appendix.
    _copy(
        baseline_bundle_root / "appendix" / "repro_appendix_phase_e.md",
        appendix_dir / "repro_appendix.md",
        overwrite=overwrite,
    )

    # Manifests: baseline + (optional) snapshot.
    base_manifest = baseline_bundle_root / "manifest"
    _copy(base_manifest / "dataset_freeze.json", manifests_dir / "dataset_freeze.json", overwrite=overwrite)
    _copy(base_manifest / "phase_e_closure_record.json", manifests_dir / "phase_e_closure_record.json", overwrite=overwrite)

    # Prefer the snapshot's pinned toolchain text if present; fallback to repo pins.
    toolchain_src = None
    if snapshot_dir:
        cand = snapshot_dir / "manifest" / "requirements-paper-toolchain.txt"
        if cand.exists():
            toolchain_src = cand
    if not toolchain_src:
        cand = Path(__file__).resolve().parents[2] / "requirements-paper-toolchain.txt"
        if cand.exists():
            toolchain_src = cand
    if toolchain_src:
        _copy(toolchain_src, manifests_dir / "toolchain.txt", overwrite=overwrite)

    # Snapshot surfacing.
    snap_source_dir: Path | None = None
    if snapshot_dir:
        snap_source_dir = snapshot_dir
        snap_manifest = (snapshot_dir / "manifest") if (snapshot_dir / "manifest").exists() else snapshot_dir
        _copy(snap_manifest / "selection_manifest.json", manifests_dir / "selection_manifest.json", overwrite=overwrite)
        _copy(snap_manifest / "freeze_manifest.json", manifests_dir / "freeze_manifest.json", overwrite=overwrite)
        _copy(snap_manifest / "model_registry.json", manifests_dir / "model_registry.json", overwrite=overwrite)
        (manifests_dir / "paper_snapshot_id.txt").write_text((snapshot_id or snapshot_dir.name) + "\n", encoding="utf-8")

        # Surface the two paper-facing snapshot tables.
        snap_tables = snapshot_dir / "tables"
        _copy(snap_tables / "risk_summary_per_group.csv", tables_dir / "risk_summary_per_group.csv", overwrite=overwrite)
        _copy(
            snap_tables / "dynamic_math_audit_per_group_model.csv",
            tables_dir / "dynamic_math_audit_per_group_model.csv",
            overwrite=overwrite,
        )

        # Archive full snapshot under internal/ for provenance.
        sid = snapshot_id or snapshot_dir.name
        _copytree(snapshot_dir, internal_snaps / sid, overwrite=overwrite)

        # Place snapshot provenance artifacts under internal/provenance/.
        _copy(base_manifest / "phase_e_artifacts_manifest.json", internal_prov / "phase_e_artifacts_manifest.json", overwrite=overwrite)
        for name in ("snapshot_bundle_manifest.json", "snapshot_summary.json", "operational_lint.json"):
            p = snap_manifest / name
            if p.exists():
                _copy(p, internal_prov / name, overwrite=overwrite)

    # README: single place to point the paper author at.
    surfaced: dict[str, Any] = {
        "created_at_utc": datetime.now(UTC).isoformat(),
        "baseline_bundle_root": str(baseline_bundle_root),
        "snapshot_id": str(snapshot_id or (snapshot_dir.name if snapshot_dir else "")),
        "snapshot_source_dir": str(snap_source_dir) if snap_source_dir else "",
        "paths": {
            "tables": str(tables_dir),
            "figures": str(figs_dir),
            "appendix": str(appendix_dir),
            "manifests": str(manifests_dir),
            "internal": str(paper_paths.output_paper_internal_root()),
        },
    }
    (paper_root / "README.md").write_text(
        "\n".join(
            [
                "# Canonical Paper Artifacts",
                "",
                "This directory is the canonical, stable artifact surface used to compile the paper.",
                "",
                "Paper-facing paths:",
                f"- tables: `{tables_dir.relative_to(paper_root)}/`",
                f"- figures: `{figs_dir.relative_to(paper_root)}/`",
                f"- appendix: `{appendix_dir.relative_to(paper_root)}/`",
                f"- manifests: `{manifests_dir.relative_to(paper_root)}/`",
                "",
                "Internal provenance (not used directly by LaTeX):",
                f"- internal: `{paper_paths.output_paper_internal_root().relative_to(paper_root)}/`",
                "",
                "Snapshot surfaced:",
                f"- `{surfaced['snapshot_id']}`" if surfaced["snapshot_id"] else "- (none)",
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    # Also write a machine-readable receipt with hashes of surfaced top-level artifacts.
    receipt: dict[str, Any] = {
        "artifact_type": "canonical_paper_receipt",
        **surfaced,
        "sha256": {},
    }
    for p in sorted(paper_root.rglob("*")):
        if not p.is_file():
            continue
        if "/internal/" in str(p).replace("\\", "/"):
            continue
        if p.name.startswith("."):
            continue
        if p.suffix.lower() not in {".json", ".csv", ".tex", ".png", ".pdf", ".md", ".txt"}:
            continue
        rel = str(p.relative_to(paper_root))
        receipt["sha256"][rel] = _sha256_file(p)
    (paper_paths.output_paper_manifests_dir() / "canonical_receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    return CanonicalPaperResult(
        paper_root=paper_root,
        baseline_bundle_root=baseline_bundle_root,
        snapshot_id=(snapshot_id or (snapshot_dir.name if snapshot_dir else None)),
        snapshot_source_dir=snap_source_dir,
        ok=True,
    )
