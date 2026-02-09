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


def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    import csv

    text = path.read_text(encoding="utf-8", errors="strict").splitlines()
    # No comment headers expected for operational snapshot CSVs; keep simple.
    r = csv.DictReader([ln for ln in text if ln.strip()])
    return [dict(row) for row in r]


def _read_table6_app_names(path: Path) -> dict[str, str]:
    """Read (package_name -> display app name) from Table 6 CSV (skipping comments)."""
    import csv

    lines = []
    for ln in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if ln.startswith("#") or not ln.strip():
            continue
        lines.append(ln)
    r = csv.DictReader(lines)
    out: dict[str, str] = {}
    for row in r:
        pkg = (row.get("package_name") or "").strip()
        name = (row.get("app") or "").strip()
        if pkg and name:
            out[pkg] = name
    return out


def _render_risk_scoring_table_tex(rows: list[dict[str, str]], *, app_name_by_package: dict[str, str] | None = None) -> str:
    """Compact IEEE-single-column friendly risk scoring table.

    Columns are intentionally compressed:
    - Static: score + grade (Exposure)
    - Dynamic: score + grade (Deviation; IF primary)
    - Final: grade only (rule-based regime mapping)
    """

    # Deterministic ordering by package name for stable diffs.
    rows = sorted(rows, key=lambda r: (r.get("package_name") or ""))

    def fmt_score(x: str) -> str:
        try:
            return f"{float(x):.1f}"
        except Exception:
            return "n/a"

    def fmt_grade(g: str) -> str:
        s = (g or "").strip().lower()
        return {"low": "L", "medium": "M", "high": "H"}.get(s, (g or "").strip()[:1].upper() or "n/a")

    lines: list[str] = []
    lines.append("% Risk scoring & grades (compact; IEEE single-column friendly).")
    lines.append("% Notes: Dynamic score is deviation (RDI-derived), not measured security harm.")
    lines.append("\\begin{table}[t]")
    lines.append("\\centering")
    lines.append("\\scriptsize")
    lines.append("\\setlength{\\tabcolsep}{3pt}")
    lines.append("\\renewcommand{\\arraystretch}{1.05}")
    lines.append("\\begin{tabular}{lccc}")
    lines.append("\\toprule")
    lines.append("App & Static Exposure (score/grade) & Dynamic Deviation (score/grade) & Final Regime (grade) \\\\")
    lines.append("\\midrule")
    app_name_by_package = app_name_by_package or {}
    for r in rows:
        pkg = (r.get("package_name") or "").strip()
        app_disp = app_name_by_package.get(pkg) or pkg
        if not app_disp:
            app_disp = "n/a"
        static_cell = f"{fmt_score(r.get('static_exposure_score',''))}/{fmt_grade(r.get('exposure_grade',''))}"
        dyn_cell = f"{fmt_score(r.get('dynamic_deviation_score_if',''))}/{fmt_grade(r.get('deviation_grade_if',''))}"
        final_cell = fmt_grade(r.get("final_grade_if", ""))
        lines.append(f"{app_disp} & {static_cell} & {dyn_cell} & {final_cell} \\\\")
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    lines.append(
        "\\caption{Risk scoring and regime grades per app (frozen cohort). Static Exposure uses StaticPostureScore. "
        "Dynamic Deviation reflects runtime behavioral deviation from a baseline distribution (Isolation Forest, interactive; "
        "deviation is not measured harm). Final Regime (grade) is rule-based and not a fused scalar.}"
    )
    lines.append("\\label{tab:risk_scoring}")
    lines.append("\\end{table}")
    return "\n".join(lines) + "\n"


def _render_masvs_domain_mapping_table_tex() -> str:
    """Small, explanatory MASVS mapping table (paper-only; no counts/compliance).

    Purpose: provide a semantic anchor for what "Static Exposure" covers without
    introducing per-app MASVS findings or compliance claims.
    """

    lines: list[str] = []
    lines.append("% MASVS domain mapping (context only; not compliance; no per-app counts).")
    lines.append("\\begin{table}[t]")
    lines.append("\\centering")
    lines.append("\\footnotesize")
    lines.append("\\setlength{\\tabcolsep}{3pt}")
    lines.append("\\renewcommand{\\arraystretch}{1.05}")
    lines.append("\\begin{tabular}{lll}")
    lines.append("\\toprule")
    lines.append("MASVS Domain & Example Signals & Used Where \\\\")
    lines.append("\\midrule")
    lines.append("MASVS-NETWORK & Cleartext posture, transport config & Static Exposure \\\\")
    lines.append("MASVS-PLATFORM & Exported components, IPC surface & Static Exposure \\\\")
    lines.append("MASVS-PRIVACY & High-value permission surface & Static Exposure \\\\")
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    lines.append(
        "\\caption{MASVS domain mapping for Static Exposure context. This table is explanatory only and does not "
        "represent MASVS compliance, pass/fail status, or per-app findings counts.}"
    )
    lines.append("\\label{tab:masvs_mapping}")
    lines.append("\\end{table}")
    return "\n".join(lines) + "\n"


def _ieeeify_tabular_booktabs(tex: str) -> str:
    """Convert a simple '\\hline' tabular into booktabs style (top/mid/bottomrule).

    This is a best-effort transformation for the surfaced paper-facing tables.
    It intentionally does not touch internal baseline artifacts used for regression gates.
    """

    lines = tex.splitlines()
    out: list[str] = []
    in_tabular = False
    hline_idx: list[int] = []
    for ln in lines:
        if ln.startswith("\\begin{tabular}"):
            in_tabular = True
            hline_idx = []
        if in_tabular and ln.strip() == "\\hline":
            # Record position within out (not lines) so we can post-fix easily.
            hline_idx.append(len(out))
            out.append(ln)
            continue
        out.append(ln)
        if in_tabular and ln.startswith("\\end{tabular}"):
            in_tabular = False
            # Replace up to 3 hlines inside this tabular block.
            if len(hline_idx) >= 1:
                out[hline_idx[0]] = "\\toprule"
            if len(hline_idx) >= 2:
                out[hline_idx[1]] = "\\midrule"
            if len(hline_idx) >= 3:
                out[hline_idx[-1]] = "\\bottomrule"

    return "\n".join(out) + ("\n" if tex.endswith("\n") else "")


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

    # Keep the canonical surface clean: only locked main-paper artifacts live here.
    _clean_dir(
        tables_dir,
        keep={
            "table_masvs_domain_mapping.tex",
            "table_4_signature_deltas.tex",
            "table_7_exposure_deviation_summary.tex",
            "table_4_signature_deltas.csv",
            "table_7_exposure_deviation_summary.csv",
            "table_risk_scoring.tex",
        },
    )
    _clean_dir(
        figs_dir,
        keep={
            "fig_b2_rdi_social_by_app.pdf",
            "fig_b2_rdi_social_by_app.png",
            "fig_b2_rdi_messaging_by_app.pdf",
            "fig_b2_rdi_messaging_by_app.png",
            "fig_b4_static_vs_rdi.pdf",
            "fig_b4_static_vs_rdi.png",
        },
    )
    # No appendix section in the 8-page paper; keep repro notes internal-only.
    _clean_dir(appendix_dir, keep=set())
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

    # Surface Phase E tables (csv + tex) that are locked into the main paper.
    base_tables = baseline_bundle_root / "tables"
    (tables_dir / "table_masvs_domain_mapping.tex").write_text(_render_masvs_domain_mapping_table_tex(), encoding="utf-8")
    for stem in (
        "table_4_signature_deltas",
        "table_7_exposure_deviation_summary",
    ):
        _copy(base_tables / f"{stem}.tex", tables_dir / f"{stem}.tex", overwrite=overwrite)
        _copy(base_tables / f"{stem}.csv", tables_dir / f"{stem}.csv", overwrite=overwrite)

    # IEEE style touch-up for surfaced tabular-only TeX tables (booktabs rules).
    for stem in ("table_4_signature_deltas", "table_7_exposure_deviation_summary"):
        p = tables_dir / f"{stem}.tex"
        if p.exists():
            p.write_text(_ieeeify_tabular_booktabs(p.read_text(encoding="utf-8", errors="strict")), encoding="utf-8")

    # Surface Phase E figures that are locked into the main paper.
    base_figs = baseline_bundle_root / "figures"
    _copy(base_figs / "fig_b2_rdi_social_by_app.pdf", figs_dir / "fig_b2_rdi_social_by_app.pdf", overwrite=overwrite)
    _copy(base_figs / "fig_b2_rdi_social_by_app.png", figs_dir / "fig_b2_rdi_social_by_app.png", overwrite=overwrite)
    _copy(
        base_figs / "fig_b2_rdi_messaging_by_app.pdf",
        figs_dir / "fig_b2_rdi_messaging_by_app.pdf",
        overwrite=overwrite,
    )
    _copy(
        base_figs / "fig_b2_rdi_messaging_by_app.png",
        figs_dir / "fig_b2_rdi_messaging_by_app.png",
        overwrite=overwrite,
    )
    _copy(base_figs / "fig_b4_static_vs_rdi.pdf", figs_dir / "fig_b4_static_vs_rdi.pdf", overwrite=overwrite)
    _copy(base_figs / "fig_b4_static_vs_rdi.png", figs_dir / "fig_b4_static_vs_rdi.png", overwrite=overwrite)

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

        # Render compact TeX risk scoring table for the main paper from snapshot tables.
        snap_tables = snapshot_dir / "tables"
        risk_rows = _read_csv_rows(snap_tables / "risk_summary_per_group.csv")
        app_names = {}
        try:
            app_names = _read_table6_app_names(base_tables / "table_6_static_posture_scores.csv")
        except Exception:
            app_names = {}
        (tables_dir / "table_risk_scoring.tex").write_text(
            _render_risk_scoring_table_tex(risk_rows, app_name_by_package=app_names),
            encoding="utf-8",
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
                "This directory is the canonical, stable artifact surface used to compile the 8-page IEEE main paper.",
                "",
                "Paper-facing paths:",
                f"- tables: `{tables_dir.relative_to(paper_root)}/`",
                f"- figures: `{figs_dir.relative_to(paper_root)}/`",
                f"- appendix: `{appendix_dir.relative_to(paper_root)}/` (unused in 8-page main paper)",
                f"- manifests: `{manifests_dir.relative_to(paper_root)}/`",
                "",
                "Locked main-paper artifacts (no swaps):",
                "- Figures: `figures/fig_b2_rdi_social_by_app.pdf`, `figures/fig_b2_rdi_messaging_by_app.pdf` (Fig B2 a/b), `figures/fig_b4_static_vs_rdi.pdf`",
                "- Tables: `tables/table_risk_scoring.tex`, `tables/table_7_exposure_deviation_summary.tex`, `tables/table_4_signature_deltas.tex`, `tables/table_masvs_domain_mapping.tex` (context-only)",
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
