"""Write a single canonical `output/publication/` directory for publication assembly.

This exporter produces stable paths for consuming artifacts in a manuscript,
blog post, report, or slide deck:
  output/publication/tables/
  output/publication/figures/
  output/publication/appendix/
  output/publication/manifests/

Snapshot/provenance detail is stored under output/publication/internal/ so authors
don't need to navigate internal phase trees.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from scytaledroid.DynamicAnalysis.ml import deliverable_bundle_paths as bundle_paths
from scytaledroid.Publication.contract_inputs import (
    app_ordering_path,
    display_name_map_path,
    load_publication_contracts,
)


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


def _split_csv_comment_header(text: str) -> tuple[list[str], list[str]]:
    """Split a CSV file into (comment_header_lines, data_lines).

    Comment header lines are leading lines starting with '#' or blank lines.
    """
    lines = text.splitlines()
    hdr: list[str] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        if not ln.strip() or ln.startswith("#"):
            hdr.append(ln)
            i += 1
            continue
        break
    return hdr, lines[i:]


def _read_csv_skip_comments(path: Path) -> list[dict[str, str]]:
    import csv

    text = path.read_text(encoding="utf-8", errors="strict")
    _, data_lines = _split_csv_comment_header(text)
    data_lines = [ln for ln in data_lines if ln.strip()]
    if not data_lines:
        return []
    r = csv.DictReader(data_lines)
    return [dict(row) for row in r]


def _write_csv_text_with_header(*, comment_header: list[str], fieldnames: list[str], rows: list[dict[str, str]]) -> str:
    import csv
    import io

    buf = io.StringIO()
    for ln in comment_header:
        buf.write(ln + "\n" if not ln.endswith("\n") else ln)
    w = csv.DictWriter(buf, fieldnames=fieldnames)
    w.writeheader()
    for row in rows:
        w.writerow({k: row.get(k, "") for k in fieldnames})
    return buf.getvalue()


def _render_tabular_from_rows(
    *,
    columns: list[tuple[str, str]],
    rows: list[dict[str, str]],
    caption_comment: str | None = None,
) -> str:
    """Render a tabular-only LaTeX table with booktabs rules."""
    keys = [k for k, _ in columns]
    headers = [h for _, h in columns]
    spec = "l" + ("r" * (len(columns) - 1))
    out: list[str] = []
    if caption_comment:
        out.append(f"% {caption_comment}")
    out.append(f"\\begin{{tabular}}{{{spec}}}")
    out.append("\\toprule")
    out.append(" & ".join(headers) + " \\\\")
    out.append("\\midrule")
    for r in rows:
        vals = [str(r.get(k, "")).replace("_", "\\_") for k in keys]
        out.append(" & ".join(vals) + " \\\\")
    out.append("\\bottomrule")
    out.append("\\end{tabular}")
    return "\n".join(out) + "\n"


_LEGACY_LABEL_VARIANTS: dict[str, list[str]] = {
    # Allow reading older emitted labels, but publication-facing artifacts must emit only canonical aliases.
    "com.facebook.orca": ["Facebook Messenger", "Messenger"],
}


def _legacy_label_variants_for_pkg(pkg: str) -> list[str]:
    return list(_LEGACY_LABEL_VARIANTS.get(pkg, []))


def _render_risk_scoring_tabular_tex(
    rows: list[dict[str, str]],
    *,
    package_order: list[str],
    display_name_by_package: dict[str, str],
) -> str:
    """Tabular-only risk scoring table (manuscript owns float/caption/label)."""

    row_by_pkg = {(r.get("package_name") or "").strip(): r for r in rows if (r.get("package_name") or "").strip()}
    ordered_pkgs = [p for p in package_order if p in row_by_pkg]
    if len(ordered_pkgs) != len(package_order):
        missing = sorted(set(package_order) - set(ordered_pkgs))
        raise RuntimeError(f"Risk table missing packages: {missing}")

    def fmt_score(x: str) -> str:
        try:
            return f"{float(x):.1f}"
        except Exception:
            return "n/a"

    def fmt_grade(g: str) -> str:
        s = (g or "").strip().lower()
        return {"low": "L", "medium": "M", "high": "H"}.get(s, (g or "").strip()[:1].upper() or "n/a")

    lines: list[str] = []
    lines.append("% Risk scoring & grades (tabular-only; manuscript owns float/caption/label).")
    lines.append("% Notes: Dynamic score is deviation (RDI-derived), not measured security harm.")
    lines.append("\\begin{tabular}{lccc}")
    lines.append("\\toprule")
    lines.append("App & Static Exposure (score/grade) & Dynamic Deviation (score/grade) & Final Regime (grade) \\\\")
    lines.append("\\midrule")
    for pkg in ordered_pkgs:
        r = row_by_pkg[pkg]
        app_disp = display_name_by_package.get(pkg, pkg) or pkg
        static_cell = f"{fmt_score(r.get('static_exposure_score',''))}/{fmt_grade(r.get('exposure_grade',''))}"
        dyn_cell = f"{fmt_score(r.get('dynamic_deviation_score_if',''))}/{fmt_grade(r.get('deviation_grade_if',''))}"
        final_cell = fmt_grade(r.get("final_grade_if", ""))
        lines.append(f"{app_disp} & {static_cell} & {dyn_cell} & {final_cell} \\\\")
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    return "\n".join(lines) + "\n"


def _render_masvs_domain_mapping_tabular_tex() -> str:
    """Tabular-only MASVS mapping table (context only; no counts/compliance)."""

    lines: list[str] = []
    lines.append("% MASVS domain mapping (context only; not compliance; no per-app counts).")
    lines.append("\\begin{tabular}{lll}")
    lines.append("\\toprule")
    lines.append("MASVS Domain & Example Signals & Used Where \\\\")
    lines.append("\\midrule")
    lines.append("MASVS-NETWORK & Cleartext posture, transport config & Static Exposure \\\\")
    lines.append("MASVS-PLATFORM & Exported components, IPC surface & Static Exposure \\\\")
    lines.append("MASVS-PRIVACY & High-value permission surface & Static Exposure \\\\")
    lines.append("\\bottomrule")
    lines.append("\\end{tabular}")
    return "\n".join(lines) + "\n"


def _ieeeify_tabular_booktabs(tex: str) -> str:
    """Convert a simple '\\hline' tabular into booktabs style (top/mid/bottomrule).

    This is a best-effort transformation for the surfaced publication-facing tables.
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
class CanonicalPublicationResult:
    publication_root: Path
    baseline_bundle_root: Path
    snapshot_id: str | None
    snapshot_source_dir: Path | None
    ok: bool


def write_canonical_publication_directory(
    *,
    baseline_bundle_root: Path,
    snapshot_dir: Path | None,
    snapshot_id: str | None,
    overwrite: bool,
) -> CanonicalPublicationResult:
    """Surface baseline + (optional) operational snapshot into output/publication/.

    `baseline_bundle_root` is expected to be the internal baseline bundle
    directory (output/publication/internal/baseline/).
    `snapshot_dir` is expected to be output/operational/<snapshot_id>/.
    """

    publication_root = bundle_paths.output_publication_root()
    tables_dir = bundle_paths.output_publication_tables_dir()
    figs_dir = bundle_paths.output_publication_figures_dir()
    appendix_dir = bundle_paths.output_publication_appendix_dir()
    manifests_dir = bundle_paths.output_publication_manifests_dir()
    internal_prov = bundle_paths.output_publication_internal_provenance_dir()
    internal_snaps = bundle_paths.output_publication_internal_snapshots_root()

    for d in (publication_root, tables_dir, figs_dir, appendix_dir, manifests_dir, internal_prov, internal_snaps):
        d.mkdir(parents=True, exist_ok=True)

    # Keep the canonical surface clean: only the publication-facing artifacts live here.
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
    # Appendix is optional; keep it empty by default.
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
            "publication_snapshot_id.txt",
            # Contracts / gates.
            "display_name_map.json",
            "app_ordering.json",
            "publication_contract.json",
            "publication_traceability.csv",
            "crosschecks.json",
        },
    )

    contracts = load_publication_contracts(fail_closed=True)

    # Surface baseline tables (csv + tex) for publication assembly.
    base_tables = baseline_bundle_root / "tables"
    (tables_dir / "table_masvs_domain_mapping.tex").write_text(
        _render_masvs_domain_mapping_tabular_tex(), encoding="utf-8"
    )

    # Rewrite Table 4/7 to enforce ordering + alias contracts (publication-facing).
    # This does not change values; it only stabilizes ordering/labels and avoids nested floats in LaTeX.
    # Table 7: keyed by package_name.
    t7_src = base_tables / "table_7_exposure_deviation_summary.csv"
    t7_comment, _ = _split_csv_comment_header(t7_src.read_text(encoding="utf-8", errors="strict"))
    t7_rows = _read_csv_skip_comments(t7_src)
    t7_by_pkg = {(r.get("package_name") or "").strip(): r for r in t7_rows if (r.get("package_name") or "").strip()}
    ordered_t7: list[dict[str, str]] = []
    for pkg in contracts.package_order:
        if pkg not in t7_by_pkg:
            raise RuntimeError(f"Missing Table 7 row for package: {pkg}")
        row = dict(t7_by_pkg[pkg])
        row["app"] = contracts.display_name_by_package.get(pkg, row.get("app") or pkg)
        ordered_t7.append(row)
    if ordered_t7:
        (tables_dir / "table_7_exposure_deviation_summary.csv").write_text(
            _write_csv_text_with_header(
                comment_header=t7_comment,
                fieldnames=list(ordered_t7[0].keys()),
                rows=ordered_t7,
            ),
            encoding="utf-8",
        )
    (tables_dir / "table_7_exposure_deviation_summary.tex").write_text(
        _render_tabular_from_rows(
            columns=[
                ("app", "App"),
                ("package_name", "Package"),
                ("static_posture_score", "Exposure (StaticPostureScore)"),
                ("exposure_grade", "Exposure Grade"),
                ("rdi_if_interactive", "Deviation (RDI IF, interactive)"),
                ("deviation_grade_if", "Deviation Grade (IF)"),
                ("regime_if", "Regime (IF)"),
                ("rdi_ocsvm_interactive", "RDI OC-SVM (interactive)"),
                ("training_mode_if", "Train (IF)"),
                ("notes", "Notes"),
            ],
            rows=ordered_t7,
            caption_comment=(
                "Table 7: Interpretive Exposure–Deviation Summary over the frozen 12-app dataset. "
                "Exposure Grade and Deviation Grade are rank-based tertile bins (4/4/4) computed on full-precision values "
                "with deterministic tie-breaking by package_name. Grades and quadrant labels are interpretive overlays "
                "(not system outputs) and do not represent measured security risk."
            ),
        ),
        encoding="utf-8",
    )

    # Table 4: keyed by app label only (legacy); remap to canonical alias per package.
    t4_src = base_tables / "table_4_signature_deltas.csv"
    t4_comment, _ = _split_csv_comment_header(t4_src.read_text(encoding="utf-8", errors="strict"))
    t4_rows = _read_csv_skip_comments(t4_src)
    t4_by_app = {(r.get("app") or "").strip(): r for r in t4_rows if (r.get("app") or "").strip()}
    ordered_t4: list[dict[str, str]] = []
    for pkg in contracts.package_order:
        canonical = contracts.display_name_by_package.get(pkg, pkg)
        candidates = [canonical] + _legacy_label_variants_for_pkg(pkg)
        found: dict[str, str] | None = None
        for label in candidates:
            if label in t4_by_app:
                found = dict(t4_by_app[label])
                break
        if not found:
            raise RuntimeError(f"Missing Table 4 row for package {pkg}; tried labels {candidates}")
        found["app"] = canonical
        ordered_t4.append(found)
    if ordered_t4:
        (tables_dir / "table_4_signature_deltas.csv").write_text(
            _write_csv_text_with_header(
                comment_header=t4_comment,
                fieldnames=list(ordered_t4[0].keys()),
                rows=ordered_t4,
            ),
            encoding="utf-8",
        )
    (tables_dir / "table_4_signature_deltas.tex").write_text(
        _render_tabular_from_rows(
            columns=[
                ("app", "App"),
                ("bytes_p50_delta", "Bytes/s Δ p50"),
                ("bytes_p95_delta", "Bytes/s Δ p95"),
                ("pps_p50_delta", "PPS Δ p50"),
                ("pps_p95_delta", "PPS Δ p95"),
                ("pkt_size_p50_delta", "PktSz Δ p50"),
                ("pkt_size_p95_delta", "PktSz Δ p95"),
            ],
            rows=ordered_t4,
            caption_comment="Table 4: Behavioral signature deltas (idle vs interactive), window stats (p50/p95 deltas).",
        ),
        encoding="utf-8",
    )

    # IEEE style touch-up for surfaced tabular-only TeX tables (booktabs rules).
    for stem in ("table_4_signature_deltas", "table_7_exposure_deviation_summary"):
        p = tables_dir / f"{stem}.tex"
        if p.exists():
            p.write_text(_ieeeify_tabular_booktabs(p.read_text(encoding="utf-8", errors="strict")), encoding="utf-8")

    # Surface remaining baseline tables for publication assembly (pure copy).
    # Table 4 and Table 7 are already rewritten above for ordering/label stability.
    for p in sorted(base_tables.glob("table_*.csv")):
        if p.name in {"table_4_signature_deltas.csv", "table_7_exposure_deviation_summary.csv"}:
            continue
        _copy(p, tables_dir / p.name, overwrite=overwrite)
    for p in sorted(base_tables.glob("table_*.tex")):
        if p.name in {"table_4_signature_deltas.tex", "table_7_exposure_deviation_summary.tex"}:
            continue
        _copy(p, tables_dir / p.name, overwrite=overwrite)
    for p in sorted(base_tables.glob("table_*.xlsx")):
        _copy(p, tables_dir / p.name, overwrite=overwrite)

    # Surface baseline figures for publication assembly (pure copy).
    base_figs = baseline_bundle_root / "figures"
    if base_figs.exists():
        for p in sorted(base_figs.glob("fig_*.pdf")):
            _copy(p, figs_dir / p.name, overwrite=overwrite)
        for p in sorted(base_figs.glob("fig_*.png")):
            _copy(p, figs_dir / p.name, overwrite=overwrite)

    # Manifests: baseline + (optional) snapshot.
    base_manifest = baseline_bundle_root / "manifest"
    _copy(base_manifest / "dataset_freeze.json", manifests_dir / "dataset_freeze.json", overwrite=overwrite)
    _copy(base_manifest / "phase_e_closure_record.json", manifests_dir / "phase_e_closure_record.json", overwrite=overwrite)
    _copy(display_name_map_path(), manifests_dir / "display_name_map.json", overwrite=overwrite)
    _copy(app_ordering_path(), manifests_dir / "app_ordering.json", overwrite=overwrite)

    # Crosschecks prefer a self-contained source for "RDI truth" rather than reading from gitignored data/.
    # This is a pure copy; it does not regenerate or alter any values.
    try:
        internal_inputs = (publication_root / "internal" / "baseline" / "inputs")
        internal_inputs.mkdir(parents=True, exist_ok=True)
        repo_root = Path(__file__).resolve().parents[2]
        src = repo_root / "data" / "anomaly_prevalence_per_app_phase.csv"
        if src.exists():
            _copy(src, internal_inputs / "anomaly_prevalence_per_app_phase.csv", overwrite=overwrite)
    except Exception:
        # Non-fatal: gates will fall back (or fail-closed) depending on posture.
        pass

    # Prefer the snapshot's pinned toolchain text if present; fallback to repo pins.
    toolchain_src = None
    if snapshot_dir:
        for name in ("requirements-toolchain.txt", "requirements-paper-toolchain.txt"):
            cand = snapshot_dir / "manifest" / name
            if cand.exists():
                toolchain_src = cand
                break
    if not toolchain_src:
        repo_root = Path(__file__).resolve().parents[2]
        for name in ("requirements-toolchain.txt", "requirements-paper-toolchain.txt"):
            cand = repo_root / name
            if cand.exists():
                toolchain_src = cand
                break
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
        (manifests_dir / "publication_snapshot_id.txt").write_text(
            (snapshot_id or snapshot_dir.name) + "\n", encoding="utf-8"
        )

        # Render compact TeX risk scoring table from snapshot tables.
        snap_tables = snapshot_dir / "tables"
        risk_rows = _read_csv_rows(snap_tables / "risk_summary_per_group.csv")
        (tables_dir / "table_risk_scoring.tex").write_text(
            _render_risk_scoring_tabular_tex(
                risk_rows,
                package_order=contracts.package_order,
                display_name_by_package=contracts.display_name_by_package,
            ),
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

    # README: single place to point authors at.
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
            "internal": str(bundle_paths.output_publication_internal_root()),
        },
    }
    (publication_root / "README.md").write_text(
        "\n".join(
            [
                "# Canonical Publication Bundle",
                "",
                "This directory is the canonical, stable artifact surface for publication assembly.",
                "",
                "Publication-facing paths:",
                f"- tables: `{tables_dir.relative_to(publication_root)}/`",
                f"- figures: `{figs_dir.relative_to(publication_root)}/`",
                f"- appendix: `{appendix_dir.relative_to(publication_root)}/`",
                f"- manifests: `{manifests_dir.relative_to(publication_root)}/`",
                "",
                "Primary artifacts (stable filenames):",
                "- Figures: `figures/fig_b1_timeline_*.pdf` (Fig B1 exemplar), `figures/fig_b2_*.pdf` (Fig B2 variants), `figures/fig_b4_static_vs_rdi.pdf`",
                "- Tables: `tables/table_*.csv` + `tables/table_*.tex` (Table 1-8 + derived presentation tables).",
                "",
                "Internal provenance (not used directly by LaTeX):",
                f"- internal: `{bundle_paths.output_publication_internal_root().relative_to(publication_root)}/`",
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
        "artifact_type": "canonical_publication_receipt",
        **surfaced,
        "sha256": {},
    }
    for p in sorted(publication_root.rglob("*")):
        if not p.is_file():
            continue
        if "/internal/" in str(p).replace("\\", "/"):
            continue
        if p.name.startswith("."):
            continue
        if p.suffix.lower() not in {".json", ".csv", ".tex", ".png", ".pdf", ".md", ".txt"}:
            continue
        rel = str(p.relative_to(publication_root))
        receipt["sha256"][rel] = _sha256_file(p)
    (bundle_paths.output_publication_manifests_dir() / "canonical_receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    return CanonicalPublicationResult(
        publication_root=publication_root,
        baseline_bundle_root=baseline_bundle_root,
        snapshot_id=(snapshot_id or (snapshot_dir.name if snapshot_dir else None)),
        snapshot_source_dir=snap_source_dir,
        ok=True,
    )
