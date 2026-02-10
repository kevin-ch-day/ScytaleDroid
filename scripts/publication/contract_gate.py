#!/usr/bin/env python3
"""Contract gate: publication-facing contracts + crosschecks (DB-free).

This gate does not change analysis. It verifies that the *paper-facing* outputs
under output/publication/ are stable and auditable:
- TeX include contract: generated .tex are tabular-only (no floats/captions/labels).
- Display alias contract: all labels come from display_name_map.json (no variants).
- Ordering contract: rows/bars use app_ordering.json exactly.
- Crosschecks: minimum invariants across figure inputs and table outputs.

It also writes contract artifacts under output/publication/manifests/:
- publication_contract.json
- publication_traceability.csv
- crosschecks.json
- (internal) math_receipt.md
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def _fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    raise SystemExit(2)


def _ok(msg: str) -> None:
    print(f"[OK] {msg}")


def _read_csv_skip_comments(p: Path) -> list[dict[str, str]]:
    txt = _read_text(p)
    lines = []
    for ln in txt.splitlines():
        if not lines and (not ln.strip() or ln.startswith("#")):
            continue
        if ln.strip():
            lines.append(ln)
    if not lines:
        return []
    r = csv.DictReader(lines)
    return [dict(row) for row in r]


def _schema_fingerprint_csv(p: Path) -> str:
    rows = _read_csv_skip_comments(p)
    if not rows:
        return "empty"
    # Use header field order as the fingerprint.
    txt = _read_text(p)
    lines = [ln for ln in txt.splitlines() if ln.strip() and not ln.startswith("#")]
    if not lines:
        return "empty"
    header = lines[0].strip()
    return hashlib.sha256(header.encode("utf-8")).hexdigest()


def _extract_first_column_tabular_tex(p: Path) -> list[str]:
    """Extract the first column (App) from a tabular-only TeX file."""
    out: list[str] = []
    for ln in _read_text(p).splitlines():
        s = ln.strip()
        if not s or s.startswith("%"):
            continue
        if "&" not in s or "\\\\" not in s:
            continue
        # Ignore header line (starts with App or MASVS Domain).
        if s.lower().startswith("app &") or s.lower().startswith("masvs domain &"):
            continue
        first = s.split("&", 1)[0].strip()
        # Remove any trailing TeX escapes.
        first = first.replace("\\_", "_")
        if first:
            out.append(first)
    return out


@dataclass(frozen=True)
class Contracts:
    display_name_by_package: dict[str, str]
    package_order: list[str]

    @property
    def display_names_ordered(self) -> list[str]:
        return [self.display_name_by_package.get(p, p) for p in self.package_order]


def _load_contracts(paper_manifests: Path) -> Contracts:
    dn = paper_manifests / "display_name_map.json"
    od = paper_manifests / "app_ordering.json"
    if not dn.exists():
        _fail(f"Missing display name map: {dn}")
    if not od.exists():
        _fail(f"Missing app ordering: {od}")
    display_obj = json.loads(_read_text(dn))
    order_obj = json.loads(_read_text(od))
    if not isinstance(display_obj, dict):
        _fail("display_name_map.json must be an object")
    if not isinstance(order_obj, list):
        _fail("app_ordering.json must be an array")
    display: dict[str, str] = {str(k).strip(): str(v).strip() for k, v in display_obj.items() if str(k).strip() and str(v).strip()}
    order = [str(x).strip() for x in order_obj if str(x).strip()]
    if len(set(order)) != len(order):
        _fail("app_ordering.json contains duplicates")
    return Contracts(display_name_by_package=display, package_order=order)


def gate_tex_include_contract(paper_tables: Path) -> None:
    """Generated TeX files must be tabular-only."""
    bad: list[str] = []
    for p in sorted(paper_tables.glob("*.tex")):
        txt = _read_text(p)
        if "\\begin{table" in txt or "\\caption{" in txt or "\\label{" in txt:
            bad.append(p.name)
        if "\\begin{tabular}" not in txt:
            bad.append(p.name + " (missing tabular)")
        for rule in ("\\toprule", "\\midrule", "\\bottomrule"):
            if rule not in txt:
                bad.append(p.name + f" (missing {rule})")
                break
    if bad:
        _fail("TeX include-contract violation (expected tabular-only): " + ", ".join(sorted(set(bad))))
    _ok("TeX include-contract: PASS (tabular-only).")


def gate_alias_and_ordering(paper_root: Path, contracts: Contracts) -> None:
    tables = paper_root / "tables"

    expected_apps = contracts.display_names_ordered

    # Table 4: app column order + alias-only.
    t4 = _read_csv_skip_comments(tables / "table_4_signature_deltas.csv")
    got_t4 = [r.get("app", "").strip() for r in t4]
    if got_t4 != expected_apps:
        _fail(f"Ordering drift in Table 4 app column. got={got_t4} expected={expected_apps}")
    if any(a not in set(contracts.display_name_by_package.values()) for a in got_t4):
        _fail("Alias drift: Table 4 contains a label not in display_name_map.json")

    # Table 7: package order and app label.
    t7 = _read_csv_skip_comments(tables / "table_7_exposure_deviation_summary.csv")
    got_pkgs = [r.get("package_name", "").strip() for r in t7]
    if got_pkgs != contracts.package_order:
        _fail(f"Ordering drift in Table 7 package_name. got={got_pkgs} expected={contracts.package_order}")
    got_apps = [r.get("app", "").strip() for r in t7]
    if got_apps != expected_apps:
        _fail(f"Alias/order drift in Table 7 app. got={got_apps} expected={expected_apps}")

    # Risk table: first column app order and alias-only.
    risk_apps = _extract_first_column_tabular_tex(tables / "table_risk_scoring.tex")
    if risk_apps != expected_apps:
        _fail(f"Ordering drift in risk table app column. got={risk_apps} expected={expected_apps}")

    # Explicit forbidden variants (minimal; extend as needed).
    forbidden = {"Facebook Messenger", "FB Messenger", "Messenger"}
    for p in sorted(tables.glob("*.tex")) + sorted(tables.glob("*.csv")):
        txt = _read_text(p)
        for f in forbidden:
            if f in txt:
                _fail(f"Forbidden label variant {f!r} found in {p}")

    _ok("Alias + ordering gates: PASS.")


def gate_crosschecks(paper_root: Path, contracts: Contracts) -> dict[str, Any]:
    """Minimum cross-artifact numeric invariants (no reruns required)."""

    tables = paper_root / "tables"
    t7 = _read_csv_skip_comments(tables / "table_7_exposure_deviation_summary.csv")
    t7_by_pkg = {r.get("package_name", "").strip(): r for r in t7}

    # Crosscheck 1: Table 7 RDI(IF, interactive) matches the deterministic dataset CSV used for Fig B2.
    #
    # Prefer a self-contained copy inside output/publication/internal/... so the gate can run from a bundle
    # without depending on gitignored `data/`.
    src = paper_root / "internal" / "baseline" / "inputs" / "anomaly_prevalence_per_app_phase.csv"
    if not src.exists():
        src = ROOT / "data" / "anomaly_prevalence_per_app_phase.csv"
    if not src.exists():
        _fail("Missing deterministic dataset CSV for B2 crosscheck (expected internal copy or data/).")
    rows = _read_csv_skip_comments(src)
    b2_by_pkg: dict[str, float] = {}
    for r in rows:
        if (r.get("phase") or "").strip() != "interactive":
            continue
        if (r.get("model") or "").strip() != "isolation_forest":
            continue
        pkg = (r.get("package_name") or "").strip()
        try:
            b2_by_pkg[pkg] = float(r.get("flagged_pct") or 0.0)
        except Exception:
            b2_by_pkg[pkg] = 0.0

    mism: list[dict[str, Any]] = []
    for pkg in contracts.package_order:
        if pkg not in t7_by_pkg:
            mism.append({"package_name": pkg, "field": "missing_table7"})
            continue
        want = b2_by_pkg.get(pkg)
        got_raw = t7_by_pkg[pkg].get("rdi_if_interactive")
        try:
            got = float(got_raw or 0.0)
        except Exception:
            got = None
        if want is None or got is None:
            mism.append({"package_name": pkg, "field": "rdi_if_interactive", "got": got_raw, "want": want})
            continue
        # Table 7 values are paper-facing and may be rounded for readability.
        if abs(want - got) > 1e-3:
            mism.append({"package_name": pkg, "field": "rdi_if_interactive", "got": got, "want": want})

    ok = len(mism) == 0
    return {"ok": ok, "mismatches": mism}


def write_phase_g_artifacts(
    *,
    paper_root: Path,
    contracts: Contracts,
    crosschecks: dict[str, Any],
) -> None:
    manifests = paper_root / "manifests"
    manifests.mkdir(parents=True, exist_ok=True)

    # Minimal contract doc (machine-readable).
    locked_tables = sorted([p.name for p in (paper_root / "tables").glob("*.tex")] + [p.name for p in (paper_root / "tables").glob("*.csv")])
    locked_figs = sorted([p.name for p in (paper_root / "figures").glob("*.pdf")] + [p.name for p in (paper_root / "figures").glob("*.png")])
    contract = {
        "artifact_type": "paper_contract",
        "paper_root": str(paper_root),
        "locked_artifacts": {
            "tables": locked_tables,
            "figures": locked_figs,
            "manifests": sorted([p.name for p in manifests.glob("*") if p.is_file()]),
        },
        "ordering": {
            "file": "app_ordering.json",
            "package_order": contracts.package_order,
        },
        "aliases": {
            "file": "display_name_map.json",
            "display_name_by_package": contracts.display_name_by_package,
        },
        "schema_fingerprints": {
            "table_4_signature_deltas.csv": _schema_fingerprint_csv(paper_root / "tables" / "table_4_signature_deltas.csv"),
            "table_7_exposure_deviation_summary.csv": _schema_fingerprint_csv(paper_root / "tables" / "table_7_exposure_deviation_summary.csv"),
        },
        "inputs": {
            "fig_b2_source_csv": str((ROOT / "data" / "anomaly_prevalence_per_app_phase.csv").relative_to(ROOT)),
        },
        "crosschecks": crosschecks,
    }
    (manifests / "publication_contract.json").write_text(
        json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # Traceability map (CSV).
    trace_rows = [
        {
            "artifact_path": "figures/fig_b2_rdi_social_by_app.pdf",
            "input_csv_path": "data/anomaly_prevalence_per_app_phase.csv",
            "key_fields": "package_name,phase,model",
        },
        {
            "artifact_path": "figures/fig_b2_rdi_messaging_by_app.pdf",
            "input_csv_path": "data/anomaly_prevalence_per_app_phase.csv",
            "key_fields": "package_name,phase,model",
        },
        {
            "artifact_path": "figures/fig_b4_static_vs_rdi.pdf",
            "input_csv_path": "tables/table_7_exposure_deviation_summary.csv",
            "key_fields": "package_name,static_posture_score,rdi_if_interactive",
        },
        {
            "artifact_path": "tables/table_4_signature_deltas.tex",
            "input_csv_path": "tables/table_4_signature_deltas.csv",
            "key_fields": "app",
        },
        {
            "artifact_path": "tables/table_7_exposure_deviation_summary.tex",
            "input_csv_path": "tables/table_7_exposure_deviation_summary.csv",
            "key_fields": "package_name",
        },
        {
            "artifact_path": "tables/table_risk_scoring.tex",
            "input_csv_path": "output/operational/<snapshot_id>/tables/risk_summary_per_group.csv",
            "key_fields": "package_name",
        },
        {
            "artifact_path": "tables/table_masvs_domain_mapping.tex",
            "input_csv_path": "(context-only; no per-app data)",
            "key_fields": "(n/a)",
        },
    ]
    out_csv = manifests / "publication_traceability.csv"
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["artifact_path", "input_csv_path", "key_fields"])
        w.writeheader()
        for r in trace_rows:
            w.writerow(r)

    (manifests / "crosschecks.json").write_text(json.dumps(crosschecks, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Internal math receipt (human-readable pointers; no DB required).
    audit_dir = paper_root / "internal" / "phase_g_audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    (audit_dir / "math_receipt.md").write_text(
        "\n".join(
            [
                "# Phase G Math Receipt (DB-free)",
                "",
                "This file records key math/contract semantics for paper regeneration audits.",
                "",
                "- RDI: `flagged_windows / windows_total` from `data/anomaly_prevalence_per_app_phase.csv`.",
                "- Threshold: 95th percentile of training-score distribution (see ML runner configs).",
                "- Windowing (paper): 10s windows / 5s stride; partial windows dropped.",
                "",
                "Code pointers:",
                "- Fig B2/B4 generation: `scytaledroid/DynamicAnalysis/ml/artifact_bundle_writer.py`",
                "- Canonical export: `scytaledroid/Paper/canonical_paper_writer.py`",
                "- Query-mode runner (operational snapshot): `scytaledroid/DynamicAnalysis/ml/query_mode_runner.py`",
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def main(argv: list[str]) -> int:
    paper_root = ROOT / "output" / "publication"
    if not paper_root.exists():
        _fail("Missing output/publication (write canonical publication bundle first).")
    contracts = _load_contracts(paper_root / "manifests")

    gate_tex_include_contract(paper_root / "tables")
    gate_alias_and_ordering(paper_root, contracts)
    cross = gate_crosschecks(paper_root, contracts)
    if not cross.get("ok", False):
        (paper_root / "manifests" / "crosschecks.json").write_text(json.dumps(cross, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _fail(f"Crosschecks FAIL: {len(cross.get('mismatches') or [])} mismatch(es)")
    _ok("Crosschecks: PASS.")

    write_phase_g_artifacts(paper_root=paper_root, contracts=contracts, crosschecks=cross)
    _ok("Phase G gate: PASS.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
