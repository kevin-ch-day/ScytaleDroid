#!/usr/bin/env python3
"""Paper #2 semantic lint.

This script enforces "reviewer safety" invariants:
- no accidental dynamic/final "risk score" language in Paper #2 docs
- MASVS table is explicitly findings-based (`finding_count_*` columns)
- Table 7 is explicitly interpretive and not a system output
- bundle closure receipt matches the bundle manifest

It is intentionally lightweight and DB-free.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def _fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    raise SystemExit(2)


def _warn(msg: str) -> None:
    print(f"[WARN] {msg}")


def _ok(msg: str) -> None:
    print(f"[OK] {msg}")


def _sha256_file(p: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def check_docs_language() -> None:
    paper2 = ROOT / "docs" / "paper2"
    if not paper2.exists():
        _warn("docs/paper2 missing; skipping docs lint.")
        return

    forbidden = [
        # Dynamic is deviation, never risk.
        re.compile(r"\bdynamic\s+risk\s+score\b", re.IGNORECASE),
        re.compile(r"\bruntime\s+risk\s+score\b", re.IGNORECASE),
        re.compile(r"\bdynamic\s+risk\b", re.IGNORECASE),
        # No fused scalar.
        re.compile(r"\bfinal\s+risk\s+score\b", re.IGNORECASE),
        re.compile(r"\bcombined\s+risk\s+score\b", re.IGNORECASE),
    ]

    hits: list[str] = []
    for p in sorted(paper2.rglob("*.md")):
        text = _read_text(p)
        for pat in forbidden:
            if pat.search(text):
                hits.append(f"{p.relative_to(ROOT)} matched {pat.pattern!r}")
    if hits:
        _fail("Forbidden Paper #2 wording found:\n" + "\n".join(hits))
    _ok("docs/paper2 wording: no forbidden dynamic/final risk phrases.")


def check_bundle_artifacts() -> None:
    bundle = ROOT / "output" / "paper"
    if not bundle.exists():
        _warn("Canonical paper output missing; skipping bundle lint.")
        return

    # Locked main-paper figures. Fig B2 is split into two narrower panels (a/b).
    for rel in (
        "figures/fig_b2_rdi_social_by_app.pdf",
        "figures/fig_b2_rdi_messaging_by_app.pdf",
        "figures/fig_b4_static_vs_rdi.pdf",
    ):
        p = bundle / rel
        if not p.exists():
            _fail(f"Missing locked figure: output/paper/{rel}")
    _ok("Locked figures: present (B2, B4).")

    # Locked main-paper tables.
    masvs_map = bundle / "tables" / "table_masvs_domain_mapping.tex"
    if not masvs_map.exists():
        _fail("Missing MASVS mapping table tex: output/paper/tables/table_masvs_domain_mapping.tex")
    txt_map = _read_text(masvs_map)
    if "MASVS-" not in txt_map:
        _fail("MASVS mapping table does not contain MASVS domain labels (expected MASVS-*).")
    # Guardrail: allow mentioning "pass/fail" only in the explicit disclaimer text.
    lowered = txt_map.lower()
    if "finding_count" in lowered:
        _fail("MASVS mapping table appears evaluative; expected context-only mapping (no findings counts).")
    if ("pass" in lowered or "fail" in lowered) and ("does not represent masvs compliance" not in lowered):
        _fail("MASVS mapping table appears evaluative; expected context-only mapping (no pass/fail).")
    _ok("MASVS mapping table: present (context-only).")

    t4 = bundle / "tables" / "table_4_signature_deltas.tex"
    if not t4.exists():
        _fail("Missing Table 4 tex: output/paper/tables/table_4_signature_deltas.tex")
    _ok("Table 4 tex: present.")

    # Table 7: interpretive caption in tex
    t7_tex = bundle / "tables" / "table_7_exposure_deviation_summary.tex"
    if not t7_tex.exists():
        _fail("Missing Table 7 tex: output/paper/tables/table_7_exposure_deviation_summary.tex")
    cap_line = ""
    for line in _read_text(t7_tex).splitlines():
        if line.startswith("% Table 7:"):
            cap_line = line
            break
    if not cap_line:
        _fail("Table 7 tex missing caption comment line starting with '% Table 7:'.")
    need = ["Interpretive", "not system outputs", "not represent measured security risk"]
    missing = [s for s in need if s.lower() not in cap_line.lower()]
    if missing:
        _fail("Table 7 caption missing required disclaimers: " + ", ".join(missing))
    _ok("Table 7 caption: interpretive + not system output + not measured risk.")

    # Risk scoring table: required for main paper assembly.
    risk_tex = bundle / "tables" / "table_risk_scoring.tex"
    if not risk_tex.exists():
        _fail("Missing risk scoring table tex: output/paper/tables/table_risk_scoring.tex")
    txt = _read_text(risk_tex)
    if "Final Regime" not in txt:
        _fail("Risk scoring table missing 'Final Regime' label (expected PM wording).")
    _ok("Risk scoring table: present (table_risk_scoring.tex).")

    # Phase G include-contract (paper owns floats/captions/labels): generated TeX must be tabular-only.
    for p in sorted((bundle / "tables").glob("*.tex")):
        txt = _read_text(p)
        if "\\begin{table" in txt or "\\caption{" in txt or "\\label{" in txt:
            _fail(f"Generated table is not tabular-only (contains float/caption/label): {p}")
        for need in ("\\begin{tabular}", "\\toprule", "\\midrule", "\\bottomrule"):
            if need not in txt:
                _fail(f"Generated table missing required TeX token {need!r}: {p}")
    _ok("TeX include-contract: tabular-only tables verified.")

    # Enforce main-paper lock: no extra artifacts in paper-facing tables/figures.
    allow_tables = {
        "table_masvs_domain_mapping.tex",
        "table_4_signature_deltas.tex",
        "table_4_signature_deltas.csv",
        "table_7_exposure_deviation_summary.tex",
        "table_7_exposure_deviation_summary.csv",
        "table_risk_scoring.tex",
    }
    allow_figs = {
        "fig_b2_rdi_social_by_app.pdf",
        "fig_b2_rdi_social_by_app.png",
        "fig_b2_rdi_messaging_by_app.pdf",
        "fig_b2_rdi_messaging_by_app.png",
        "fig_b4_static_vs_rdi.pdf",
        "fig_b4_static_vs_rdi.png",
    }
    extra_tables = sorted([p.name for p in (bundle / "tables").iterdir() if p.is_file() and p.name not in allow_tables])
    extra_figs = sorted([p.name for p in (bundle / "figures").iterdir() if p.is_file() and p.name not in allow_figs])
    if extra_tables:
        _fail("Unexpected extra paper-facing table artifacts present (scope creep): " + ", ".join(extra_tables))
    if extra_figs:
        _fail("Unexpected extra paper-facing figure artifacts present (scope creep): " + ", ".join(extra_figs))
    _ok("Paper-facing directories: no extra artifacts beyond locked set.")

    # Closure record pins manifest hash correctly
    closure = bundle / "manifests" / "phase_e_closure_record.json"
    manifest = bundle / "internal" / "provenance" / "phase_e_artifacts_manifest.json"
    if not closure.exists():
        _fail("Missing closure record: output/paper/manifests/phase_e_closure_record.json")
    if not manifest.exists():
        _fail("Missing artifacts manifest: output/paper/internal/provenance/phase_e_artifacts_manifest.json")
    obj = json.loads(_read_text(closure))
    expected = _sha256_file(manifest)
    got = str(obj.get("bundle_manifest_sha256") or "").strip()
    if got != expected:
        _fail(f"Closure record manifest sha mismatch: got={got} expected={expected}")
    _ok("Closure record: manifest sha matches.")


def main() -> None:
    check_docs_language()
    check_bundle_artifacts()
    _ok("Semantic lint passed.")


if __name__ == "__main__":
    main()
