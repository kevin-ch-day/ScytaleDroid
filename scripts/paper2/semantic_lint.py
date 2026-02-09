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
import sys
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
    bundle = ROOT / "output" / "paper" / "paper2" / "phase_e"
    if not bundle.exists():
        _warn("Phase E bundle missing; skipping bundle lint.")
        return

    # Table 5: findings-based naming
    t5 = bundle / "tables" / "table_5_masvs_coverage.csv"
    if not t5.exists():
        _fail("Missing Table 5: output/paper/paper2/phase_e/tables/table_5_masvs_coverage.csv")
    header = ""
    for line in _read_text(t5).splitlines():
        if line.startswith("#") or not line.strip():
            continue
        header = line.strip()
        break
    if not header:
        _fail("Table 5 CSV has no header row.")
    if "finding_count_total" not in header or "finding_count_platform" not in header:
        _fail("Table 5 header does not look findings-based (expected finding_count_* columns).")
    _ok("Table 5 columns: findings-based (`finding_count_*`).")

    # Table 7: interpretive caption in tex
    t7_tex = bundle / "tables" / "table_7_exposure_deviation_summary.tex"
    if not t7_tex.exists():
        _fail("Missing Table 7 tex: output/paper/paper2/phase_e/tables/table_7_exposure_deviation_summary.tex")
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

    # Closure record pins manifest hash correctly
    closure = bundle / "manifest" / "phase_e_closure_record.json"
    manifest = bundle / "manifest" / "phase_e_artifacts_manifest.json"
    if not closure.exists():
        _fail("Missing closure record: output/paper/paper2/phase_e/manifest/phase_e_closure_record.json")
    if not manifest.exists():
        _fail("Missing artifacts manifest: output/paper/paper2/phase_e/manifest/phase_e_artifacts_manifest.json")
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

