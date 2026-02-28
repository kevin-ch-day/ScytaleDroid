#!/usr/bin/env python3
"""Profile v3 scripted coverage audit (paper-grade, fail-closed).

This is a Profile v3 integrity gate. It ensures that for every package in the
v3 catalog, the current v3 manifest includes at least:
- 1 idle baseline run
- 1 scripted interaction run

Policy locks (Paper #3 / OSS vNext):
- manual interaction runs are excluded by default
- categorization is catalog-defined (package -> app_category)
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.DynamicAnalysis.run_profile_norm import (  # noqa: E402
    normalize_run_profile,
    phase_from_normalized_profile,
    resolve_run_profile_from_manifest,
)

from scytaledroid.Publication.profile_v3_metrics import (  # noqa: E402
    load_profile_v3_catalog,
    load_profile_v3_manifest,
)


def _rjson(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object: {path}")
    return payload


def _read_run_manifest(evidence_root: Path, run_id: str) -> dict:
    p = evidence_root / run_id / "run_manifest.json"
    if not p.exists():
        raise SystemExit(f"Missing run_manifest.json for run_id={run_id}: {p}")
    return _rjson(p)


def _package_name(man: dict) -> str:
    tgt = man.get("target") if isinstance(man.get("target"), dict) else {}
    pkg = str(tgt.get("package_name") or tgt.get("package") or "").strip()
    if not pkg:
        raise SystemExit("run_manifest missing target.package_name")
    return pkg


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Audit profile v3 scripted coverage (catalog x manifest)")
    p.add_argument(
        "--manifest",
        default=str(REPO_ROOT / "data" / "archive" / "profile_v3_manifest.json"),
        help="Path to profile v3 manifest (included_run_ids).",
    )
    p.add_argument(
        "--catalog",
        default=str(REPO_ROOT / "profiles" / "profile_v3_app_catalog.json"),
        help="Path to profile v3 app catalog.",
    )
    p.add_argument(
        "--evidence-root",
        default=str(REPO_ROOT / "output" / "evidence" / "dynamic"),
        help="Dynamic evidence root containing run directories.",
    )
    p.add_argument(
        "--out",
        default=str(REPO_ROOT / "output" / "audit" / "profile_v3" / "profile_v3_scripted_coverage.csv"),
        help="Output CSV path (paper-facing).",
    )
    p.add_argument(
        "--recapture-plan",
        default=str(REPO_ROOT / "output" / "audit" / "profile_v3" / "profile_v3_recapture_plan.csv"),
        help="Output recapture plan CSV path (operator-facing).",
    )
    args = p.parse_args(argv)

    manifest_path = Path(args.manifest)
    catalog_path = Path(args.catalog)
    evidence_root = Path(args.evidence_root)

    manifest = load_profile_v3_manifest(manifest_path)
    included = [str(r).strip() for r in (manifest.get("included_run_ids") or []) if str(r).strip()]
    if not included:
        print("[FAIL] Profile v3 NOT READY: manifest contains 0 included_run_ids.")
        print(f"manifest: {manifest_path}")
        print(f"catalog : {catalog_path}")
        print(f"evidence: {evidence_root}")
        print()
        print("Next steps:")
        print("- Capture scripted dynamic runs for the v3 cohort")
        print("- Rebuild the v3 manifest to populate included_run_ids (profile_v3_manifest_build.py)")
        return 2

    catalog = load_profile_v3_catalog(catalog_path)

    # Bucket included runs by package and normalized run_profile/phase.
    by_pkg: dict[str, dict[str, list[str]]] = {}
    unknown_pkgs: set[str] = set()
    for rid in included:
        man = _read_run_manifest(evidence_root, rid)
        pkg = _package_name(man)
        if pkg not in catalog:
            unknown_pkgs.add(pkg)
        rp = resolve_run_profile_from_manifest(man, strict_conflict=True).normalized
        rp = normalize_run_profile(rp)
        phase = phase_from_normalized_profile(rp)
        bucket = by_pkg.setdefault(pkg, {})
        bucket.setdefault(f"run_profile:{rp}", []).append(rid)
        bucket.setdefault(f"phase:{phase}", []).append(rid)

    rows: list[dict[str, object]] = []
    recapture_rows: list[dict[str, object]] = []
    failures: list[str] = []
    for pkg in sorted(catalog.keys()):
        meta = catalog.get(pkg) or {}
        app = str(meta.get("app") or "").strip()
        category = str(meta.get("app_category") or "").strip()
        buckets = by_pkg.get(pkg, {})
        idle = buckets.get("phase:idle", [])
        inter = buckets.get("phase:interactive", [])
        scripted = buckets.get("run_profile:interaction_scripted", [])
        manual = buckets.get("run_profile:interaction_manual", [])

        needs_idle = 1 if len(idle) == 0 else 0
        needs_scripted = 1 if len(scripted) == 0 else 0
        needs = needs_idle or needs_scripted

        if needs_idle:
            failures.append(f"MISSING_IDLE\t{pkg}")
        if needs_scripted:
            failures.append(f"MISSING_SCRIPTED_INTERACTION\t{pkg}")
        if manual:
            failures.append(f"MANUAL_INCLUDED\t{pkg}\tcount={len(manual)}")

        rows.append(
            {
                "package": pkg,
                "app": app,
                "app_category": category,
                "n_included_runs_total": len((buckets.get("phase:idle", []) or []) + (buckets.get("phase:interactive", []) or [])),
                "n_idle_runs": len(idle),
                "n_interactive_runs": len(inter),
                "n_scripted_interaction_runs": len(scripted),
                "n_manual_interaction_runs": len(manual),
                "idle_run_ids": " ".join(sorted(idle)),
                "scripted_interaction_run_ids": " ".join(sorted(scripted)),
                "manual_interaction_run_ids": " ".join(sorted(manual)),
                "needs_idle": needs_idle,
                "needs_scripted_interaction": needs_scripted,
            }
        )
        if needs:
            recapture_rows.append(
                {
                    "package": pkg,
                    "app": app,
                    "app_category": category,
                    "required_idle_runs_min": 1,
                    "required_scripted_interaction_runs_min": 1,
                    "have_idle_runs": len(idle),
                    "have_scripted_interaction_runs": len(scripted),
                    "have_manual_interaction_runs": len(manual),
                    "recapture_requirements": "idle>=1 scripted_interaction>=1",
                }
            )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "package",
                "app",
                "app_category",
                "n_included_runs_total",
                "n_idle_runs",
                "n_interactive_runs",
                "n_scripted_interaction_runs",
                "n_manual_interaction_runs",
                "needs_idle",
                "needs_scripted_interaction",
                "idle_run_ids",
                "scripted_interaction_run_ids",
                "manual_interaction_run_ids",
            ],
        )
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print(f"[OK] Wrote: {out_path}")
    rec_path = Path(args.recapture_plan)
    rec_path.parent.mkdir(parents=True, exist_ok=True)
    with rec_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "package",
                "app",
                "app_category",
                "required_idle_runs_min",
                "required_scripted_interaction_runs_min",
                "have_idle_runs",
                "have_scripted_interaction_runs",
                "have_manual_interaction_runs",
                "recapture_requirements",
            ],
        )
        w.writeheader()
        for r in recapture_rows:
            w.writerow(r)
    print(f"[OK] Wrote: {rec_path}")

    if unknown_pkgs:
        print("[WARN] Included runs contain packages missing from the v3 catalog:")
        for pkg in sorted(unknown_pkgs):
            print(f"  - {pkg}")

    if failures:
        print("[FAIL] Profile v3 scripted coverage: FAIL")
        for line in failures:
            print("  " + line)
        return 2

    print("[PASS] Profile v3 scripted coverage: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
