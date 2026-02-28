#!/usr/bin/env python3
"""Validate Profile v3 catalog coverage against included runs (fail-fast helper).

This helper does not modify any artifacts. It reads:
- data/archive/profile_v3_manifest.json (included_run_ids)
- output/evidence/dynamic/<run_id>/run_manifest.json (package_name)
- profiles/profile_v3_app_catalog.json (package -> app/category)

It prints a report and exits non-zero if any included run's package is missing
from the catalog.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Publication.profile_v3_metrics import (  # noqa: E402
    ProfileV3Error,
    load_profile_v3_catalog,
    load_profile_v3_manifest,
)


def _rjson(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object: {path}")
    return payload


def _package_from_run_manifest(path: Path) -> str:
    man = _rjson(path)
    target = man.get("target") if isinstance(man.get("target"), dict) else {}
    pkg = str(target.get("package_name") or target.get("package") or "").strip()
    if not pkg:
        raise ProfileV3Error("PROFILE_V3_BAD_MANIFEST", f"missing package_name in {path}")
    return pkg


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Validate profile v3 app catalog coverage")
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
        help="Dynamic evidence root.",
    )
    p.add_argument(
        "--emit-json-snippet",
        action="store_true",
        help="Emit a JSON snippet mapping missing packages to empty placeholders for manual fill.",
    )
    args = p.parse_args(argv)

    manifest_path = Path(args.manifest)
    catalog_path = Path(args.catalog)
    evidence_root = Path(args.evidence_root)

    manifest = load_profile_v3_manifest(manifest_path)
    included = [str(r).strip() for r in (manifest.get("included_run_ids") or []) if str(r).strip()]
    if not included:
        catalog_n = "unknown"
        try:
            catalog_n = str(len(load_profile_v3_catalog(catalog_path)))
        except Exception:
            pass
        print("[FAIL] Profile v3 NOT READY: manifest contains 0 included_run_ids.")
        print(f"manifest: {manifest_path}")
        print(f"catalog : {catalog_path} (packages={catalog_n})")
        print(f"evidence: {evidence_root}")
        print()
        print("Next steps:")
        print("- Run: Reporting -> Profile v3 -> Run v3 integrity gates")
        print("- Capture scripted dynamic runs for the v3 cohort")
        print("- Rebuild the v3 manifest to populate included_run_ids (profile_v3_manifest_build.py)")
        return 2

    catalog = load_profile_v3_catalog(catalog_path)

    missing: dict[str, dict[str, str]] = {}
    seen: dict[str, int] = {}
    for run_id in included:
        run_dir = evidence_root / run_id
        man_path = run_dir / "run_manifest.json"
        if not man_path.exists():
            raise SystemExit(f"PROFILE_V3_MISSING_RUN_DIR: missing run_manifest.json for {run_id}")
        pkg = _package_from_run_manifest(man_path)
        seen[pkg] = int(seen.get(pkg, 0)) + 1
        if pkg not in catalog:
            missing.setdefault(pkg, {"app": "", "app_category": ""})

    if missing:
        pkgs = sorted(missing.keys())
        print("[FAIL] Missing packages in profiles/profile_v3_app_catalog.json:")
        for pkg in pkgs:
            print(f"- {pkg} (runs_included={seen.get(pkg, 0)})")
        if args.emit_json_snippet:
            print()
            print("JSON snippet to paste into the catalog (fill app/app_category):")
            print(json.dumps({pkg: missing[pkg] for pkg in pkgs}, indent=2, sort_keys=True))
        return 2

    print(f"[OK] Catalog covers all included packages (unique_packages={len(seen)}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
