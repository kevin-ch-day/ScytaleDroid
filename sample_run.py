#!/usr/bin/env python3
"""
Debug sampler for Scytaledroid static analysis.

Run from repo root:
  python3 sample_run.py ZY22JK89DR 12
"""

from __future__ import annotations
import json, os, random, sys, traceback
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.StaticAnalysis.core.pipeline import analyze_apk
from scytaledroid.StaticAnalysis.core.context import AnalysisConfig

def collect_userland(device_dir: Path) -> list[Path]:
    apks = list(device_dir.glob("*/*/*.apk"))
    return [p for p in apks if "overlay" not in p.as_posix().lower()]

def main(device_id: str, k: int = 10) -> None:
    base_dir = Path(os.environ.get("BASE_DIR", REPO_ROOT / "data" / "apks" / "device_apks"))
    device_dir = base_dir / device_id
    if not device_dir.exists():
        print(json.dumps({"error": f"Device dir not found: {device_dir}"}, indent=2)); sys.exit(2)

    cands = collect_userland(device_dir)
    if not cands:
        print(json.dumps({"error": f"No APKs under {device_dir}"}, indent=2)); sys.exit(3)

    pick = random.sample(cands, min(k, len(cands)))
    cfg = AnalysisConfig(profile="full", enable_string_index=False, verbosity=2)

    results = []
    for apk_path in pick:
        try:
            rep = analyze_apk(apk_path, config=cfg)
            meta = rep.metadata or {}
            results.append({
                "apk": str(apk_path),
                "pkg": rep.manifest.package_name,
                "label": rep.manifest.app_label,
                "findings": len(rep.findings),
                "parse_error_resources": bool(meta.get("parse_error_resources")),
                "label_fallback": meta.get("label_fallback"),
            })
        except Exception:
            results.append({
                "apk": str(apk_path),
                "error": "exception",
                "traceback": traceback.format_exc()
            })

    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sample_run.py <DEVICE_ID> [count]", file=sys.stderr)
        sys.exit(1)
    device = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    main(device, count)
