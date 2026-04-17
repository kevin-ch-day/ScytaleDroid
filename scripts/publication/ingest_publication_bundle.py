#!/usr/bin/env python3
"""Ingest the canonical publication bundle into the DB (optional).

Policy:
- Canonical truth is filesystem: output/publication/* (rebuildable from evidence).
- DB is a mirror/index/cache. This step is optional and may fail without blocking workflows.

This script reads output/publication/manifests/publication_results_v1.json to derive a
deterministic cohort_id keyed by freeze_dataset_hash, then invokes the existing
DB ingest tool.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _read_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Optional: ingest output/publication bundle into DB.")
    ap.add_argument("--bundle-root", default="output/publication", help="Path to canonical output/publication directory.")
    ap.add_argument("--name", default=None, help="Human-friendly cohort name (default derived).")
    ap.add_argument("--selector-type", default="freeze", choices=["freeze", "query", "manual"], help="Selector type.")
    args = ap.parse_args(argv)

    bundle_root = Path(args.bundle_root).resolve()
    results = bundle_root / "manifests" / "publication_results_v1.json"
    if not results.exists():
        results = bundle_root / "manifests" / "paper_results_v1.json"
    if not results.exists():
        print(f"Missing: {results}", file=sys.stderr)
        return 2
    payload = _read_json(results)
    freeze_hash = str(payload.get("freeze_dataset_hash") or "").strip()
    if not freeze_hash:
        print(f"{results.name} missing freeze_dataset_hash", file=sys.stderr)
        return 2

    cohort_id = f"freeze_{freeze_hash}"
    name = args.name or f"Freeze {freeze_hash[:12]}"

    cmd = [
        sys.executable,
        "-m",
        "scytaledroid.Database.tools.analysis_ingest",
        "--bundle-root",
        str(bundle_root),
        "--cohort-id",
        cohort_id,
        "--name",
        name,
        "--selector-type",
        str(args.selector_type),
    ]
    # This step is optional; let failures surface as non-zero exit to the caller.
    return subprocess.call(cmd)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
