#!/usr/bin/env python3
"""Phase F3 acceptance gate (operational snapshot closure).

Creates a real query-mode snapshot from the on-disk evidence packs and asserts
the snapshot is self-contained and auditable:
- selection_manifest.json written
- freeze_manifest.json written (checksummed)
- operational_lint.json ok
- snapshot_bundle_manifest.json present
- snapshot_summary.json indicates bundle_ok

This avoids the smoke gate's temporary evidence root (which intentionally gets cleaned).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _fail(msg: str) -> int:
    print(f"[phase_f3_gate] FAIL {msg}")
    return 2


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", default="com.facebook.katana", help="Package to snapshot (must exist in evidence packs).")
    args = ap.parse_args(argv)

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    from scytaledroid.Config import app_config
    from scytaledroid.DynamicAnalysis.ml.selectors import QueryParams, QuerySelector
    from scytaledroid.DynamicAnalysis.ml.query_mode_runner import run_ml_query_mode

    evidence_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    if not evidence_root.exists():
        return _fail(f"missing evidence root: {evidence_root}")

    params = QueryParams(
        tier="dataset",
        package_name=args.package,
        include_unknown_mode=True,
        pool_versions=False,
        require_valid_dataset_run=True,
    )
    sel = QuerySelector(evidence_root=evidence_root, params=params, allow_db_index=False).select()
    if not sel.included:
        return _fail(f"no runs selected for package={args.package}")

    stats = run_ml_query_mode(selection=sel, reuse_existing_outputs=True)
    snap = Path(stats.snapshot_dir)
    summary_path = snap / "snapshot_summary.json"
    if not summary_path.exists():
        return _fail("missing snapshot_summary.json")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if summary.get("bundle_ok") is not True:
        return _fail(f"bundle_ok is not true (freeze_ok={summary.get('freeze_ok')} lint_ok={summary.get('lint_ok')})")

    for p in ("selection_manifest.json", "freeze_manifest.json", "operational_lint.json", "snapshot_bundle_manifest.json", "model_registry.json"):
        if not (snap / p).exists():
            return _fail(f"missing required artifact: {p}")

    print("[phase_f3_gate] PASS")
    print(f"- snapshot: {snap}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

