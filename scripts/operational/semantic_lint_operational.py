#!/usr/bin/env python3
"""Operational snapshot semantic lint (Phase F3).

This is a *math audit* and consistency checker for query-mode snapshots under
output/operational/<snapshot_id>/.

It validates:
- required tables exist
- key ratios are internally consistent (pct = anomalous/windows)
- dynamic score/grade computations match the spec (docs/operational_risk_scoring.md)
- final regime/grade labels are consistent with exposure+deviation grades
- threshold stability fields are self-consistent

This is DB-free and intended for reproducible auditing.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _ok(msg: str) -> None:
    print(f"[OK] {msg}")


def _latest_snapshot(root: Path) -> Path | None:
    if not root.exists():
        return None
    snaps = sorted([p for p in root.iterdir() if p.is_dir()])
    return snaps[-1] if snaps else None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", help="Path to output/operational/<snapshot_id> (default=latest).")
    args = ap.parse_args(argv)

    # Allow running from a git checkout without installation.
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    snap_root = ROOT / "output" / "operational"
    snap = Path(args.snapshot) if args.snapshot else _latest_snapshot(snap_root)
    if not snap:
        print(f"[FAIL] No operational snapshots found under {snap_root}")
        return 2
    from scytaledroid.DynamicAnalysis.ml.operational_lint import lint_operational_snapshot

    res = lint_operational_snapshot(snap)
    if not res.ok:
        print("[FAIL] Operational semantic lint failed:")
        for issue in res.issues[:30]:
            print(f"- {issue}")
        return 2
    _ok(f"Operational semantic lint passed: {snap}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
