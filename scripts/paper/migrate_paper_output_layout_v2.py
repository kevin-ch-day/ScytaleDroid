#!/usr/bin/env python3
"""Migrate paper outputs into the canonical `output/paper/` structure.

Moves legacy Phase E/F bundles into output/paper/internal/:
  - output/paper/paper2/baseline -> output/paper/internal/baseline
  - output/paper/paper2/snapshots/<id> -> output/paper/internal/snapshots/<id>

Also supports older legacy:
  - output/paper/paper2/phase_e -> output/paper/internal/baseline
  - output/paper/paper2/phase_f/<id> -> output/paper/internal/snapshots/<id>

This is filesystem-only and does not change computed artifacts.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _move(src: Path, dst: Path, *, dry_run: bool) -> None:
    if not src.exists():
        return
    if dst.exists():
        raise SystemExit(f"[FAIL] Destination already exists: {dst}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    print(f"[MOVE] {src} -> {dst}")
    if dry_run:
        return
    shutil.move(str(src), str(dst))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    paper = ROOT / "output" / "paper"
    paper2 = paper / "paper2"
    internal = paper / "internal"
    internal_base = internal / "baseline"
    internal_snaps = internal / "snapshots"

    did = False

    # Phase E baseline.
    for legacy in (paper2 / "baseline", paper2 / "phase_e"):
        if legacy.exists():
            _move(legacy, internal_base, dry_run=bool(args.dry_run))
            did = True
            break

    # Phase F snapshots.
    for legacy_snaps_root in (paper2 / "snapshots", paper2 / "phase_f"):
        if not legacy_snaps_root.exists():
            continue
        internal_snaps.mkdir(parents=True, exist_ok=True)
        for snap in sorted([p for p in legacy_snaps_root.iterdir() if p.is_dir()]):
            _move(snap, internal_snaps / snap.name, dry_run=bool(args.dry_run))
            did = True
        if not args.dry_run:
            try:
                legacy_snaps_root.rmdir()
                print(f"[RM] {legacy_snaps_root} (empty)")
            except OSError:
                pass

    if not args.dry_run and paper2.exists():
        # Remove paper2 if empty.
        try:
            paper2.rmdir()
            print(f"[RM] {paper2} (empty)")
        except OSError:
            pass

    if not did:
        print("[OK] Nothing to migrate.")
    else:
        print("[OK] Migration complete.")
        print(f"[INFO] Internal baseline: {internal_base}")
        print(f"[INFO] Internal snapshots: {internal_snaps}")
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
