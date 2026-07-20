#!/usr/bin/env python3
"""Rebuild legacy output/evidence/dynamic aliases from canonical evidence packs.

Dry-run is the default. ``--apply`` only repairs aliases for existing canonical
runs. ``--prune-orphans`` additionally removes legacy symlinks without a
same-named canonical pack. Neither mode deletes canonical evidence or
non-symlink conflicts.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--canonical-root", type=Path, help="Canonical dynamic evidence root.")
    parser.add_argument("--legacy-root", type=Path, help="Legacy output alias root.")
    parser.add_argument("--apply", action="store_true", help="Create or replace only same-run stale aliases.")
    parser.add_argument(
        "--prune-orphans",
        action="store_true",
        help="With --apply, remove only stale legacy symlinks without canonical evidence.",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.prune_orphans and not args.apply:
        _parser().error("--prune-orphans requires --apply")
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    from scytaledroid.DynamicAnalysis.utils.path_utils import (
        inspect_legacy_dynamic_aliases,
        rebuild_legacy_dynamic_aliases,
    )

    before = inspect_legacy_dynamic_aliases(
        canonical_root=args.canonical_root,
        legacy_root=args.legacy_root,
    )
    repairs = rebuild_legacy_dynamic_aliases(
        canonical_root=args.canonical_root,
        legacy_root=args.legacy_root,
        apply=args.apply,
        prune_orphans=args.prune_orphans,
    )
    after = (
        inspect_legacy_dynamic_aliases(canonical_root=args.canonical_root, legacy_root=args.legacy_root)
        if args.apply
        else before
    )
    payload = {
        "apply": bool(args.apply),
        "prune_orphans": bool(args.prune_orphans),
        "before": before.__dict__,
        "after": after.__dict__,
        "repairs": [repair.__dict__ for repair in repairs],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        mode = "applied" if args.apply else "planned"
        print(
            f"Dynamic evidence aliases: {mode}={len(repairs)} | "
            f"canonical={before.canonical_runs} valid={before.valid} "
            f"missing={before.missing} stale={before.stale} "
            f"conflicts={before.conflicts} orphaned={before.orphaned}"
        )
        if not args.apply and repairs:
            print("Re-run with --apply after restoring canonical evidence to repair listed aliases.")
        for repair in repairs[:20]:
            print(f"- {repair.run_id}: {repair.action} ({repair.detail})")
        if len(repairs) > 20:
            print(f"- ... {len(repairs) - 20} additional action(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
