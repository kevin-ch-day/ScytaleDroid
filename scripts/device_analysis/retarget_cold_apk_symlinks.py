#!/usr/bin/env python3
"""Retarget canonical cold-APK symlinks after moving external storage.

Dry-run is the default. The tool only changes symlinks under the canonical
``data/store/apk/sha256`` tree whose current resolved target is beneath
``--old-root`` and whose mapped target exists beneath ``--new-root``. It never
copies APK bytes, changes database rows, or edits regular files.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class RetargetAction:
    """One canonical APK symlink decision."""

    path: str
    action: str
    detail: str


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--canonical-root",
        type=Path,
        default=Path("data") / "store" / "apk" / "sha256",
        help="Canonical APK SHA-256 root relative to the current directory.",
    )
    parser.add_argument("--old-root", type=Path, required=True, help="Current external storage root in symlink targets.")
    parser.add_argument("--new-root", type=Path, required=True, help="Restored external storage root to target.")
    parser.add_argument("--apply", action="store_true", help="Atomically retarget eligible symlinks. Default is dry-run.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable output.")
    return parser


def plan_retarget(
    *,
    canonical_root: Path,
    old_root: Path,
    new_root: Path,
    apply: bool = False,
) -> tuple[RetargetAction, ...]:
    """Plan or atomically retarget verified canonical cold-APK symlinks."""

    canonical = canonical_root.expanduser()
    old = old_root.expanduser().resolve(strict=False)
    new = new_root.expanduser().resolve(strict=False)
    if not canonical.is_dir():
        return (RetargetAction(str(canonical), "blocked", "canonical root does not exist"),)

    actions: list[RetargetAction] = []
    for path in sorted(canonical.rglob("*.apk")):
        if not path.is_symlink():
            continue
        target = path.resolve(strict=False)
        try:
            relative_target = target.relative_to(old)
        except ValueError:
            actions.append(RetargetAction(str(path), "skip", "target is outside old root"))
            continue
        replacement = new / relative_target
        if target == replacement:
            actions.append(RetargetAction(str(path), "unchanged", "already targets new root"))
            continue
        if not replacement.is_file():
            actions.append(RetargetAction(str(path), "blocked", f"mapped target unavailable: {replacement}"))
            continue
        actions.append(RetargetAction(str(path), "retarget", str(replacement)))
        if apply:
            _replace_symlink(path, replacement)
    return tuple(actions)


def _replace_symlink(path: Path, target: Path) -> None:
    """Atomically replace an existing symlink without exposing a missing path."""

    temporary = path.with_name(f".{path.name}.retarget-{os.getpid()}")
    try:
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(target)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    canonical = args.canonical_root
    if not canonical.is_absolute():
        canonical = Path.cwd() / canonical
    actions = plan_retarget(
        canonical_root=canonical,
        old_root=args.old_root,
        new_root=args.new_root,
        apply=args.apply,
    )
    counts = {name: sum(action.action == name for action in actions) for name in {action.action for action in actions}}
    payload = {"apply": bool(args.apply), "counts": counts, "actions": [asdict(action) for action in actions]}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("Cold APK symlink retarget: " + " | ".join(f"{name}={count}" for name, count in sorted(counts.items())))
        for action in actions[:20]:
            print(f"- {action.path}: {action.action} ({action.detail})")
        if len(actions) > 20:
            print(f"- ... {len(actions) - 20} additional action(s)")
    return 1 if counts.get("blocked", 0) else 0


if __name__ == "__main__":
    raise SystemExit(main())
