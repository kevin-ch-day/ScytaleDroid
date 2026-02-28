#!/usr/bin/env python3
"""Profile v3 publication bundle lint runner (paper-grade contract)."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Publication.paper_mode import PaperModeContext  # noqa: E402

from scytaledroid.Publication.profile_v3_contract import lint_profile_v3_bundle  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Lint Profile v3 publication bundle")
    p.add_argument(
        "--root",
        default=str(REPO_ROOT / "output" / "publication" / "profile_v3"),
        help="Publication root to lint.",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Enable strict mode (equivalent to SCYTALEDROID_PAPER_STRICT=1).",
    )
    args = p.parse_args(argv)

    mode = PaperModeContext.detect(repo_root=REPO_ROOT, strict_arg=bool(args.strict))
    mode.apply_env()
    mode.assert_clean_if_required()

    root = Path(args.root)
    lint = lint_profile_v3_bundle(root)
    if lint.ok:
        print("[PASS] Profile v3 lint: READY")
        print(
            f"[COPY] v3_lint=PASS root='{root.relative_to(REPO_ROOT)}' "
            f"strict={int(mode.strict)} errors=0 warnings={len(lint.warnings)}"
        )
        if lint.warnings:
            print("[WARN] Warnings (first 20):")
            for w in lint.warnings[:20]:
                print("- " + w)
        return 0

    print("[FAIL] Profile v3 lint: NOT READY")
    print(
        f"[COPY] v3_lint=FAIL root='{root.relative_to(REPO_ROOT)}' "
        f"strict={int(mode.strict)} errors={len(lint.errors)} warnings={len(lint.warnings)}"
    )
    print("Errors (first 50):")
    for e in lint.errors[:50]:
        print("- " + e)
    if len(lint.errors) > 50:
        print(f"- ... ({len(lint.errors) - 50} more)")
    if lint.warnings:
        print("Warnings (first 20):")
        for w in lint.warnings[:20]:
            print("- " + w)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
