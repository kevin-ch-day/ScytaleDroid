#!/usr/bin/env python3
"""Profile v3 catalog freeze check (paper-grade cohort lock).

This is a pre-harvest/capture guard. It enforces that the v3 cohort definition
is stable before operators start pulling APKs or capturing dynamic runs.

Policy (PM-locked for OSS vNext / Paper #3):
- catalog must contain exactly 21 packages (no temporary 19-app phase)
- every package entry must define: app + app_category
- app_category must be one of the allowed enum values
"""

from __future__ import annotations

import argparse
import sys
import signal
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.Publication.profile_v3_metrics import (  # noqa: E402
    ALLOWED_CATEGORIES,
    load_profile_v3_catalog,
)


EXPECTED_PAPER_GRADE_COHORT_SIZE = 21


def main(argv: list[str] | None = None) -> int:
    # If output is piped (e.g., to `head`), avoid noisy BrokenPipeError messages.
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except Exception:
        pass

    p = argparse.ArgumentParser(description="Profile v3 catalog freeze check (fail-closed)")
    p.add_argument(
        "--catalog",
        default=str(REPO_ROOT / "profiles" / "profile_v3_app_catalog.json"),
        help="Path to Profile v3 app catalog.",
    )
    args = p.parse_args(argv)

    catalog_path = Path(args.catalog)
    catalog = load_profile_v3_catalog(catalog_path)

    errors: list[str] = []
    if len(catalog) != EXPECTED_PAPER_GRADE_COHORT_SIZE:
        errors.append(f"catalog_size:{len(catalog)}!=expected:{EXPECTED_PAPER_GRADE_COHORT_SIZE}")

    for pkg in sorted(catalog.keys()):
        meta = catalog.get(pkg) or {}
        app = str(meta.get("app") or "").strip()
        cat = str(meta.get("app_category") or "").strip()
        if not app:
            errors.append(f"missing_app_label:{pkg}")
        if cat not in ALLOWED_CATEGORIES:
            errors.append(f"bad_app_category:{pkg}:{cat or 'missing'}")

    if errors:
        print("[FAIL] Profile v3 catalog is not frozen (paper-grade cohort lock failed).")
        print(f"catalog: {catalog_path}")
        for e in errors:
            print(f"  - {e}")
        print(f"[COPY] v3_catalog_frozen=FAIL catalog_packages={len(catalog)} expected={EXPECTED_PAPER_GRADE_COHORT_SIZE}")
        print()
        print("Next steps:")
        print("- Install missing apps on the capture device (e.g., Drive/Sheets).")
        print("- Update profiles/profile_v3_app_catalog.json to exactly 21 packages with categories.")
        print("- (Helper) After install+inventory sync: scripts/profile_tools/profile_v3_catalog_suggest_missing.py")
        print("- Re-run this check before harvest/capture.")
        return 2

    # Stable summary (paper-facing).
    counts: dict[str, int] = {c: 0 for c in sorted(ALLOWED_CATEGORIES)}
    for pkg in catalog:
        counts[str(catalog[pkg]["app_category"])] += 1

    print("[PASS] Profile v3 catalog frozen (paper-grade).")
    print(f"  catalog_packages={len(catalog)}")
    print(f"  category_counts={counts}")
    print(f"[COPY] v3_catalog_frozen=PASS catalog_packages={len(catalog)} expected={EXPECTED_PAPER_GRADE_COHORT_SIZE} category_counts={counts}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        raise SystemExit(0)
