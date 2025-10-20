"""Utility script to initialise canonical persistence helpers."""

from __future__ import annotations

import argparse
from typing import Optional

from standalone import db_lib


def _coerce_session(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = value.strip()
    return text or None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Initialise canonical persistence helpers for static analysis runs.",
    )
    parser.add_argument(
        "--session",
        dest="session",
        help="Optional session stamp to scope provider ingestion and string views.",
    )
    args = parser.parse_args()

    session = _coerce_session(args.session)

    if not db_lib.ensure_provider_plumbing():
        print("Failed to ensure canonical schema; aborting.")
        return 2

    promoted = db_lib.upsert_base002_for_session(session)
    sample_rows = db_lib.build_session_string_view(session)

    print("Canonical persistence ready.")
    print(f"  BASE-002 findings promoted: {promoted}")
    print(f"  Session string samples available: {sample_rows}")

    return 0


if __name__ == "__main__":  # pragma: no cover - script entry point
    raise SystemExit(main())
