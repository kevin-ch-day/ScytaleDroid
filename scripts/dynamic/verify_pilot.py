#!/usr/bin/env python3
"""Verify a pinned pilot packet without DB access, APK parsing or execution."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", required=True, type=Path)
    parser.add_argument("--expect-manifest-sha256", required=True)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument(
        "--quarantine", type=Path, help="Optional opaque payload rehash; never APK parsing"
    )
    args = parser.parse_args(argv)
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from scytaledroid.DynamicAnalysis.tools.pilot_preflight import (
        PilotVerificationError,
        verify_pilot,
    )

    try:
        report = verify_pilot(
            args.packet,
            expected_manifest_sha256=args.expect_manifest_sha256,
            source_root=args.source_root,
            quarantine=args.quarantine,
        )
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as exc:
        # Do not echo malformed source content, config values or arbitrary paths.
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error_type": type(exc).__name__,
                    "reason": str(exc)
                    if isinstance(exc, PilotVerificationError)
                    else "Input unavailable or malformed",
                    "execution_authorized": False,
                }
            )
        )
        return 2
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if args.quarantine is not None else 3


if __name__ == "__main__":
    raise SystemExit(main())
