#!/usr/bin/env python3
"""Read-only verification of the original pilot plus its pinned pre-runtime V2 freeze."""

import argparse
import json
import sys
from pathlib import Path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", required=True, type=Path)
    parser.add_argument("--original-packet", required=True, type=Path)
    parser.add_argument("--expect-manifest-sha256", required=True)
    parser.add_argument("--quarantine", required=True, type=Path)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from scytaledroid.DynamicAnalysis.tools.pilot_preruntime_v2 import verify_preruntime_v2

    try:
        result = verify_preruntime_v2(
            args.packet,
            expected_manifest_sha256=args.expect_manifest_sha256,
            original_packet=args.original_packet,
            source_root=args.source_root,
            quarantine=args.quarantine,
        )
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as exc:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error_type": type(exc).__name__,
                    "execution_authorized": False,
                }
            )
        )
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
