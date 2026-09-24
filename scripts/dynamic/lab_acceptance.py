#!/usr/bin/env python3
"""Run one isolated boot probe or the pinned benign fixture. Never runs malware."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["boot", "benign"])
    parser.add_argument("--lab-root", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New evidence directory; existing directories are refused",
    )
    parser.add_argument(
        "--gpu-mode", choices=["software", "swiftshader", "lavapipe", "swangle"], default="lavapipe"
    )
    parser.add_argument(
        "--control",
        action="append",
        choices=["wipe", "grpc", "dns", "pcap"],
        default=[],
        help="Boot diagnosis only; add a research control explicitly",
    )
    args = parser.parse_args()
    if args.mode == "benign" and args.control:
        parser.error("Benign acceptance always uses all controls")
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    import json

    from scytaledroid.DynamicAnalysis.lab.runner import run_benign, run_boot_probe

    kwargs = dict(
        lab_root=args.lab_root, apk=args.fixture, output=args.output, gpu_mode=args.gpu_mode
    )
    result = (
        run_benign(**kwargs)
        if args.mode == "benign"
        else run_boot_probe(**kwargs, controls=tuple(args.control))
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["acceptance_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
