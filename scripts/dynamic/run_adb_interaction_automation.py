#!/usr/bin/env python3
"""Run bounded ADB-backed interaction automation during dynamic capture."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from scytaledroid.DeviceAnalysis.adb import devices as adb_devices  # noqa: E402
from scytaledroid.DynamicAnalysis.scenarios.adb_automation import (  # noqa: E402
    AutomationAction,
    build_safe_fuzz_plan,
    build_x_twitter_plan,
    read_device_geometry,
    run_automation_actions,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Exercise an Android app through ADB while ScytaleDroid observers capture runtime behavior."
    )
    parser.add_argument("--serial", help="ADB device serial. Defaults to the only connected device.")
    parser.add_argument("--package", required=True, help="Target package name, e.g. com.twitter.android.")
    parser.add_argument("--duration", type=int, default=240, help="Target automation duration in seconds.")
    parser.add_argument(
        "--mode",
        choices=("auto", "x-plan", "safe-fuzz"),
        default="auto",
        help="Automation plan to run. auto uses x-plan for com.twitter.android, otherwise safe-fuzz.",
    )
    parser.add_argument("--seed", type=int, default=1, help="Deterministic seed for safe-fuzz mode.")
    parser.add_argument(
        "--allow-mutation",
        action="store_true",
        help="Allow mutation-capable steps such as controlled test-account compose/draft or content taps.",
    )
    parser.add_argument(
        "--submit-test-post",
        action="store_true",
        help="With --allow-mutation, submit one clearly labeled X test post instead of draft-only compose.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print the planned actions without executing ADB input.")
    return parser


def _resolve_serial(requested: str | None) -> str:
    return adb_devices.resolve_serial(adb_devices.list_devices(), requested)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    package = str(args.package or "").strip().lower()
    mode = str(args.mode or "auto").strip().lower()
    if mode == "auto":
        mode = "x-plan" if package == "com.twitter.android" else "safe-fuzz"
    if bool(args.submit_test_post) and not bool(args.allow_mutation):
        raise SystemExit("--submit-test-post requires --allow-mutation")

    serial = _resolve_serial(args.serial)
    geometry = read_device_geometry(serial)
    if mode == "x-plan":
        if package != "com.twitter.android":
            raise SystemExit("x-plan currently supports only --package com.twitter.android")
        actions = build_x_twitter_plan(
            duration_s=int(args.duration),
            allow_mutation=bool(args.allow_mutation),
            submit_test_post=bool(args.submit_test_post),
        )
    else:
        actions = build_safe_fuzz_plan(
            duration_s=int(args.duration),
            seed=int(args.seed),
            allow_mutation=bool(args.allow_mutation),
        )
        actions.insert(0, AutomationAction(f"launch {package}", "monkey_launch", (package,), 2.5))

    summary = {
        "serial": serial,
        "package": package,
        "mode": mode,
        "duration_s": int(args.duration),
        "screen": {"width": geometry.width, "height": geometry.height},
        "allow_mutation": bool(args.allow_mutation),
        "submit_test_post": bool(args.submit_test_post),
        "dry_run": bool(args.dry_run),
        "package_lock": True,
        "actions": [
            {
                "label": action.label,
                "op": action.op,
                "mutation_candidate": bool(action.mutation_candidate),
                "command": action.adb_command(geometry),
            }
            for action in actions
        ],
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    counts = run_automation_actions(
        serial=serial,
        actions=actions,
        geometry=geometry,
        dry_run=bool(args.dry_run),
        expected_package=package,
        package_lock=True,
    )
    print(json.dumps({"result": counts}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
