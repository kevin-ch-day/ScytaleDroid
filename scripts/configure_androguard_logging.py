#!/usr/bin/env python3
"""Utility entry point for configuring androguard logging gates."""

from __future__ import annotations

import argparse
from pathlib import Path

from scytaledroid.Utils.LoggingUtils.logging_engine import (
    configure_third_party_loggers,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Configure androguard logging behaviour for ScytaleDroid runs.",
    )
    parser.add_argument(
        "--verbosity",
        choices=("normal", "detail", "debug"),
        default="normal",
        help="Verbosity level to apply when gating androguard logs.",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help=(
            "Deterministic identifier for debug runs. Defaults to 'session' when"
            " omitted."
        ),
    )
    parser.add_argument(
        "--log-dir",
        default=Path("logs"),
        type=Path,
        help="Directory where debug log files should be written.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    log_path = configure_third_party_loggers(
        verbosity=args.verbosity,
        run_id=args.run_id,
        debug_dir=str(Path(args.log_dir).expanduser().resolve()),
    )
    if log_path is None:
        print(
            "Androguard logging silenced for verbosity '",
            args.verbosity,
            "'.",
            sep="",
        )
    else:
        print(f"Androguard debug log captured at: {log_path}")


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    main()

