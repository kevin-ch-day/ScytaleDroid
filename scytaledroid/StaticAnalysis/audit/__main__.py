"""CLI: ``python -m scytaledroid.StaticAnalysis.audit``."""

from __future__ import annotations

from argparse import ArgumentParser

from .run_log_audit import emit_static_audit_report


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser(
        description=(
            "Scan static_analysis.log / error.log tails and summarize persistence audit JSON "
            "for a session stamp (filesystem-only; use db_scripts.static_run_audit for DB rows)."
        )
    )
    parser.add_argument(
        "--session",
        type=str,
        default=None,
        help="Session stamp (e.g. 20260501-rda-full) to match in logs and resolve persistence audit path.",
    )
    parser.add_argument(
        "--tail-lines",
        type=int,
        default=8000,
        help="How many lines to read from the end of each log file (default: 8000).",
    )
    parser.add_argument(
        "--max-hits",
        type=int,
        default=120,
        help="Cap matching lines printed per log file (default: 120).",
    )
    parser.add_argument(
        "--keyword",
        action="append",
        default=[],
        dest="keywords",
        metavar="SUBSTR",
        help="Extra case-insensitive substring to match (repeatable).",
    )
    args = parser.parse_args(argv)

    emit_static_audit_report(
        session=args.session,
        tail_lines=max(100, int(args.tail_lines)),
        max_hits_per_file=max(1, int(args.max_hits)),
        extra_keywords=tuple(args.keywords or ()),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
