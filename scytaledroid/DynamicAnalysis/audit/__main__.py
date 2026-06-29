"""CLI: ``python -m scytaledroid.DynamicAnalysis.audit``."""

from __future__ import annotations

from argparse import ArgumentParser

from .run_log_audit import emit_dynamic_audit_report


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser(
        description=(
            "Summarize dedicated dynamic run logs and core evidence artifacts for one dynamic_run_id."
        )
    )
    parser.add_argument(
        "--run-id",
        required=True,
        help="Dynamic run ID to inspect.",
    )
    args = parser.parse_args(argv)
    emit_dynamic_audit_report(args.run_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
