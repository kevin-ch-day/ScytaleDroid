"""CLI: ``python -m scytaledroid.DeviceAnalysis.evidence_verify``.

V1 harvest verification: filesystem (manifests/receipts, re-hash when recorded) plus
optional ``--with-db`` alignment against ``android_apk_repository``.
"""

from __future__ import annotations

from argparse import ArgumentParser
from pathlib import Path

from scytaledroid.Config import app_config

from .filesystem import format_report, verify_harvest_filesystem


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser(description="Harvest evidence verification (filesystem / manifest-first in V1).")
    fs = parser.add_argument_group("filesystem")
    fs.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Repo data root containing device_apks/ (defaults to configured DATA_DIR).",
    )
    fs.add_argument(
        "--serial",
        type=str,
        default=None,
        help="Limit scan to device_apks/<serial>/...",
    )
    fs.add_argument(
        "--warnings-as-errors",
        action="store_true",
        help="Exit non-zero if any verification warning appears.",
    )
    fs.add_argument(
        "--with-db",
        action="store_true",
        help="Also query android_apk_repository for each hashed manifest artifact (MariaDB reachable).",
    )
    args = parser.parse_args(argv)

    data_dir = (args.data_dir or Path(app_config.DATA_DIR)).expanduser().resolve()
    harvest_root = data_dir / "device_apks"

    issues, base_exit = verify_harvest_filesystem(
        harvest_root=harvest_root,
        data_root=data_dir,
        serial=args.serial,
    )

    if args.with_db:
        from .database import verify_harvest_db_alignment

        db_issues, db_exit = verify_harvest_db_alignment(
            harvest_root=harvest_root,
            data_root=data_dir,
            serial=args.serial,
        )
        issues.extend(db_issues)
        base_exit = max(base_exit, db_exit)

    txt = format_report(issues)
    if txt.strip():
        print(txt)

    if args.warnings_as_errors and base_exit == 0:
        warns = sum(1 for issue in issues if issue.severity == "warning")
        base_exit = 1 if warns else 0

    return base_exit


if __name__ == "__main__":
    raise SystemExit(main())
