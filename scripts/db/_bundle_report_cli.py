#!/usr/bin/env python3
"""Shared CLI glue for read-only bundle-style DB audit scripts."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if any(arg in {"-h", "--help"} for arg in args):
        print("usage: _bundle_report_cli.py [-h]")
        print()
        print("Shared CLI glue for read-only bundle-style DB audit scripts.")
        print()
        print("options:")
        print("  -h, --help  show this help message and exit")
    return 0


def bootstrap_repo_root(wrapper_file: str) -> Path:
    repo_root = Path(wrapper_file).resolve().parents[2]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    return repo_root


def default_output_dir(repo_root: Path, leaf_dir: str) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return repo_root / "output" / "audit" / leaf_dir / stamp


def load_core_db() -> tuple[Any, Any]:
    from scytaledroid.Database.db_core import db_config
    from scytaledroid.Database.db_core import db_queries as core_q

    return db_config, core_q


def check_db_enabled(db_config: Any, disabled_message: str) -> str | None:
    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write(disabled_message + "\n")
        return "disabled"
    return None


def summarize_bundle(report: dict[str, Any], files: list[Path], output_dir: Path) -> dict[str, Any]:
    summary = dict(report.get("summary") or {})
    summary["output_dir"] = str(output_dir)
    summary["written_files"] = [str(path) for path in files]
    return summary


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
