#!/usr/bin/env python3
"""Read-only audit of static dangling rows that still overlap legacy mirror tables."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Write outputs to this directory instead of output/audit/artifact_registry_static_legacy_overlap/<stamp>/.",
    )
    parser.add_argument("--json", action="store_true", help="Print summary JSON to stdout after writing files.")
    return parser


def _default_output_dir() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return _REPO_ROOT / "output" / "audit" / "artifact_registry_static_legacy_overlap" / stamp


def _load_db() -> tuple[Any, Any]:
    from scytaledroid.Database.db_core import db_config
    from scytaledroid.Database.db_core import db_queries as core_q

    return db_config, core_q


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        db_config, core_q = _load_db()
        if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
            sys.stderr.write("DB disabled; static legacy overlap audit needs the core database.\n")
            return 2
        from scytaledroid.Database.db_utils.artifact_registry_static_legacy_overlap import (
            collect_static_legacy_overlap_report,
            write_static_legacy_overlap_bundle,
        )

        output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
        report = collect_static_legacy_overlap_report(core_q.run_sql)
        files = write_static_legacy_overlap_bundle(report, output_dir)
        summary = dict(report.get("summary") or {})
        summary["output_dir"] = str(output_dir)
        summary["written_files"] = [str(path) for path in files]

        if args.json:
            sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n")
            return 0

        print("# artifact_registry static legacy overlap audit (read-only)")
        print(f"output_dir: {output_dir}")
        print(f"overlap_registry_rows: {summary.get('overlap_registry_rows')}")
        print(f"overlap_run_ids: {summary.get('overlap_run_ids')}")
        print(f"overlap_session_stamps: {summary.get('overlap_session_stamps')}")
        print(f"top_session_stamps: {json.dumps(summary.get('top_session_stamps') or [])}")
        return 0
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"static legacy overlap audit failed: {type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
