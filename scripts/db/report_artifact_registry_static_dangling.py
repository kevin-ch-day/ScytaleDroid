#!/usr/bin/env python3
"""Read-only audit of dangling static ``artifact_registry`` rows.

Correlates dangling registry rows against surviving static DB surfaces and local
files, then writes a CSV/JSON audit bundle.

Examples:

  PYTHONPATH=. python scripts/db/report_artifact_registry_static_dangling.py
  PYTHONPATH=. python scripts/db/report_artifact_registry_static_dangling.py --verbose
  PYTHONPATH=. python scripts/db/report_artifact_registry_static_dangling.py --output-dir /tmp/static-dangling-audit
"""

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
        help="Write outputs to this directory instead of output/audit/artifact_registry_static_dangling/<stamp>/.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the summary JSON to stdout after writing files.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print compact progress to stderr.",
    )
    return parser


def _log(verbose: bool, message: str) -> None:
    if verbose:
        sys.stderr.write(f"{message}\n")


def _default_output_dir() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return _REPO_ROOT / "output" / "audit" / "artifact_registry_static_dangling" / stamp


def _load_db() -> tuple[Any, Any]:
    from scytaledroid.Database.db_core import db_config
    from scytaledroid.Database.db_core import db_queries as core_q

    return db_config, core_q


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        db_config, core_q = _load_db()
        if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
            sys.stderr.write("DB disabled; static dangling audit needs the core database.\n")
            return 2
        from scytaledroid.Database.db_utils.artifact_registry_static_dangling import (
            collect_artifact_registry_static_dangling_report,
            write_artifact_registry_static_dangling_bundle,
        )

        output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
        _log(args.verbose, "collecting static dangling registry audit")
        report = collect_artifact_registry_static_dangling_report(core_q.run_sql, repo_root=_REPO_ROOT)
        files = write_artifact_registry_static_dangling_bundle(report, output_dir)
        summary = dict(report.get("summary") or {})
        summary["output_dir"] = str(output_dir)
        summary["written_files"] = [str(path) for path in files]
        (output_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )

        if args.json:
            sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n")
            return 0

        print("# artifact_registry static dangling audit (read-only)")
        print(f"output_dir: {output_dir}")
        print(f"dangling_static_registry_rows: {summary.get('dangling_static_registry_rows')}")
        print(f"linked_static_registry_rows: {summary.get('linked_static_registry_rows')}")
        print(f"distinct_static_run_count: {summary.get('distinct_static_run_count')}")
        print(f"distinct_recovered_package_count: {summary.get('distinct_recovered_package_count')}")
        print(f"runs_with_recovered_manifest_context: {summary.get('runs_with_recovered_manifest_context')}")
        print(f"complete_core_bundle_run_count: {summary.get('complete_core_bundle_run_count')}")
        print(f"partial_core_bundle_run_count: {summary.get('partial_core_bundle_run_count')}")
        print(f"runs_with_duplicate_artifact_types: {summary.get('runs_with_duplicate_artifact_types')}")
        print(f"primary_reason_counts: {json.dumps(summary.get('primary_reason_counts') or {}, sort_keys=True)}")
        print(f"reason_flag_counts: {json.dumps(summary.get('reason_flag_counts') or {}, sort_keys=True)}")
        print(f"path_family_counts: {json.dumps(summary.get('path_family_counts') or {}, sort_keys=True)}")
        print(f"artifact_type_counts: {json.dumps(summary.get('artifact_type_counts') or {}, sort_keys=True)}")
        print(f"schema_tables_discovered: {', '.join(summary.get('schema_tables_discovered') or [])}")
        return 0
    except Exception as exc:  # noqa: BLE001 - operator-facing audit script
        sys.stderr.write(f"static dangling audit failed: {type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
