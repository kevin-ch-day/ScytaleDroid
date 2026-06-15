#!/usr/bin/env python3
"""Read-only session-scoped retirement proposal for remaining static dangling legacy-overlap rows."""

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
        help="Write outputs to this directory instead of output/audit/artifact_registry_static_session_retirement/<stamp>/.",
    )
    parser.add_argument("--json", action="store_true", help="Print summary JSON to stdout after writing files.")
    return parser


def _default_output_dir() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return _REPO_ROOT / "output" / "audit" / "artifact_registry_static_session_retirement" / stamp


def _load_db() -> tuple[Any, Any]:
    from scytaledroid.Database.db_core import db_config
    from scytaledroid.Database.db_core import db_queries as core_q

    return db_config, core_q


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        db_config, core_q = _load_db()
        if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
            sys.stderr.write("DB disabled; static session retirement report needs the core database.\n")
            return 2
        from scytaledroid.Database.db_utils.artifact_registry_static_session_retirement import (
            collect_static_session_retirement_report,
            write_static_session_retirement_bundle,
        )

        output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
        report = collect_static_session_retirement_report(core_q.run_sql, repo_root=_REPO_ROOT)
        files = write_static_session_retirement_bundle(report, output_dir)
        summary = dict(report.get("summary") or {})
        summary["output_dir"] = str(output_dir)
        summary["written_files"] = [str(path) for path in files]

        if args.json:
            sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n")
            return 0

        print("# artifact_registry static session retirement proposal (read-only)")
        print(f"output_dir: {output_dir}")
        print(f"legacy_overlap_session_count: {summary.get('legacy_overlap_session_count')}")
        print(f"candidate_session_count: {summary.get('candidate_session_count')}")
        print(f"blocked_session_count: {summary.get('blocked_session_count')}")
        print(f"recommended_candidate_order: {json.dumps(summary.get('recommended_candidate_order') or [])}")
        return 0
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"static session retirement report failed: {type(exc).__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
