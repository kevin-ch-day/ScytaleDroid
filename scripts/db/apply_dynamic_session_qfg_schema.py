#!/usr/bin/env python3
"""Apply the additive dynamic-session QFG metadata migration.

Run without ``--apply`` to inspect state. ``--apply`` adds only nullable
metadata columns and records the migration; it does not rewrite run rows.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Apply the additive migration.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    from scytaledroid.Database.db_core import db_queries as core_q
    from scytaledroid.Database.db_utils.dynamic_session_qfg_schema import (
        MIGRATION_ID,
        apply_dynamic_session_qfg_schema,
        migration_already_applied,
    )

    if migration_already_applied(core_q.run_sql):
        print(f"already applied: {MIGRATION_ID}")
        return 0
    if not args.apply:
        print(f"pending: {MIGRATION_ID}")
        print("rerun with --apply to add nullable QFG metadata columns")
        return 0
    applied = apply_dynamic_session_qfg_schema(core_q.run_sql)
    print(f"{'applied' if applied else 'already applied'}: {MIGRATION_ID}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
