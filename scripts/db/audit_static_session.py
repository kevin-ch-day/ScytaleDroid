#!/usr/bin/env python3
"""Cohort/session audit: canonical row counts + Web views + legacy table counts (read-only).

Validates that a static analysis session wrote expected **canonical** rows and that
read-model views are queryable by ``session_stamp``. Intended for research cohort runs
(e.g. Research Dataset Alpha) before scaling to full-library scans.

Environment: same as CLI static persistence (``SCYTALEDROID_DB_*``). Run from repo root::

  export SCYTALEDROID_DB_USER=… SCYTALEDROID_DB_NAME=… SCYTALEDROID_DB_PASSWD=…
  PYTHONPATH=. python scripts/db/audit_static_session.py --session 20260502-rda-full

Implementation: :func:`scytaledroid.Database.db_utils.static_session_operator_audit.audit_static_session_operator`.

Static persistence writes **canonical** tables only (no legacy mirror). Empty legacy
``runs`` / ``metrics`` / ``buckets`` / ``findings`` counts are **not** treated as failure.

Exit codes:
  0 — audit completed; canonical session has at least one ``static_analysis_runs`` row
  1 — DB error or import failure
  2 — no rows in ``static_analysis_runs`` for the given session stamp
  3 — (only with ``--strict-masvs-views``) canonical MASVS views not deployed on this catalog
"""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit canonical static persistence + views for a session_stamp.",
    )
    parser.add_argument(
        "--session",
        required=True,
        help="session_stamp on static_analysis_runs (e.g. 20260502-rda-canonical-only)",
    )
    parser.add_argument(
        "--no-sql",
        action="store_true",
        help="Do not print the copyable SQL appendix.",
    )
    parser.add_argument(
        "--strict-masvs-views",
        action="store_true",
        help="Exit 3 when v_static_masvs_matrix_v1 / session summary views are missing (1146 etc.).",
    )
    args = parser.parse_args()
    session = str(args.session).strip()
    if not session:
        sys.stderr.write("Empty --session.\n")
        return 1

    try:
        from scytaledroid.Database.db_utils.static_session_operator_audit import (
            audit_static_session_operator,
        )
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    return audit_static_session_operator(
        session,
        print_sql_appendix=not args.no_sql,
        strict_masvs_views=args.strict_masvs_views,
    )


if __name__ == "__main__":
    raise SystemExit(main())
