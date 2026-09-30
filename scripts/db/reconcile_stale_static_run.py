#!/usr/bin/env python3
"""Inspect or close one abandoned STARTED static run with no persisted child evidence.

Dry-run is the default. An apply requires the exact session and start timestamp
shown by dry-run, and refuses any static lock or canonical child rows. It never
rebuilds session links or starts analysis.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Callable
from contextlib import AbstractContextManager, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_CHILD_TABLES = (
    ("artifact_registry", ("static_run_id",)),
    ("masvs_control_coverage", ("run_id",)),
    ("static_analysis_findings", ("run_id",)),
    ("static_correlation_results", ("static_run_id",)),
    ("static_fileproviders", ("run_id",)),
    ("static_findings", ("run_id", "static_run_id")),
    ("static_findings_summary", ("run_id", "static_run_id")),
    ("static_permission_matrix", ("run_id",)),
    ("static_permission_risk_vnext", ("run_id",)),
    ("static_persistence_failures", ("static_run_id",)),
    ("static_session_run_links", ("static_run_id",)),
    ("static_string_samples", ("static_run_id",)),
    ("static_string_sample_sets", ("static_run_id",)),
    ("static_string_selected_samples", ("static_run_id",)),
    ("static_string_summary", ("static_run_id",)),
)


def reconcile_one(
    *,
    run_id: int,
    expect_database: str | None,
    expect_session: str | None,
    expect_started_at: str | None,
    expect_row_sha256: str | None,
    apply: bool,
    run_sql: Callable[..., Any],
    run_sql_rowcount: Callable[..., int],
    refresh_summary: Callable[..., bool],
    transaction: Callable[[], AbstractContextManager[Any]],
    lock_path: Path,
    receipt_root: Path,
) -> dict[str, Any]:
    database = run_sql("SELECT DATABASE()", (), fetch="one")[0]
    row = run_sql(
        """SELECT id, session_stamp, CAST(run_started_at_utc AS CHAR) AS started_at_utc,
                  status, CAST(ended_at_utc AS CHAR) AS ended_at_utc,
                  abort_reason, is_canonical, static_session_id, scope_label
           FROM static_analysis_runs WHERE id=%s""",
        (run_id,),
        fetch="one",
        dictionary=True,
    )
    if not row:
        raise RuntimeError(f"Static run {run_id} does not exist in {database}.")
    full_row = run_sql(
        "SELECT * FROM static_analysis_runs WHERE id=%s", (run_id,), fetch="one", dictionary=True
    )
    if not full_row:
        raise RuntimeError("Run disappeared during inspection; repeat dry-run.")
    row_sha256 = hashlib.sha256(
        json.dumps(full_row, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()

    def child_counts_for_run() -> dict[str, int]:
        return {
            table: int(
                run_sql(
                    f"SELECT COUNT(*) FROM {table} WHERE "
                    + " OR ".join(f"{key}=%s" for key in keys),
                    (run_id,) * len(keys),
                    fetch="one",
                )[0]
            )
            for table, keys in _CHILD_TABLES
        }

    child_counts = child_counts_for_run()
    report: dict[str, Any] = {
        "database": database,
        "run": dict(row),
        "row_sha256": row_sha256,
        "child_counts": child_counts,
        "static_lock_present": lock_path.exists(),
        "eligible_for_exact_close": (
            row["status"] == "STARTED"
            and row["ended_at_utc"] is None
            and row["started_at_utc"] is not None
            and not any(child_counts.values())
            and not lock_path.exists()
        ),
        "applied": False,
    }
    if not apply:
        return report

    if not expect_database or not expect_session or not expect_started_at or not expect_row_sha256:
        raise RuntimeError(
            "--apply requires --expect-database, --expect-session, --expect-started-at, "
            "and --expect-row-sha256 from dry-run."
        )
    if database != expect_database:
        raise RuntimeError("Database changed; repeat dry-run against the intended catalog.")
    if row["session_stamp"] != expect_session or row["started_at_utc"] != expect_started_at:
        raise RuntimeError("Run session or start timestamp changed; repeat dry-run.")
    if row_sha256 != expect_row_sha256:
        raise RuntimeError("Run row changed since dry-run; repeat inspection.")
    if not report["eligible_for_exact_close"]:
        raise RuntimeError(
            "Run is not an empty abandoned STARTED row, or a static lock exists; no update made."
        )

    receipt_root.mkdir(parents=True, exist_ok=True)
    receipt_path = receipt_root / f"{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}-{run_id}.json"
    report["apply_requested_at_utc"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    receipt_path.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    try:
        with transaction():
            locked_row = run_sql(
                """SELECT id, session_stamp, CAST(run_started_at_utc AS CHAR) AS started_at_utc,
                          status, CAST(ended_at_utc AS CHAR) AS ended_at_utc,
                          abort_reason, is_canonical, static_session_id, scope_label
                   FROM static_analysis_runs WHERE id=%s FOR UPDATE""",
                (run_id,),
                fetch="one",
                dictionary=True,
            )
            locked_full_row = run_sql(
                "SELECT * FROM static_analysis_runs WHERE id=%s FOR UPDATE",
                (run_id,),
                fetch="one",
                dictionary=True,
            )
            if (
                locked_row != row
                or locked_full_row != full_row
                or child_counts_for_run() != child_counts
                or lock_path.exists()
            ):
                raise RuntimeError(
                    "Run, child evidence, or scan lock changed since inspection; rolled back."
                )
            affected = run_sql_rowcount(
                """UPDATE static_analysis_runs
                   SET status='FAILED', ended_at_utc=UTC_TIMESTAMP(),
                       abort_reason='stale_finalize', abort_signal=NULL, is_canonical=0
                   WHERE id=%s AND session_stamp=%s AND run_started_at_utc=%s
                     AND status='STARTED' AND ended_at_utc IS NULL""",
                (run_id, expect_session, expect_started_at),
                query_name="static_run.reconcile_exact_stale",
            )
            report["updated_rows"] = affected
            if affected != 1:
                raise RuntimeError("Exact update affected no single row; rolled back.")
            report["summary_refreshed"] = bool(
                refresh_summary(
                    session_stamp=expect_session, scope_label=str(row["scope_label"] or "")
                )
            )
            if not report["summary_refreshed"]:
                raise RuntimeError("Session summary refresh failed; rolled back.")
            report["after"] = run_sql(
                """SELECT id, status, CAST(ended_at_utc AS CHAR) AS ended_at_utc,
                          abort_reason, is_canonical FROM static_analysis_runs WHERE id=%s""",
                (run_id,),
                fetch="one",
                dictionary=True,
            )
            if not (
                report["after"]
                and report["after"]["status"] == "FAILED"
                and report["after"]["abort_reason"] == "stale_finalize"
                and report["after"]["ended_at_utc"]
                and not report["after"]["is_canonical"]
            ):
                raise RuntimeError("Terminal row verification failed; rolled back.")
    except Exception as exc:
        report["error"] = str(exc)
        report["transaction_outcome"] = "FAILED_OR_UNCONFIRMED"
        receipt_path.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
        raise

    report["transaction_outcome"] = "COMMITTED"
    report["applied"] = True
    report["applied_at_utc"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    report["receipt"] = str(receipt_path.resolve())
    receipt_path.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-id", type=int, required=True, help="Exact static_analysis_runs.id to inspect."
    )
    parser.add_argument(
        "--expect-database", help="Exact database name shown by dry-run; required with --apply."
    )
    parser.add_argument("--expect-session", help="Exact session_stamp; required with --apply.")
    parser.add_argument(
        "--expect-started-at", help="Exact UTC start shown by dry-run; required with --apply."
    )
    parser.add_argument(
        "--expect-row-sha256", help="Exact row digest shown by dry-run; required with --apply."
    )
    parser.add_argument(
        "--apply", action="store_true", help="Close only the verified empty STARTED row."
    )
    args = parser.parse_args(argv)
    if args.run_id <= 0:
        parser.error("--run-id must be positive")

    from scytaledroid.Config import app_config
    from scytaledroid.Database.db_core import db_queries
    from scytaledroid.Database.db_core.session import database_session
    from scytaledroid.StaticAnalysis.cli.persistence.static_session_summary import (
        refresh_static_analysis_session_summary,
    )

    @contextmanager
    def transaction() -> Any:
        with database_session() as engine:
            with engine.transaction():
                yield

    try:
        report = reconcile_one(
            run_id=args.run_id,
            expect_database=args.expect_database,
            expect_session=args.expect_session,
            expect_started_at=args.expect_started_at,
            expect_row_sha256=args.expect_row_sha256,
            apply=args.apply,
            run_sql=db_queries.run_sql,
            run_sql_rowcount=db_queries.run_sql_rowcount,
            refresh_summary=refresh_static_analysis_session_summary,
            transaction=transaction,
            lock_path=Path(app_config.DATA_DIR) / "locks" / "static_analysis.lock",
            receipt_root=Path(app_config.OUTPUT_DIR) / "audit" / "static_run_reconciliation",
        )
    except Exception as exc:
        print(f"Static run reconciliation blocked: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
