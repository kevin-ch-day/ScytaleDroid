#!/usr/bin/env python3
"""Repair legacy dynamic session validity from DB issue payloads.

This is a bounded DB-only repair for older rows where ``dynamic_sessions`` did
not persist dataset-validity columns, but ``dynamic_session_issues`` already
contains the dataset-validity decision captured at ingest time.

Default mode is dry-run.  ``--apply`` updates only selected
``dynamic_sessions`` rows by primary key; it does not touch evidence packs,
PCAPs, APKs, static rows, or dynamic issue rows.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    _REPO_ROOT = Path(__file__).resolve().parents[2]
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))


OUTPUT_FIELDS = (
    "dynamic_run_id",
    "package_name",
    "version_name",
    "version_code",
    "status",
    "pcap_valid",
    "pcap_bytes",
    "current_valid_dataset_run",
    "current_countable",
    "current_invalid_reason_code",
    "new_valid_dataset_run",
    "new_countable",
    "new_invalid_reason_code",
    "new_sampling_duration_seconds",
    "issue_row_id",
    "issue_created_at",
    "reason",
    "updated",
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", help="Limit repair preview/apply to one Android package.")
    parser.add_argument("--run-id", action="append", default=[], help="Limit repair preview/apply to one or more dynamic run IDs.")
    parser.add_argument("--output-dir", help="Receipt directory. Defaults to output/audit/dynamic_legacy_issue_repair/<timestamp>.")
    parser.add_argument("--apply", action="store_true", help="Apply candidate updates to dynamic_sessions.")
    parser.add_argument("--json", action="store_true", help="Print summary JSON.")
    return parser


def _default_output_dir() -> Path:
    from scytaledroid.Config import app_config

    stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return Path(app_config.OUTPUT_DIR) / "audit" / "dynamic_legacy_issue_repair" / stamp


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fieldnames: Sequence[str] = OUTPUT_FIELDS) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def _fetch_issue_rows(core_q: Any, *, package: str | None, run_ids: Sequence[str]) -> list[dict[str, Any]]:
    where: list[str] = ["ds.valid_dataset_run IS NULL"]
    params: list[Any] = []
    if package:
        where.append("ds.package_name = %s")
        params.append(package)
    normalized_run_ids = [str(value).strip() for value in run_ids if str(value).strip()]
    if normalized_run_ids:
        placeholders = ", ".join(["%s"] * len(normalized_run_ids))
        where.append(f"ds.dynamic_run_id IN ({placeholders})")
        params.extend(normalized_run_ids)
    where_sql = " AND ".join(where)
    return core_q.run_sql(
        f"""
        SELECT
          ds.dynamic_run_id,
          ds.package_name,
          ds.version_name,
          ds.version_code,
          ds.status,
          ds.pcap_valid,
          ds.pcap_bytes,
          ds.valid_dataset_run AS current_valid_dataset_run,
          ds.countable AS current_countable,
          ds.invalid_reason_code AS current_invalid_reason_code,
          ds.sampling_duration_seconds AS current_sampling_duration_seconds,
          dsi.id AS issue_row_id,
          dsi.details_json,
          dsi.created_at AS issue_created_at
        FROM dynamic_sessions ds
        JOIN (
          SELECT dynamic_run_id, MAX(id) AS issue_row_id
          FROM dynamic_session_issues
          WHERE issue_code = 'dataset_validity'
          GROUP BY dynamic_run_id
        ) latest_issue ON latest_issue.dynamic_run_id = ds.dynamic_run_id
        JOIN dynamic_session_issues dsi ON dsi.id = latest_issue.issue_row_id
        WHERE {where_sql}
        ORDER BY ds.package_name, ds.started_at_utc, ds.dynamic_run_id
        """,
        tuple(params),
        fetch="all_dict",
        query_name="repair_dynamic_dataset_validity_from_db_issues.fetch",
    ) or []


def _as_bool_int(value: Any) -> int | None:
    if value is True:
        return 1
    if value is False:
        return 0
    if value in {0, 1}:
        return int(value)
    return None


def _parse_details(row: Mapping[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    raw = row.get("details_json")
    if not isinstance(raw, str) or not raw.strip():
        return None, "missing_details_json"
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None, "invalid_details_json"
    if not isinstance(parsed, dict):
        return None, "details_json_not_object"
    return parsed, None


def _classify_row(row: Mapping[str, Any]) -> dict[str, Any]:
    details, parse_error = _parse_details(row)
    public = {
        "dynamic_run_id": row.get("dynamic_run_id"),
        "package_name": row.get("package_name"),
        "version_name": row.get("version_name"),
        "version_code": row.get("version_code"),
        "status": row.get("status"),
        "pcap_valid": row.get("pcap_valid"),
        "pcap_bytes": row.get("pcap_bytes"),
        "current_valid_dataset_run": row.get("current_valid_dataset_run"),
        "current_countable": row.get("current_countable"),
        "current_invalid_reason_code": row.get("current_invalid_reason_code"),
        "issue_row_id": row.get("issue_row_id"),
        "issue_created_at": row.get("issue_created_at"),
        "updated": 0,
    }
    if parse_error:
        return {**public, "reason": parse_error}

    new_valid = _as_bool_int(details.get("valid_dataset_run"))
    new_countable = _as_bool_int(details.get("countable"))
    public.update(
        {
            "new_valid_dataset_run": new_valid,
            "new_countable": new_countable,
            "new_invalid_reason_code": details.get("invalid_reason_code"),
            "new_sampling_duration_seconds": details.get("sampling_duration_seconds"),
        }
    )
    if new_valid != 1:
        return {**public, "reason": "issue_payload_not_valid_dataset_run"}
    if str(row.get("status") or "").strip().lower() != "success":
        return {**public, "reason": "status_not_success"}
    if _as_bool_int(row.get("pcap_valid")) != 1:
        return {**public, "reason": "pcap_not_valid"}
    return {**public, "reason": "candidate"}


def _split_rows(rows: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    candidates: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for row in rows:
        classified = _classify_row(row)
        if classified.get("reason") == "candidate":
            candidates.append(classified)
        else:
            blocked.append(classified)
    return candidates, blocked


def _apply_candidates(core_q: Any, candidates: Sequence[Mapping[str, Any]]) -> set[str]:
    updated_run_ids: set[str] = set()
    for row in candidates:
        affected = core_q.run_sql_rowcount(
            """
            UPDATE dynamic_sessions
            SET valid_dataset_run = %s,
                countable = COALESCE(%s, countable),
                invalid_reason_code = %s,
                sampling_duration_seconds = COALESCE(%s, sampling_duration_seconds)
            WHERE dynamic_run_id = %s
              AND valid_dataset_run IS NULL
            """,
            (
                int(row["new_valid_dataset_run"]),
                row.get("new_countable"),
                row.get("new_invalid_reason_code"),
                row.get("new_sampling_duration_seconds"),
                row["dynamic_run_id"],
            ),
            query_name="repair_dynamic_dataset_validity_from_db_issues.apply_one",
        )
        if int(affected or 0) > 0:
            updated_run_ids.add(str(row["dynamic_run_id"]))
    return updated_run_ids


def _fetch_after_rows(core_q: Any, candidates: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    run_ids = [str(row.get("dynamic_run_id") or "").strip() for row in candidates if str(row.get("dynamic_run_id") or "").strip()]
    if not run_ids:
        return []
    placeholders = ", ".join(["%s"] * len(run_ids))
    return core_q.run_sql(
        f"""
        SELECT
          dynamic_run_id,
          package_name,
          version_name,
          version_code,
          status,
          pcap_valid,
          pcap_bytes,
          valid_dataset_run AS current_valid_dataset_run,
          countable AS current_countable,
          invalid_reason_code AS current_invalid_reason_code,
          sampling_duration_seconds AS current_sampling_duration_seconds
        FROM dynamic_sessions
        WHERE dynamic_run_id IN ({placeholders})
        ORDER BY package_name, started_at_utc, dynamic_run_id
        """,
        tuple(run_ids),
        fetch="all_dict",
        query_name="repair_dynamic_dataset_validity_from_db_issues.after",
    ) or []


def _print_text(summary: Mapping[str, Any]) -> None:
    mode = "APPLY" if summary.get("apply") else "DRY-RUN"
    print(f"=== Dynamic dataset-validity DB issue repair ({mode}) ===")
    if summary.get("package"):
        print(f"Package: {summary['package']}")
    if summary.get("run_ids"):
        print(f"Run IDs: {', '.join(summary['run_ids'])}")
    print(f"Issue rows reviewed: {summary['issue_rows_reviewed']}")
    print(f"Candidates: {summary['candidate_rows']}")
    print(f"Blocked: {summary['blocked_rows']}")
    print(f"Rows updated: {summary['updated_rows']}")
    if not summary.get("apply"):
        print("No DB writes were made. Re-run with --apply after reviewing the receipt.")
    print(f"Receipt: {summary['output_dir']}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    run_ids = [str(value).strip() for value in (args.run_id or []) if str(value).strip()]
    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        from scytaledroid.Database.db_core import db_config
        from scytaledroid.Database.db_core import db_queries as core_q
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 2

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    issue_rows = _fetch_issue_rows(core_q, package=args.package, run_ids=run_ids)
    candidates, blocked = _split_rows(issue_rows)
    before_path = output_dir / "candidates.csv"
    blocked_path = output_dir / "blocked.csv"
    _write_csv(before_path, candidates)
    _write_csv(blocked_path, blocked)
    _write_json(output_dir / "candidates.json", {"rows": candidates})
    _write_json(output_dir / "blocked.json", {"rows": blocked})

    updated_rows = 0
    after_rows: list[dict[str, Any]] = []
    if args.apply and candidates:
        updated_run_ids = _apply_candidates(core_q, candidates)
        updated_rows = len(updated_run_ids)
        for row in candidates:
            row["updated"] = 1 if str(row.get("dynamic_run_id") or "") in updated_run_ids else 0
        _write_csv(before_path, candidates)
        _write_json(output_dir / "candidates.json", {"rows": candidates})
        after_rows = _fetch_after_rows(core_q, candidates)
        _write_csv(output_dir / "after.csv", after_rows, fieldnames=(
            "dynamic_run_id",
            "package_name",
            "version_name",
            "version_code",
            "status",
            "pcap_valid",
            "pcap_bytes",
            "current_valid_dataset_run",
            "current_countable",
            "current_invalid_reason_code",
            "current_sampling_duration_seconds",
        ))

    summary = {
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "apply": bool(args.apply),
        "package": args.package,
        "run_ids": run_ids,
        "issue_rows_reviewed": len(issue_rows),
        "candidate_rows": len(candidates),
        "blocked_rows": len(blocked),
        "updated_rows": int(updated_rows),
        "output_dir": str(output_dir.resolve()),
        "source": "dynamic_session_issues.latest_dataset_validity_payload",
        "selection_policy": (
            "Only dynamic_sessions rows with valid_dataset_run IS NULL, status=success, "
            "pcap_valid=1, and latest dataset_validity issue payload valid_dataset_run=true "
            "are candidates."
        ),
        "no_file_mutations": True,
        "no_apk_or_pcap_mutations": True,
        "output_files": {
            "summary_json": str((output_dir / "summary.json").resolve()),
            "candidates_csv": str(before_path.resolve()),
            "blocked_csv": str(blocked_path.resolve()),
            "after_csv": str((output_dir / "after.csv").resolve()) if args.apply else None,
        },
    }
    _write_json(output_dir / "summary.json", summary)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True, default=str))
    else:
        _print_text(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
