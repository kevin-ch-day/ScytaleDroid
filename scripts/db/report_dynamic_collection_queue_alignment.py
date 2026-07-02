#!/usr/bin/env python3
"""Read-only alignment audit: Web queue view vs CLI tracker vs DB session validity.

Compares three read surfaces for the active research cohort:

1. ``v_web_dynamic_app_queue_v1`` (MariaDB read model / ScytaleDroid-Web)
2. Filesystem dataset tracker scoped to the current static identity (CLI queue)
3. Raw ``dynamic_sessions`` / ``v_dynamic_run_context_v1`` validity breakdown

Does not mutate manifests, tracker JSON, or database rows.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@dataclass(frozen=True)
class AlignmentRow:
    package_name: str
    app_label: str
    cohort_key: str
    web_data_scope: str
    web_collection_status: str
    web_baseline_quota: int
    web_interactive_quota: int
    web_legacy_unknown_runs: int
    cli_baseline_quota: int
    cli_interactive_quota: int
    cli_baseline_extra: int
    cli_interactive_extra: int
    cli_technical_valid_active: int
    cli_legacy_valid: int
    db_valid_runs: int
    db_invalid_runs: int
    db_legacy_null_runs: int
    db_quota_valid_runs: int
    db_supplemental_runs: int
    baseline_quota_delta: int
    interactive_quota_delta: int
    alignment_state: str
    notes: str


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit summary JSON to stdout.")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Optional directory for alignment.csv (default: output/audit/dynamic_collection_queue_alignment/<stamp>/).",
    )
    parser.add_argument(
        "--cohort-key",
        default=None,
        help="Optional cohort filter (e.g. research_dataset_beta). Default: active CLI cohort context.",
    )
    parser.add_argument(
        "--only-mismatches",
        action="store_true",
        help="Print/emit rows where Web quota differs from CLI scoped quota.",
    )
    return parser


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _default_output_dir() -> Path:
    return _REPO_ROOT / "output" / "audit" / "dynamic_collection_queue_alignment" / _stamp()


def _write_csv(path: Path, rows: list[AlignmentRow]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(asdict(rows[0]).keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def _alignment_state(
    *,
    web_baseline: int,
    web_interactive: int,
    cli_baseline: int,
    cli_interactive: int,
    web_legacy: int,
    db_legacy_null: int,
    in_tracker: bool,
) -> tuple[str, str]:
    notes: list[str] = []
    if not in_tracker:
        notes.append("missing from dataset tracker apps map")
    if web_legacy > 0 or db_legacy_null > 0:
        notes.append(f"legacy_unrated db={db_legacy_null} web={web_legacy}")
    base_delta = int(web_baseline) - int(cli_baseline)
    inter_delta = int(web_interactive) - int(cli_interactive)
    if base_delta == 0 and inter_delta == 0:
        state = "aligned"
    elif base_delta != 0 and inter_delta != 0:
        state = "baseline+interactive_mismatch"
    elif base_delta != 0:
        state = "baseline_mismatch"
    else:
        state = "interactive_mismatch"
    if state != "aligned" and in_tracker:
        notes.append(f"delta base={base_delta:+d} inter={inter_delta:+d}")
    return state, "; ".join(notes)


def _fetch_web_rows(*, cohort_key: str | None) -> dict[str, dict[str, Any]]:
    from scytaledroid.Database.db_core import run_sql

    sql = """
    SELECT
      package_name,
      app_label,
      cohort_key,
      data_scope,
      collection_status,
      baseline_quota_counted,
      interactive_quota_counted,
      legacy_unknown_runs,
      invalid_run_count,
      dynamic_run_count
    FROM v_web_dynamic_app_queue_v1
    """
    params: tuple[str, ...] = ()
    if cohort_key:
        sql += " WHERE LOWER(cohort_key) = LOWER(%s)"
        params = (cohort_key,)
    sql += " ORDER BY sort_order ASC, app_label ASC"
    rows = run_sql(sql, params or None, fetch="all", dictionary=True) or []
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        pkg = str(row.get("package_name") or "").strip().lower()
        if pkg:
            out[pkg] = dict(row)
    return out


def _fetch_db_validity_rows(packages: tuple[str, ...]) -> dict[str, dict[str, int]]:
    if not packages:
        return {}
    from scytaledroid.Database.db_core import run_sql

    placeholders = ", ".join(["%s"] * len(packages))
    sql = f"""
    SELECT
      LOWER(TRIM(package_name)) AS package_name_lc,
      SUM(CASE WHEN valid_dataset_run = 1 THEN 1 ELSE 0 END) AS db_valid_runs,
      SUM(CASE WHEN valid_dataset_run = 0 THEN 1 ELSE 0 END) AS db_invalid_runs,
      SUM(CASE WHEN valid_dataset_run IS NULL THEN 1 ELSE 0 END) AS db_legacy_null_runs
    FROM dynamic_sessions
    WHERE LOWER(TRIM(package_name)) IN ({placeholders})
    GROUP BY LOWER(TRIM(package_name))
    """
    rows = run_sql(sql, packages, fetch="all", dictionary=True) or []
    out: dict[str, dict[str, int]] = {}
    for row in rows:
        pkg = str(row.get("package_name_lc") or "").strip().lower()
        if pkg:
            out[pkg] = {
                "db_valid_runs": int(row.get("db_valid_runs") or 0),
                "db_invalid_runs": int(row.get("db_invalid_runs") or 0),
                "db_legacy_null_runs": int(row.get("db_legacy_null_runs") or 0),
            }
    return out


def _fetch_db_quota_rows(packages: tuple[str, ...]) -> dict[str, dict[str, int]]:
    if not packages:
        return {}
    from scytaledroid.Database.db_core import run_sql

    placeholders = ", ".join(["%s"] * len(packages))
    sql = f"""
    SELECT
      LOWER(TRIM(package_name)) AS package_name_lc,
      SUM(CASE WHEN quota_state = 'QUOTA_VALID' THEN 1 ELSE 0 END) AS db_quota_valid_runs,
      SUM(CASE WHEN quota_state = 'SUPPLEMENTAL_VALID' THEN 1 ELSE 0 END) AS db_supplemental_runs
    FROM v_dynamic_run_context_v1
    WHERE LOWER(TRIM(package_name)) IN ({placeholders})
    GROUP BY LOWER(TRIM(package_name))
    """
    rows = run_sql(sql, packages, fetch="all", dictionary=True) or []
    out: dict[str, dict[str, int]] = {}
    for row in rows:
        pkg = str(row.get("package_name_lc") or "").strip().lower()
        if pkg:
            out[pkg] = {
                "db_quota_valid_runs": int(row.get("db_quota_valid_runs") or 0),
                "db_supplemental_runs": int(row.get("db_supplemental_runs") or 0),
            }
    return out


def _cli_scoped_counts(packages: tuple[str, ...]) -> dict[str, dict[str, int | str]]:
    from scytaledroid.Config import app_config
    from scytaledroid.DynamicAnalysis.menus.queue_selection import resolve_tracker_run_identity
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig, load_dataset_tracker
    from scytaledroid.DynamicAnalysis.tracker_scope import build_scoped_dataset_counts

    cfg = DatasetTrackerConfig()
    tracker = load_dataset_tracker()
    apps = tracker.get("apps") if isinstance(tracker.get("apps"), dict) else {}
    cache: dict[str, tuple[str | None, str | None]] = {}
    output_dir = str(app_config.OUTPUT_DIR)

    def _resolve(pkg: str, run: dict) -> tuple[str | None, str | None]:
        return resolve_tracker_run_identity(
            pkg,
            run,
            run_identity_cache=cache,
            output_dir=output_dir,
        )

    out: dict[str, dict[str, int | str]] = {}
    for pkg in packages:
        entry = apps.get(pkg) if isinstance(apps, dict) else None
        runs = entry.get("runs") if isinstance(entry, dict) and isinstance(entry.get("runs"), list) else []
        scoped = build_scoped_dataset_counts(
            pkg,
            runs,
            cfg=cfg,
            resolve_tracker_run_identity_fn=lambda package_name, run: _resolve(package_name, run),
        )
        out[pkg] = scoped
    return out


def _resolve_packages(cohort_key: str | None) -> tuple[str, ...]:
    if cohort_key:
        from scytaledroid.Database.db_func.research_cohorts import fetch_active_research_cohort_packages

        return tuple(fetch_active_research_cohort_packages(cohort_key))
    from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_packages

    return tuple(active_research_cohort_packages())


def build_alignment_rows(*, cohort_key: str | None = None) -> list[AlignmentRow]:
    packages = _resolve_packages(cohort_key)
    web_rows = _fetch_web_rows(cohort_key=cohort_key)
    db_validity = _fetch_db_validity_rows(packages)
    db_quota = _fetch_db_quota_rows(packages)
    cli_counts = _cli_scoped_counts(packages)

    rows: list[AlignmentRow] = []
    for pkg in packages:
        web = web_rows.get(pkg, {})
        cli = cli_counts.get(pkg, {})
        validity = db_validity.get(pkg, {})
        quota = db_quota.get(pkg, {})
        in_tracker = bool(cli)
        web_base = int(web.get("baseline_quota_counted") or 0)
        web_inter = int(web.get("interactive_quota_counted") or 0)
        cli_base = int(cli.get("baseline_countable") or 0) if in_tracker else 0
        cli_inter = int(cli.get("interactive_countable") or 0) if in_tracker else 0
        state, notes = _alignment_state(
            web_baseline=web_base,
            web_interactive=web_inter,
            cli_baseline=cli_base,
            cli_interactive=cli_inter,
            web_legacy=int(web.get("legacy_unknown_runs") or 0),
            db_legacy_null=int(validity.get("db_legacy_null_runs") or 0),
            in_tracker=in_tracker,
        )
        rows.append(
            AlignmentRow(
                package_name=pkg,
                app_label=str(web.get("app_label") or pkg),
                cohort_key=str(web.get("cohort_key") or cohort_key or ""),
                web_data_scope=str(web.get("data_scope") or "missing"),
                web_collection_status=str(web.get("collection_status") or "missing"),
                web_baseline_quota=web_base,
                web_interactive_quota=web_inter,
                web_legacy_unknown_runs=int(web.get("legacy_unknown_runs") or 0),
                cli_baseline_quota=cli_base,
                cli_interactive_quota=cli_inter,
                cli_baseline_extra=int(cli.get("baseline_extra") or 0) if in_tracker else 0,
                cli_interactive_extra=int(cli.get("interactive_extra") or 0) if in_tracker else 0,
                cli_technical_valid_active=int(cli.get("technical_valid_active") or 0) if in_tracker else 0,
                cli_legacy_valid=int(cli.get("legacy_valid") or 0) if in_tracker else 0,
                db_valid_runs=int(validity.get("db_valid_runs") or 0),
                db_invalid_runs=int(validity.get("db_invalid_runs") or 0),
                db_legacy_null_runs=int(validity.get("db_legacy_null_runs") or 0),
                db_quota_valid_runs=int(quota.get("db_quota_valid_runs") or 0),
                db_supplemental_runs=int(quota.get("db_supplemental_runs") or 0),
                baseline_quota_delta=web_base - cli_base,
                interactive_quota_delta=web_inter - cli_inter,
                alignment_state=state,
                notes=notes,
            )
        )
    return rows


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from scytaledroid.Database.db_core import db_config
    except ImportError as exc:
        sys.stderr.write(f"Import failed (run from repo root with PYTHONPATH=.): {exc}\n")
        return 1

    if str(db_config.DB_CONFIG.get("engine") or "").lower() == "disabled":
        sys.stderr.write("Database is disabled in db_config.\n")
        return 2

    rows = build_alignment_rows(cohort_key=args.cohort_key)
    if args.only_mismatches:
        rows = [row for row in rows if row.alignment_state != "aligned"]

    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "alignment.csv"
    _write_csv(csv_path, rows)

    summary = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "cohort_key": args.cohort_key,
        "row_count": len(rows),
        "alignment_counts": {},
        "web_only_packages": sorted(
            pkg
            for pkg, row in ((r.package_name, r) for r in rows)
            if row.web_collection_status == "missing"
        ),
        "output_dir": str(output_dir),
        "alignment_csv": str(csv_path),
    }
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.alignment_state] = int(counts.get(row.alignment_state, 0)) + 1
    summary["alignment_counts"] = counts

    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True, default=str), encoding="utf-8")

    if args.json:
        sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n")
        return 0

    print("# dynamic collection queue alignment")
    print(f"rows: {len(rows)}")
    print(f"output: {output_dir}")
    for state, count in sorted(counts.items()):
        print(f"  {state}: {count}")
    print("")
    print("package | web B/I | cli B/I | db legacy-null | state")
    for row in rows:
        print(
            f"{row.app_label:24} "
            f"{row.web_baseline_quota}/{row.web_interactive_quota:>1} "
            f"{row.cli_baseline_quota}/{row.cli_interactive_quota:>1} "
            f"legacy={row.db_legacy_null_runs:>2} "
            f"{row.alignment_state}"
        )
        if row.notes:
            print(f"  note: {row.notes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
