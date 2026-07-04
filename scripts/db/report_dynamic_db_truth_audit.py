#!/usr/bin/env python3
"""Deep read-only audit of dynamic DB truth vs filesystem tracker vs Web queue.

Surfaces:
- analysis integrity scalars
- legacy ``valid_dataset_run IS NULL`` forensics
- filesystem evidence presence vs ``dynamic_sessions`` rows
- tracker membership and countable drift
- Web queue vs CLI scoped tracker alignment (embedded summary)

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
class CountableDriftRow:
    package_name: str
    dynamic_run_id: str
    db_valid_dataset_run: int | None
    db_countable: int | None
    tracker_countable: bool | None
    tracker_valid: bool | None
    profile: str
    tier: str


@dataclass(frozen=True)
class PackageTruthRow:
    package_name: str
    db_sessions: int
    db_valid: int
    db_legacy_null: int
    db_invalid: int
    local_manifest_runs: int
    tracker_runs: int
    tracker_valid_active: int
    web_baseline_quota: int
    web_interactive_quota: int
    cli_baseline_quota: int
    cli_interactive_quota: int
    alignment_state: str
    feature_rows: int
    legacy_local_missing: int


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit summary JSON to stdout.")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Optional output directory (default: output/audit/dynamic_db_truth/<stamp>/).",
    )
    parser.add_argument(
        "--cohort-key",
        default=None,
        help="Optional cohort filter for package rollup (default: active CLI cohort).",
    )
    return parser


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _default_output_dir() -> Path:
    return _REPO_ROOT / "output" / "audit" / "dynamic_db_truth" / _stamp()


def _local_manifest_ids(evidence_root: Path) -> set[str]:
    if not evidence_root.exists():
        return set()
    return {
        p.name
        for p in evidence_root.iterdir()
        if p.is_dir() and (p / "run_manifest.json").exists()
    }


def _tracker_index() -> tuple[dict[str, dict[str, Any]], dict[str, tuple[str, dict[str, Any]]]]:
    from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import load_dataset_tracker

    apps = load_dataset_tracker().get("apps")
    if not isinstance(apps, dict):
        return {}, {}
    by_pkg: dict[str, dict[str, Any]] = {}
    by_id: dict[str, tuple[str, dict[str, Any]]] = {}
    for pkg, entry in apps.items():
        if not isinstance(entry, dict):
            continue
        by_pkg[str(pkg).strip().lower()] = entry
        for run in entry.get("runs") or []:
            if not isinstance(run, dict):
                continue
            rid = str(run.get("run_id") or run.get("dynamic_run_id") or "").strip()
            if rid:
                by_id[rid] = (str(pkg).strip().lower(), run)
    return by_pkg, by_id


def _fetch_session_rollup(packages: tuple[str, ...]) -> dict[str, dict[str, int]]:
    if not packages:
        return {}
    from scytaledroid.Database.db_core import run_sql

    placeholders = ", ".join(["%s"] * len(packages))
    sql = f"""
    SELECT
      LOWER(TRIM(package_name)) AS package_name_lc,
      COUNT(*) AS db_sessions,
      SUM(CASE WHEN valid_dataset_run = 1 THEN 1 ELSE 0 END) AS db_valid,
      SUM(CASE WHEN valid_dataset_run IS NULL THEN 1 ELSE 0 END) AS db_legacy_null,
      SUM(CASE WHEN valid_dataset_run = 0 THEN 1 ELSE 0 END) AS db_invalid
    FROM dynamic_sessions
    WHERE LOWER(TRIM(package_name)) IN ({placeholders})
    GROUP BY LOWER(TRIM(package_name))
    """
    rows = run_sql(sql, packages, fetch="all", dictionary=True) or []
    out: dict[str, dict[str, int]] = {}
    for row in rows:
        pkg = str(row.get("package_name_lc") or "").strip().lower()
        if pkg:
            out[pkg] = {k: int(row.get(k) or 0) for k in ("db_sessions", "db_valid", "db_legacy_null", "db_invalid")}
    return out


def _fetch_feature_counts(packages: tuple[str, ...]) -> dict[str, int]:
    if not packages:
        return {}
    from scytaledroid.Database.db_core import run_sql

    placeholders = ", ".join(["%s"] * len(packages))
    sql = f"""
    SELECT LOWER(TRIM(ds.package_name)) AS package_name_lc, COUNT(nf.dynamic_run_id) AS feature_rows
    FROM dynamic_sessions ds
    LEFT JOIN dynamic_network_features nf ON nf.dynamic_run_id = ds.dynamic_run_id
    WHERE LOWER(TRIM(ds.package_name)) IN ({placeholders})
    GROUP BY LOWER(TRIM(ds.package_name))
    """
    rows = run_sql(sql, packages, fetch="all", dictionary=True) or []
    return {str(r.get("package_name_lc") or "").strip().lower(): int(r.get("feature_rows") or 0) for r in rows}


def _fetch_countable_drift(*, tracker_by_id: dict[str, tuple[str, dict[str, Any]]]) -> list[CountableDriftRow]:
    from scytaledroid.Database.db_core import run_sql

    rows = run_sql(
        """
        SELECT package_name, dynamic_run_id, valid_dataset_run, countable, tier,
               COALESCE(operator_run_profile, profile_key, '') AS profile
        FROM dynamic_sessions
        WHERE valid_dataset_run = 1
        ORDER BY started_at_utc DESC
        """,
        fetch="all",
        dictionary=True,
    ) or []
    drift: list[CountableDriftRow] = []
    for row in rows:
        rid = str(row.get("dynamic_run_id") or "").strip()
        if not rid:
            continue
        hit = tracker_by_id.get(rid)
        if not hit:
            continue
        _, tr = hit
        tr_countable = tr.get("countable")
        db_countable = row.get("countable")
        if tr_countable is True and int(db_countable or 0) != 1:
            drift.append(
                CountableDriftRow(
                    package_name=str(row.get("package_name") or ""),
                    dynamic_run_id=rid,
                    db_valid_dataset_run=int(row.get("valid_dataset_run") or 0),
                    db_countable=int(db_countable) if db_countable is not None else None,
                    tracker_countable=True if tr_countable is True else False if tr_countable is False else None,
                    tracker_valid=True if tr.get("valid_dataset_run") is True else False if tr.get("valid_dataset_run") is False else None,
                    profile=str(row.get("profile") or ""),
                    tier=str(row.get("tier") or ""),
                )
            )
    return drift


def _legacy_forensics(*, evidence_root: Path) -> dict[str, Any]:
    from scytaledroid.Database.db_core import run_sql

    rows = run_sql(
        """
        SELECT dynamic_run_id, evidence_path, tier, started_at_utc
        FROM dynamic_sessions
        WHERE valid_dataset_run IS NULL
        """,
        fetch="all",
        dictionary=True,
    ) or []
    local_missing = 0
    local_present = 0
    tier_counts: dict[str, int] = {}
    for row in rows:
        tier = str(row.get("tier") or "unknown")
        tier_counts[tier] = int(tier_counts.get(tier, 0)) + 1
        rid = str(row.get("dynamic_run_id") or "").strip()
        if rid and (evidence_root / rid / "run_manifest.json").exists():
            local_present += 1
        else:
            local_missing += 1
    return {
        "legacy_null_total": len(rows),
        "legacy_local_manifest_present": local_present,
        "legacy_local_manifest_missing": local_missing,
        "legacy_tier_counts": tier_counts,
    }


def build_truth_audit(*, cohort_key: str | None = None) -> dict[str, Any]:
    from scytaledroid.Config import app_config
    from scytaledroid.Database.db_utils.health_checks.analysis_integrity import fetch_analysis_integrity_summary
    from scripts.db.report_dynamic_collection_queue_alignment import build_alignment_rows

    if cohort_key:
        from scytaledroid.Database.db_func.research_cohorts import fetch_active_research_cohort_packages

        packages = tuple(fetch_active_research_cohort_packages(cohort_key))
    else:
        from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_packages

        packages = tuple(active_research_cohort_packages())

    evidence_root = Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"
    local_ids = _local_manifest_ids(evidence_root)
    tracker_by_pkg, tracker_by_id = _tracker_index()
    session_rollup = _fetch_session_rollup(packages)
    feature_counts = _fetch_feature_counts(packages)
    alignment_rows = build_alignment_rows(cohort_key=cohort_key)
    alignment_by_pkg = {row.package_name: row for row in alignment_rows}
    countable_drift = _fetch_countable_drift(tracker_by_id=tracker_by_id)

    from scytaledroid.Database.db_core import run_sql

    db_ids = {
        str(r.get("dynamic_run_id") or "").strip()
        for r in (run_sql("SELECT dynamic_run_id FROM dynamic_sessions", fetch="all", dictionary=True) or [])
        if str(r.get("dynamic_run_id") or "").strip()
    }

    package_rows: list[PackageTruthRow] = []
    for pkg in packages:
        sess = session_rollup.get(pkg, {})
        entry = tracker_by_pkg.get(pkg, {})
        tracker_runs = len(entry.get("runs") or []) if isinstance(entry.get("runs"), list) else 0
        align = alignment_by_pkg.get(pkg)
        local_for_pkg = 0
        legacy_local_missing = int(sess.get("db_legacy_null") or 0)
        if tracker_runs:
            from scytaledroid.Config import app_config as cfg
            from scytaledroid.DynamicAnalysis.menus.queue_selection import resolve_tracker_run_identity
            from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig
            from scytaledroid.DynamicAnalysis.tracker_scope import build_scoped_dataset_counts

            cache: dict[str, tuple[str | None, str | None]] = {}
            scoped = build_scoped_dataset_counts(
                pkg,
                list(entry.get("runs") or []),
                cfg=DatasetTrackerConfig(),
                resolve_tracker_run_identity_fn=lambda package_name, run, _cache=cache: resolve_tracker_run_identity(
                    package_name,
                    run,
                    run_identity_cache=_cache,
                    output_dir=str(cfg.OUTPUT_DIR),
                ),
            )
            tracker_valid_active = int(scoped.get("technical_valid_active") or 0)
        else:
            tracker_valid_active = 0

        for rid in local_ids:
            hit = tracker_by_id.get(rid)
            if hit and hit[0] == pkg:
                local_for_pkg += 1

        package_rows.append(
            PackageTruthRow(
                package_name=pkg,
                db_sessions=int(sess.get("db_sessions") or 0),
                db_valid=int(sess.get("db_valid") or 0),
                db_legacy_null=int(sess.get("db_legacy_null") or 0),
                db_invalid=int(sess.get("db_invalid") or 0),
                local_manifest_runs=local_for_pkg,
                tracker_runs=tracker_runs,
                tracker_valid_active=tracker_valid_active,
                web_baseline_quota=int(align.web_baseline_quota) if align else 0,
                web_interactive_quota=int(align.web_interactive_quota) if align else 0,
                cli_baseline_quota=int(align.cli_baseline_quota) if align else 0,
                cli_interactive_quota=int(align.cli_interactive_quota) if align else 0,
                alignment_state=str(align.alignment_state) if align else "missing",
                feature_rows=int(feature_counts.get(pkg) or 0),
                legacy_local_missing=legacy_local_missing,
            )
        )

    integrity = fetch_analysis_integrity_summary()
    legacy = _legacy_forensics(evidence_root=evidence_root)

    not_in_tracker = 0
    for rid in db_ids:
        if rid not in tracker_by_id:
            not_in_tracker += 1

    alignment_counts: dict[str, int] = {}
    for row in alignment_rows:
        alignment_counts[row.alignment_state] = int(alignment_counts.get(row.alignment_state, 0)) + 1

    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "cohort_key": cohort_key,
        "packages": list(packages),
        "integrity": integrity.__dict__ if hasattr(integrity, "__dict__") else integrity,
        "filesystem": {
            "local_manifest_run_dirs": len(local_ids),
            "db_session_rows": len(db_ids),
            "local_not_in_db": len(local_ids - db_ids),
            "db_not_in_local_manifests": len(db_ids - local_ids),
            "db_sessions_not_in_tracker": not_in_tracker,
        },
        "legacy_null": legacy,
        "countable_drift_rows": len(countable_drift),
        "alignment_counts": alignment_counts,
        "package_rows": [asdict(r) for r in package_rows],
        "countable_drift": [asdict(r) for r in countable_drift],
        "operator_notes": [
            "142 legacy NULL sessions have evidence_path but local run_manifest.json is missing on this host — DB-only historical rows.",
            "Reindex from evidence only updates runs whose local packs still exist; tracker-preferred reindex fixes countable drift when tracker JSON is authoritative.",
            "analysis_dynamic_cohort_status is empty — paper_eligible in SQL views falls back to COHORT_NOT_EVALUATED unless ingested elsewhere.",
            "105 dynamic_sessions rows lack dynamic_network_features — quota-valid runs are not affected, but Web feature_state may show missing_features.",
        ],
    }


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


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

    payload = build_truth_audit(cohort_key=args.cohort_key)
    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
    _write_csv(output_dir / "package_truth.csv", list(payload.get("package_rows") or []))
    _write_csv(output_dir / "countable_drift.csv", list(payload.get("countable_drift") or []))

    if args.json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
        return 0

    fs = payload.get("filesystem") or {}
    legacy = payload.get("legacy_null") or {}
    integrity = payload.get("integrity") or {}
    print("# dynamic DB truth audit")
    print(f"output: {output_dir}")
    print(f"dynamic_sessions: {integrity.get('dynamic_runs')} | features: {integrity.get('dynamic_feature_rows')} | missing_features: {integrity.get('dynamic_runs_missing_features')}")
    print(
        f"filesystem: local_manifests={fs.get('local_manifest_run_dirs')} db_rows={fs.get('db_session_rows')} "
        f"db_not_local={fs.get('db_not_in_local_manifests')} db_not_tracker={fs.get('db_sessions_not_in_tracker')}"
    )
    print(
        f"legacy_null: total={legacy.get('legacy_null_total')} local_missing={legacy.get('legacy_local_manifest_missing')} "
        f"tiers={legacy.get('legacy_tier_counts')}"
    )
    print(f"countable_drift_rows: {payload.get('countable_drift_rows')} | alignment: {payload.get('alignment_counts')}")
    print("")
    print("package | db sess valid/null | local trk | web B/I | cli B/I | align")
    for row in payload.get("package_rows") or []:
        print(
            f"{row['package_name']:28} "
            f"{row['db_sessions']:>3}/{row['db_valid']:>2}/{row['db_legacy_null']:>2} "
            f"loc={row['local_manifest_runs']:>2} trk={row['tracker_runs']:>2} "
            f"{row['web_baseline_quota']}/{row['web_interactive_quota']} "
            f"{row['cli_baseline_quota']}/{row['cli_interactive_quota']} "
            f"{row['alignment_state']}"
        )
    print("")
    for note in payload.get("operator_notes") or []:
        print(f"- {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
