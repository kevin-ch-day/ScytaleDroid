#!/usr/bin/env python3
"""Advanced read-only SQL audit bundle for dynamic DB truth.

Runs parameterized SQL probes against MariaDB and writes CSV/JSON artifacts.
Side-effect free ``--help``; DB work only executes in ``main()``.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

COHORT_PACKAGES_SUBQUERY = """
SELECT LOWER(TRIM(rcm.package_name)) AS package_name
FROM research_cohort_members rcm
JOIN research_cohorts rc ON rc.cohort_id = rcm.cohort_id
WHERE rc.is_active = 1 AND rcm.is_active = 1
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print summary JSON to stdout.")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory (default: output/audit/dynamic_sql_audit/<stamp>/).",
    )
    parser.add_argument(
        "--cohort-key",
        default=None,
        help="Optional cohort filter appended to member subquery.",
    )
    return parser


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _default_output_dir() -> Path:
    return _REPO_ROOT / "output" / "audit" / "dynamic_sql_audit" / _stamp()


def _cohort_subquery(cohort_key: str | None) -> str:
    if not cohort_key:
        return COHORT_PACKAGES_SUBQUERY
    return f"""
SELECT LOWER(TRIM(rcm.package_name)) AS package_name
FROM research_cohort_members rcm
JOIN research_cohorts rc ON rc.cohort_id = rcm.cohort_id
WHERE rc.is_active = 1
  AND rcm.is_active = 1
  AND LOWER(rc.cohort_key) = LOWER({json.dumps(cohort_key)})
"""


def _profile_bucket_sql(profile_expr: str = "ctx.effective_run_profile") -> str:
    p = (
        f"LOWER(CONVERT(COALESCE({profile_expr}, '') USING utf8mb4) "
        f"COLLATE utf8mb4_unicode_ci)"
    )
    return f"""
    CASE
      WHEN INSTR({p}, 'baseline') > 0 OR INSTR({p}, 'idle') > 0 THEN 'baseline'
      WHEN INSTR({p}, 'interaction') > 0 OR INSTR({p}, 'interactive') > 0 THEN 'interactive'
      ELSE 'other'
    END
    """


def _current_build_flag_sql() -> str:
    return """
    CASE
      WHEN t.latest_sha <> ''
       AND LOWER(TRIM(CONVERT(COALESCE(ctx.base_apk_sha256, '') USING utf8mb4) COLLATE utf8mb4_unicode_ci)) = t.latest_sha
        THEN 1
      ELSE 0
    END
    """


def sql_probes(*, cohort_key: str | None) -> list[tuple[str, str]]:
    cohort = _cohort_subquery(cohort_key)
    bucket = _profile_bucket_sql("ctx.effective_run_profile")
    build_flag = _current_build_flag_sql()

    return [
        (
            "validity_matrix",
            f"""
            SELECT
              LOWER(TRIM(ds.package_name)) AS package_name,
              COUNT(*) AS sessions,
              SUM(ds.valid_dataset_run = 1) AS valid_1,
              SUM(ds.valid_dataset_run = 0) AS valid_0,
              SUM(ds.valid_dataset_run IS NULL) AS valid_null,
              SUM(ds.countable = 1) AS countable_1,
              SUM(ds.countable = 0) AS countable_0,
              SUM(ds.countable IS NULL) AS countable_null,
              SUM(nf.dynamic_run_id IS NOT NULL) AS with_features,
              MIN(ds.started_at_utc) AS first_run,
              MAX(ds.started_at_utc) AS last_run
            FROM dynamic_sessions ds
            LEFT JOIN dynamic_network_features nf ON nf.dynamic_run_id = ds.dynamic_run_id
            WHERE LOWER(TRIM(ds.package_name)) IN ({cohort})
            GROUP BY LOWER(TRIM(ds.package_name))
            ORDER BY sessions DESC
            """,
        ),
        (
            "quota_by_profile_bucket",
            f"""
            SELECT
              {bucket} AS profile_bucket,
              ctx.quota_state,
              COUNT(*) AS run_count
            FROM v_dynamic_run_context_v1 ctx
            WHERE LOWER(TRIM(ctx.package_name)) IN ({cohort})
            GROUP BY profile_bucket, ctx.quota_state
            ORDER BY profile_bucket, run_count DESC
            """,
        ),
        (
            "current_vs_all_build_quota",
            f"""
            WITH targets AS (
              SELECT
                LOWER(TRIM(sds.package_name)) AS package_name,
                LOWER(TRIM(COALESCE(sds.latest_apk_sha256, ''))) AS latest_sha
              FROM v_web_static_dynamic_app_summary sds
              WHERE LOWER(TRIM(sds.package_name)) IN ({cohort})
            ),
            runs AS (
              SELECT
                LOWER(TRIM(ctx.package_name)) AS package_name,
                {bucket} AS profile_bucket,
                ctx.quota_state,
                {build_flag} AS current_build
              FROM v_dynamic_run_context_v1 ctx
              JOIN targets t ON t.package_name = LOWER(TRIM(ctx.package_name))
              WHERE ctx.valid_dataset_run = 1
            )
            SELECT
              package_name,
              SUM(profile_bucket = 'baseline' AND quota_state = 'QUOTA_VALID' AND current_build = 1) AS cur_b_quota,
              SUM(profile_bucket = 'baseline' AND quota_state = 'QUOTA_VALID' AND current_build = 0) AS old_b_quota,
              SUM(profile_bucket = 'interactive' AND quota_state = 'QUOTA_VALID' AND current_build = 1) AS cur_i_quota,
              SUM(profile_bucket = 'interactive' AND quota_state = 'QUOTA_VALID' AND current_build = 0) AS old_i_quota,
              SUM(profile_bucket = 'interactive' AND quota_state = 'SUPPLEMENTAL_VALID' AND current_build = 1) AS cur_i_supplemental,
              SUM(profile_bucket = 'baseline' AND quota_state = 'SUPPLEMENTAL_VALID' AND current_build = 1) AS cur_b_supplemental,
              SUM(profile_bucket = 'interactive' AND quota_state = 'SUPPLEMENTAL_VALID' AND current_build = 0) AS old_i_supplemental
            FROM runs
            GROUP BY package_name
            ORDER BY package_name
            """,
        ),
        (
            "latest_run_per_package",
            f"""
            SELECT package_name, dynamic_run_id, started_at_utc, valid_dataset_run, countable,
                   quota_state, effective_run_profile, technical_validity_state
            FROM (
              SELECT
                LOWER(TRIM(ctx.package_name)) AS package_name,
                ctx.dynamic_run_id,
                ctx.started_at_utc,
                ctx.valid_dataset_run,
                ctx.countable,
                ctx.quota_state,
                ctx.effective_run_profile,
                ctx.technical_validity_state,
                ROW_NUMBER() OVER (
                  PARTITION BY LOWER(TRIM(ctx.package_name))
                  ORDER BY ctx.started_at_utc DESC, ctx.dynamic_run_id DESC
                ) AS rn
              FROM v_dynamic_run_context_v1 ctx
              WHERE LOWER(TRIM(ctx.package_name)) IN ({cohort})
            ) ranked
            WHERE rn = 1
            ORDER BY package_name
            """,
        ),
        (
            "sha_alignment",
            f"""
            SELECT
              CASE
                WHEN COALESCE(TRIM(sds.latest_apk_sha256), '') = '' THEN 'no_static_sha'
                WHEN LOWER(TRIM(CONVERT(COALESCE(ds.base_apk_sha256, '') USING utf8mb4) COLLATE utf8mb4_unicode_ci))
                   = LOWER(TRIM(CONVERT(COALESCE(sds.latest_apk_sha256, '') USING utf8mb4) COLLATE utf8mb4_unicode_ci))
                  THEN 'sha_match'
                ELSE 'sha_mismatch'
              END AS sha_state,
              SUM(ds.valid_dataset_run = 1) AS valid_runs,
              SUM(ds.valid_dataset_run IS NULL) AS legacy_null,
              COUNT(*) AS total_runs
            FROM dynamic_sessions ds
            JOIN v_web_static_dynamic_app_summary sds
              ON LOWER(TRIM(sds.package_name)) = LOWER(TRIM(ds.package_name))
            WHERE LOWER(TRIM(ds.package_name)) IN ({cohort})
            GROUP BY sha_state
            ORDER BY total_runs DESC
            """,
        ),
        (
            "monthly_ingestion",
            f"""
            SELECT
              DATE_FORMAT(started_at_utc, '%Y-%m') AS ingest_month,
              COUNT(*) AS sessions,
              SUM(valid_dataset_run = 1) AS valid_runs,
              SUM(valid_dataset_run IS NULL) AS legacy_null_runs,
              SUM(countable = 1) AS countable_runs
            FROM dynamic_sessions
            WHERE LOWER(TRIM(package_name)) IN ({cohort})
            GROUP BY ingest_month
            ORDER BY ingest_month
            """,
        ),
        (
            "interactive_quota_valid_runs",
            f"""
            SELECT
              ctx.package_name,
              ctx.dynamic_run_id,
              ctx.effective_run_profile,
              ctx.countable,
              ctx.quota_state,
              ctx.started_at_utc,
              ctx.low_signal,
              sds.latest_apk_sha256
            FROM v_dynamic_run_context_v1 ctx
            LEFT JOIN v_web_static_dynamic_app_summary sds
              ON LOWER(TRIM(sds.package_name)) = LOWER(TRIM(ctx.package_name))
            WHERE ctx.quota_state = 'QUOTA_VALID'
              AND ({bucket.replace("ctx.effective_run_profile", "ctx.effective_run_profile")}) = 'interactive'
            ORDER BY ctx.started_at_utc DESC
            """,
        ),
        (
            "queue_view_snapshot",
            """
            SELECT
              q.package_name,
              q.app_label,
              q.cohort_key,
              q.data_scope,
              q.collection_status,
              q.baseline_quota_counted,
              q.interactive_quota_counted,
              q.baseline_extra_valid,
              q.baseline_low_signal_retained,
              q.interactive_extra_valid,
              q.interactive_low_signal_retained,
              q.current_build_baseline_quota_counted,
              q.current_build_interactive_quota_counted,
              q.all_build_baseline_quota_counted,
              q.all_build_interactive_quota_counted,
              q.legacy_unknown_runs,
              q.need_baseline,
              q.need_interactive,
              q.quota_gap_label,
              q.qa_label
            FROM v_web_dynamic_app_queue_v1 q
            ORDER BY q.sort_order, q.app_label
            """,
        ),
        (
            "static_link_x_quota",
            f"""
            SELECT
              ctx.static_link_state,
              ctx.quota_state,
              COUNT(*) AS run_count
            FROM v_dynamic_run_context_v1 ctx
            WHERE LOWER(TRIM(ctx.package_name)) IN ({cohort})
            GROUP BY ctx.static_link_state, ctx.quota_state
            ORDER BY run_count DESC
            """,
        ),
        (
            "feature_coverage_by_quota_state",
            f"""
            SELECT
              CASE WHEN nf.dynamic_run_id IS NULL THEN 'missing_features' ELSE 'has_features' END AS feature_state,
              ctx.quota_state,
              COUNT(*) AS run_count
            FROM v_dynamic_run_context_v1 ctx
            LEFT JOIN dynamic_network_features nf ON nf.dynamic_run_id = ctx.dynamic_run_id
            WHERE LOWER(TRIM(ctx.package_name)) IN ({cohort})
              AND ctx.valid_dataset_run = 1
            GROUP BY feature_state, ctx.quota_state
            ORDER BY run_count DESC
            """,
        ),
        (
            "legacy_corpus_by_tier",
            f"""
            SELECT
              COALESCE(NULLIF(TRIM(tier), ''), '(blank)') AS tier,
              COUNT(*) AS sessions,
              SUM(valid_dataset_run IS NULL) AS legacy_null,
              SUM(valid_dataset_run = 1) AS valid_runs,
              SUM(countable = 1) AS countable_runs
            FROM dynamic_sessions
            WHERE LOWER(TRIM(package_name)) IN ({cohort})
            GROUP BY tier
            ORDER BY sessions DESC
            """,
        ),
        (
            "interactive_countable_zero_current_build",
            f"""
            WITH targets AS (
              SELECT
                LOWER(TRIM(sds.package_name)) AS package_name,
                LOWER(TRIM(COALESCE(sds.latest_apk_sha256, ''))) AS latest_sha
              FROM v_web_static_dynamic_app_summary sds
              WHERE LOWER(TRIM(sds.package_name)) IN ({cohort})
            )
            SELECT
              LOWER(TRIM(ds.package_name)) AS package_name,
              ds.dynamic_run_id,
              ds.started_at_utc,
              ds.countable,
              ds.valid_dataset_run,
              COALESCE(ds.operator_run_profile, ds.profile_key, '') AS profile,
              ds.tier
            FROM dynamic_sessions ds
            JOIN targets t ON t.package_name = LOWER(TRIM(ds.package_name))
            WHERE ds.valid_dataset_run = 1
              AND ds.countable = 0
              AND (
                INSTR(LOWER(CONVERT(COALESCE(ds.operator_run_profile, ds.profile_key, '') USING utf8mb4) COLLATE utf8mb4_unicode_ci), 'interaction') > 0
                OR INSTR(LOWER(CONVERT(COALESCE(ds.operator_run_profile, ds.profile_key, '') USING utf8mb4) COLLATE utf8mb4_unicode_ci), 'interactive') > 0
              )
              AND t.latest_sha <> ''
              AND LOWER(TRIM(CONVERT(COALESCE(ds.base_apk_sha256, '') USING utf8mb4) COLLATE utf8mb4_unicode_ci)) = t.latest_sha
            ORDER BY ds.package_name, ds.started_at_utc DESC
            """,
        ),
    ]


def _rows_to_dicts(rows: list[Any], columns: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict):
            out.append(dict(row))
            continue
        out.append({col: row[idx] for idx, col in enumerate(columns)})
    return out


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run_sql_audit(*, cohort_key: str | None = None) -> dict[str, Any]:
    from scytaledroid.Database.db_core import run_sql

    probes = sql_probes(cohort_key=cohort_key)
    sections: dict[str, Any] = {}
    for name, sql in probes:
        rows = run_sql(sql.strip(), fetch="all", dictionary=True) or []
        sections[name] = rows
    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "cohort_key": cohort_key,
        "probe_count": len(probes),
        "sections": sections,
    }


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

    payload = run_sql_audit(cohort_key=args.cohort_key)
    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    for name, rows in (payload.get("sections") or {}).items():
        if not isinstance(rows, list):
            continue
        path = output_dir / f"{name}.csv"
        _write_csv(path, [dict(r) for r in rows if isinstance(r, dict)])
        written.append(str(path))

    summary = {
        "generated_at_utc": payload["generated_at_utc"],
        "cohort_key": payload.get("cohort_key"),
        "probe_count": payload.get("probe_count"),
        "output_dir": str(output_dir),
        "files": written,
        "highlights": _summarize(payload),
    }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True, default=str), encoding="utf-8")

    if args.json:
        sys.stdout.write(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n")
        return 0

    print("# dynamic SQL audit")
    print(f"output: {output_dir}")
    print(f"probes: {payload.get('probe_count')}")
    for line in summary.get("highlights") or []:
        print(f"- {line}")
    print("")
    for path in written:
        print(path)
    return 0


def _summarize(payload: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    sections = payload.get("sections") or {}
    validity = sections.get("validity_matrix") or []
    if validity:
        total_sessions = sum(int(r.get("sessions") or 0) for r in validity if isinstance(r, dict))
        total_legacy = sum(int(r.get("valid_null") or 0) for r in validity if isinstance(r, dict))
        lines.append(f"cohort packages in validity_matrix: {len(validity)}; sessions={total_sessions}; legacy_null={total_legacy}")

    quota = sections.get("quota_by_profile_bucket") or []
    if quota:
        interactive_valid = sum(
            int(r.get("run_count") or 0)
            for r in quota
            if isinstance(r, dict)
            and r.get("profile_bucket") == "interactive"
            and r.get("quota_state") == "QUOTA_VALID"
        )
        interactive_supp = sum(
            int(r.get("run_count") or 0)
            for r in quota
            if isinstance(r, dict)
            and r.get("profile_bucket") == "interactive"
            and r.get("quota_state") == "SUPPLEMENTAL_VALID"
        )
        lines.append(
            f"interactive valid runs: QUOTA_VALID={interactive_valid}, SUPPLEMENTAL_VALID={interactive_supp}"
        )

    iqv = sections.get("interactive_quota_valid_runs") or []
    lines.append(f"interactive QUOTA_VALID rows listed: {len(iqv)} (expect Messenger-heavy)")

    sha = sections.get("sha_alignment") or []
    for row in sha:
        if isinstance(row, dict):
            lines.append(
                f"sha {row.get('sha_state')}: total={row.get('total_runs')} valid={row.get('valid_runs')} legacy_null={row.get('legacy_null')}"
            )

    drift = sections.get("interactive_countable_zero_current_build") or []
    if drift:
        by_pkg: dict[str, int] = {}
        for row in drift:
            if isinstance(row, dict):
                pkg = str(row.get("package_name") or "")
                by_pkg[pkg] = by_pkg.get(pkg, 0) + 1
        lines.append(
            f"current-build interactive valid with countable=0: {len(drift)} rows across {len(by_pkg)} packages"
        )

    legacy = sections.get("legacy_corpus_by_tier") or []
    if legacy:
        legacy_null = sum(int(r.get("legacy_null") or 0) for r in legacy if isinstance(r, dict))
        lines.append(f"legacy valid_dataset_run IS NULL in cohort: {legacy_null}")

    return lines


if __name__ == "__main__":
    raise SystemExit(main())
