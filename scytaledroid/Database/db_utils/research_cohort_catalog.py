"""Bounded migration + seed support for canonical DB-backed research cohorts."""

from __future__ import annotations

import csv
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Database.db_func.research_cohorts import (
    ALPHA_COHORT_KEY,
    BETA_COHORT_KEY,
    ResearchCohortMemberSeed,
    fetch_active_research_cohort_members,
    make_member_seeds,
    replace_research_cohort_members,
    upsert_research_cohort,
)
from scytaledroid.Database.db_queries.canonical.schema import (
    CREATE_RESEARCH_COHORT_MEMBERS,
    CREATE_RESEARCH_COHORTS,
)
from scytaledroid.DynamicAnalysis.datasets.research_dataset_alpha import CANONICAL_PACKAGES

from .schema_migration_registry import (
    MigrationSpec,
    append_schema_version,
    latest_schema_version,
    record_schema_migration,
)

RunSql = Callable[..., Any]
_REPO_ROOT = Path(__file__).resolve().parents[3]
RECEIPT_SUBDIR = "research_cohorts"
MIGRATION_ID = "20260615_research_cohort_tables_v1"
SCHEMA_VERSION_AFTER = "0.3.7-research-cohorts"


RESEARCH_COHORT_TABLES_MIGRATION = MigrationSpec(
    migration_id=MIGRATION_ID,
    migration_name="Canonical research cohort tables",
    schema_version_before="0.3.6-schema-version-width-hotfix",
    schema_version_after=SCHEMA_VERSION_AFTER,
    statements=(
        CREATE_RESEARCH_COHORTS.strip(),
        CREATE_RESEARCH_COHORT_MEMBERS.strip(),
    ),
    description="Introduces canonical DB-backed reusable research cohort definitions without changing apps.profile_key.",
    apply_mode="manual_script",
    stage="research",
)


@dataclass(frozen=True)
class CohortSeed:
    cohort_key: str
    display_name: str
    description: str
    members: tuple[ResearchCohortMemberSeed, ...]


def _beta_manual_additions() -> tuple[str, ...]:
    return (
        "bbc.mobile.news.ww",
        "com.cnn.mobile.android.phone",
        "com.guardian",
        "com.espn.score_center",
        "com.android.chrome",
    )


def default_seed_payload() -> tuple[CohortSeed, ...]:
    alpha_members = make_member_seeds(
        (
            (pkg, "legacy_alpha_seed", None, idx, None)
            for idx, pkg in enumerate(CANONICAL_PACKAGES, start=1)
        )
    )
    beta_rows: list[tuple[str, str, str | None, int, str | None]] = []
    for idx, pkg in enumerate(CANONICAL_PACKAGES, start=1):
        beta_rows.append((pkg, "alpha_inherited", ALPHA_COHORT_KEY, idx, None))
    start = len(beta_rows) + 1
    for offset, pkg in enumerate(_beta_manual_additions(), start=start):
        beta_rows.append((pkg, "manual_addition", None, offset, None))
    beta_members = make_member_seeds(beta_rows)
    return (
        CohortSeed(
            cohort_key=ALPHA_COHORT_KEY,
            display_name="Research Dataset Alpha",
            description="Canonical reusable research cohort for the ScytaleDroid dynamic paper lineage.",
            members=tuple(alpha_members),
        ),
        CohortSeed(
            cohort_key=BETA_COHORT_KEY,
            display_name="Research Dataset Beta",
            description="Expanded reusable consumer/news research cohort for static analysis paper runs.",
            members=tuple(beta_members),
        ),
    )


def migration_already_applied(run_sql: RunSql) -> bool:
    row = run_sql(
        """
        SELECT migration_entry_id
        FROM schema_migrations
        WHERE migration_id = %s
          AND status = 'applied'
        ORDER BY migration_entry_id DESC
        LIMIT 1
        """,
        (MIGRATION_ID,),
        fetch="one",
    )
    return bool(row)


def collect_state_fingerprint(run_sql: RunSql) -> dict[str, Any]:
    alpha_rows = run_sql(
        """
        SELECT package_name, profile_key
        FROM apps
        WHERE profile_key = 'RESEARCH_DATASET_ALPHA'
        ORDER BY package_name
        """,
        (),
        fetch="all",
        dictionary=True,
    ) or []
    analysis_cohort_rows = run_sql(
        "SELECT cohort_id, name, selector_type FROM analysis_cohorts ORDER BY cohort_id",
        (),
        fetch="all",
        dictionary=True,
    ) or []
    analysis_cohort_run_counts = run_sql(
        """
        SELECT cohort_id, COUNT(*) AS row_count
        FROM analysis_cohort_runs
        GROUP BY cohort_id
        ORDER BY cohort_id
        """,
        (),
        fetch="all",
        dictionary=True,
    ) or []
    return {
        "apps_profile_alpha_rows": [dict(row) for row in alpha_rows if isinstance(row, Mapping)],
        "analysis_cohorts_rows": [dict(row) for row in analysis_cohort_rows if isinstance(row, Mapping)],
        "analysis_cohort_runs_counts": [dict(row) for row in analysis_cohort_run_counts if isinstance(row, Mapping)],
    }


def apply_research_cohort_tables_migration(
    run_sql: RunSql,
    *,
    run_sql_many: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    if migration_already_applied(run_sql):
        payload = {
            "generated_at": datetime.now(UTC).isoformat(),
            "migration_id": MIGRATION_ID,
            "schema_version_before": latest_schema_version(run_sql),
            "schema_version_after": SCHEMA_VERSION_AFTER,
            "already_applied": True,
            "before": collect_state_fingerprint(run_sql),
            "after": collect_state_fingerprint(run_sql),
            "seeded": {
                "cohorts": [
                    {
                        "cohort_key": ALPHA_COHORT_KEY,
                        "member_count": len(
                            fetch_active_research_cohort_members(ALPHA_COHORT_KEY, run_sql_fn=run_sql)
                        ),
                    },
                    {
                        "cohort_key": BETA_COHORT_KEY,
                        "member_count": len(
                            fetch_active_research_cohort_members(BETA_COHORT_KEY, run_sql_fn=run_sql)
                        ),
                    },
                ]
            },
            "alpha_members": fetch_active_research_cohort_members(ALPHA_COHORT_KEY, run_sql_fn=run_sql),
            "beta_members": fetch_active_research_cohort_members(BETA_COHORT_KEY, run_sql_fn=run_sql),
        }
        return payload

    before_schema_version = latest_schema_version(run_sql)
    before_fingerprint = collect_state_fingerprint(run_sql)

    for stmt in RESEARCH_COHORT_TABLES_MIGRATION.statements:
        run_sql(stmt, (), query_name=f"schema_migrations.apply.{MIGRATION_ID}")

    seeded: dict[str, Any] = {"cohorts": []}
    for seed in default_seed_payload():
        cohort_id = upsert_research_cohort(
            cohort_key=seed.cohort_key,
            display_name=seed.display_name,
            description=seed.description,
            run_sql_fn=run_sql,
        )
        member_count = replace_research_cohort_members(
            cohort_id=cohort_id,
            members=seed.members,
            run_sql_fn=run_sql,
            run_sql_many_fn=run_sql_many,
        )
        seeded["cohorts"].append(
            {
                "cohort_id": cohort_id,
                "cohort_key": seed.cohort_key,
                "display_name": seed.display_name,
                "member_count": member_count,
            }
        )

    after_schema_version = SCHEMA_VERSION_AFTER
    append_schema_version(run_sql, after_schema_version)

    after_fingerprint = collect_state_fingerprint(run_sql)
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "migration_id": MIGRATION_ID,
        "schema_version_before": before_schema_version,
        "schema_version_after": after_schema_version,
        "before": before_fingerprint,
        "after": after_fingerprint,
        "seeded": seeded,
        "alpha_members": fetch_active_research_cohort_members(ALPHA_COHORT_KEY, run_sql_fn=run_sql),
        "beta_members": fetch_active_research_cohort_members(BETA_COHORT_KEY, run_sql_fn=run_sql),
    }
    receipt_dir = _REPO_ROOT / "data" / "state" / "schema_migrations" / RECEIPT_SUBDIR
    receipt_files = write_research_cohort_receipt_bundle(payload, receipt_dir)
    record_schema_migration(
        run_sql,
        spec=RESEARCH_COHORT_TABLES_MIGRATION,
        status="applied",
        schema_version_before=before_schema_version,
        schema_version_after=after_schema_version,
        notes="applied canonical research cohort tables and seeded Alpha/Beta",
        receipt_path=receipt_files["json"],
        payload=payload,
    )
    payload["receipt_files"] = receipt_files
    return payload


def write_research_cohort_receipt_bundle(payload: Mapping[str, Any], output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"research_cohort_tables_{stamp}"
    files: dict[str, str] = {}

    json_path = output_dir / f"{stem}.json"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    files["json"] = str(json_path.resolve())

    csv_path = output_dir / f"{stem}_seeded_members.csv"
    rows: list[dict[str, Any]] = []
    for cohort_key, key_name in ((ALPHA_COHORT_KEY, "alpha_members"), (BETA_COHORT_KEY, "beta_members")):
        for row in payload.get(key_name) or []:
            if not isinstance(row, Mapping):
                continue
            rows.append(
                {
                    "cohort_key": cohort_key,
                    "package_name": row.get("package_name"),
                    "member_source": row.get("member_source"),
                    "source_cohort_key": row.get("source_cohort_key"),
                    "sort_order": row.get("sort_order"),
                }
            )
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["cohort_key", "package_name", "member_source", "source_cohort_key", "sort_order"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    files["members_csv"] = str(csv_path.resolve())

    summary_path = output_dir / f"{stem}_summary.txt"
    seeded = payload.get("seeded") if isinstance(payload, Mapping) else {}
    lines = [
        f"migration_id: {payload.get('migration_id')}",
        f"schema_version_before: {payload.get('schema_version_before')}",
        f"schema_version_after: {payload.get('schema_version_after')}",
    ]
    for cohort in (seeded.get("cohorts") if isinstance(seeded, Mapping) else []) or []:
        if not isinstance(cohort, Mapping):
            continue
        lines.append(
            f"{cohort.get('cohort_key')}: cohort_id={cohort.get('cohort_id')} members={cohort.get('member_count')}"
        )
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    files["summary_txt"] = str(summary_path.resolve())
    return files


__all__ = [
    "MIGRATION_ID",
    "RESEARCH_COHORT_TABLES_MIGRATION",
    "SCHEMA_VERSION_AFTER",
    "apply_research_cohort_tables_migration",
    "collect_state_fingerprint",
    "default_seed_payload",
    "migration_already_applied",
    "write_research_cohort_receipt_bundle",
]
