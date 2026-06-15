"""Schema migration registry helpers for staged DB evolution."""

from __future__ import annotations

import csv
import getpass
import hashlib
import json
import re
import socket
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scytaledroid.Utils.version_utils import get_git_commit

RunSql = Callable[..., Any]


@dataclass(frozen=True)
class MigrationSpec:
    migration_id: str
    migration_name: str
    schema_version_before: str | None
    schema_version_after: str | None
    statements: tuple[str, ...] = ()
    description: str | None = None
    apply_mode: str = "manual"
    stage: str = "phase_a"

    @property
    def checksum(self) -> str:
        payload = {
            "migration_id": self.migration_id,
            "migration_name": self.migration_name,
            "schema_version_before": self.schema_version_before,
            "schema_version_after": self.schema_version_after,
            "statements": list(self.statements),
            "description": self.description,
            "apply_mode": self.apply_mode,
            "stage": self.stage,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


PHASE_A_MIGRATIONS: tuple[MigrationSpec, ...] = (
    MigrationSpec(
        migration_id="20260614_phase_a_migration_governance_v1",
        migration_name="Phase A migration governance registry baseline",
        schema_version_before="0.3.0-bootstrap",
        schema_version_after="0.3.1-schema-governance",
        statements=(),
        description="Introduces schema_migrations governance and reporting surfaces.",
        apply_mode="bootstrap_baseline",
    ),
    MigrationSpec(
        migration_id="20260614_phase_a_typed_replacement_columns_v1",
        migration_name="Phase A typed replacement columns",
        schema_version_before="0.3.1-schema-governance",
        schema_version_after="0.3.2-typed-columns",
        statements=(
            "ALTER TABLE artifact_registry ADD COLUMN IF NOT EXISTS dynamic_run_uuid CHAR(36) DEFAULT NULL",
            "CREATE INDEX IF NOT EXISTS ix_artifact_dynamic_run_uuid ON artifact_registry (dynamic_run_uuid)",
            "ALTER TABLE dynamic_sessions ADD COLUMN IF NOT EXISTS static_run_id_u BIGINT UNSIGNED DEFAULT NULL",
            "CREATE INDEX IF NOT EXISTS ix_dynamic_sessions_static_run_id_u ON dynamic_sessions (static_run_id_u)",
            "ALTER TABLE static_analysis_runs ADD COLUMN IF NOT EXISTS run_started_at_utc DATETIME DEFAULT NULL",
            "CREATE INDEX IF NOT EXISTS ix_static_runs_started_at_utc ON static_analysis_runs (run_started_at_utc)",
        ),
        description="Additive typed replacement columns for UUID, FK, and temporal normalization.",
        apply_mode="manual_script",
    ),
    MigrationSpec(
        migration_id="20260614_phase_a_typed_replacement_backfill_v1",
        migration_name="Phase A typed replacement backfill",
        schema_version_before="0.3.2-typed-columns",
        schema_version_after="0.3.3-typed-backfill",
        statements=(),
        description="Conservative backfill of typed replacement columns after clean preflight.",
        apply_mode="manual_script",
    ),
)

PHASE_B_MIGRATIONS: tuple[MigrationSpec, ...] = (
    MigrationSpec(
        migration_id="20260614_phase_b1_join_key_collation_width_normalization",
        migration_name="Phase B1 join-key collation and width normalization",
        schema_version_before="0.3.3-typed-backfill",
        schema_version_after="0.3.4-b1-join-key-normalization",
        statements=(),
        description="Normalize the first-wave canonical join-key columns to the repo-specific B1 contract.",
        apply_mode="manual_script",
        stage="phase_b1",
    ),
    MigrationSpec(
        migration_id="20260614_phase_b1_session_stamp_backlog_normalization",
        migration_name="Phase B1 session-stamp backlog normalization",
        schema_version_before="0.3.4-b1-join-key-normalization",
        schema_version_after="0.3.5-b1-session-stamp-backlog-normalization",
        statements=(),
        description="Normalize the remaining legacy and derived session_stamp columns to the repo-specific B1 contract.",
        apply_mode="manual_script",
        stage="phase_b1",
    ),
    MigrationSpec(
        migration_id="20260614_schema_version_width_hotfix_v1",
        migration_name="Schema-version width hotfix for runtime base tables",
        schema_version_before="0.3.5-b1-session-stamp-backlog-normalization",
        schema_version_after="0.3.6-schema-version-width-hotfix",
        statements=(),
        description="Widen runtime schema_version columns from VARCHAR(32) to VARCHAR(64) without changing view contracts.",
        apply_mode="manual_script",
        stage="hotfix",
    ),
)

RESEARCH_COHORT_MIGRATIONS: tuple[MigrationSpec, ...] = (
    MigrationSpec(
        migration_id="20260615_research_cohort_tables_v1",
        migration_name="Canonical research cohort tables",
        schema_version_before="0.3.6-schema-version-width-hotfix",
        schema_version_after="0.3.7-research-cohorts",
        statements=(),
        description="Introduces canonical DB-backed reusable research cohort definitions without changing apps.profile_key.",
        apply_mode="manual_script",
        stage="research",
    ),
)

DYNAMIC_DOMAIN_CONTEXT_MIGRATIONS: tuple[MigrationSpec, ...] = (
    MigrationSpec(
        migration_id="20260615_dynamic_domain_context_tables_v1",
        migration_name="Dynamic domain context reference and observation tables",
        schema_version_before="0.3.7-research-cohorts",
        schema_version_after="0.3.8-dynamic-domain-context",
        statements=(),
        description="Adds DB-backed background domain reference intel and rebuildable per-run dynamic domain context observations.",
        apply_mode="manual_script",
        stage="dynamic_context",
    ),
    MigrationSpec(
        migration_id="20260615_dynamic_domain_context_collation_hotfix_v1",
        migration_name="Dynamic domain context dynamic_run_id collation hotfix",
        schema_version_before="0.3.8-dynamic-domain-context",
        schema_version_after="0.3.9-dynamic-domain-context-collation-hotfix",
        statements=(),
        description="Align dynamic_domain_observations.dynamic_run_id collation with dynamic_sessions.dynamic_run_id for natural joins.",
        apply_mode="manual_script",
        stage="dynamic_context",
    ),
)

DYNAMIC_SERVICE_CONTEXT_MIGRATIONS: tuple[MigrationSpec, ...] = (
    MigrationSpec(
        migration_id="20260615_dynamic_service_context_tables_v1",
        migration_name="Dynamic service context catalog and domain map tables",
        schema_version_before="0.3.9-dynamic-domain-context-collation-hotfix",
        schema_version_after="0.3.10-dynamic-service-context",
        statements=(),
        description="Adds DB-backed provider/service catalog context and domain-to-service mappings for dynamic traffic interpretation.",
        apply_mode="manual_script",
        stage="dynamic_context",
    ),
)

DYNAMIC_SERVICE_SIGNAL_MIGRATIONS: tuple[MigrationSpec, ...] = (
    MigrationSpec(
        migration_id="20260615_dynamic_service_signal_tables_v1",
        migration_name="Dynamic service signal taxonomy and service-signal map tables",
        schema_version_before="0.3.10-dynamic-service-context",
        schema_version_after="0.3.11-dynamic-service-signals",
        statements=(),
        description="Adds DB-backed privacy/security/context signal taxonomy on top of dynamic service context.",
        apply_mode="manual_script",
        stage="dynamic_context",
    ),
)


def registered_migrations() -> tuple[MigrationSpec, ...]:
    return (
        PHASE_A_MIGRATIONS
        + PHASE_B_MIGRATIONS
        + RESEARCH_COHORT_MIGRATIONS
        + DYNAMIC_DOMAIN_CONTEXT_MIGRATIONS
        + DYNAMIC_SERVICE_CONTEXT_MIGRATIONS
        + DYNAMIC_SERVICE_SIGNAL_MIGRATIONS
    )


def latest_registered_schema_version() -> str | None:
    migrations = registered_migrations()
    if not migrations:
        return None
    value = str(migrations[-1].schema_version_after or "").strip()
    return value or None


def schema_version_gte(current: str | None, minimum: str | None) -> bool:
    """Return True when `current` parses as greater than or equal to `minimum`."""

    def _parse(value: str | None) -> tuple[int, ...]:
        if not value:
            return ()
        parts = re.findall(r"\d+", str(value))
        return tuple(int(part) for part in parts) if parts else ()

    current_tuple = _parse(current)
    minimum_tuple = _parse(minimum)
    if not current_tuple or not minimum_tuple:
        return False
    max_len = max(len(current_tuple), len(minimum_tuple))
    current_tuple += (0,) * (max_len - len(current_tuple))
    minimum_tuple += (0,) * (max_len - len(minimum_tuple))
    return current_tuple >= minimum_tuple


def duplicate_registry_ids() -> dict[str, int]:
    counter = Counter(spec.migration_id for spec in registered_migrations())
    return {key: int(value) for key, value in counter.items() if value > 1}


def registry_version_chain_issues() -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    previous_after: str | None = None
    for index, spec in enumerate(registered_migrations(), start=1):
        expected_before = previous_after
        actual_before = str(spec.schema_version_before or "").strip() or None
        if expected_before is not None and actual_before != expected_before:
            issues.append(
                {
                    "migration_id": spec.migration_id,
                    "position": str(index),
                    "expected_schema_version_before": str(expected_before),
                    "actual_schema_version_before": str(actual_before or ""),
                    "schema_version_after": str(spec.schema_version_after or ""),
                    "issue_code": "schema_version_chain_break",
                }
            )
        previous_after = str(spec.schema_version_after or "").strip() or previous_after
    return issues


def latest_schema_version(run_sql: RunSql) -> str | None:
    try:
        row = run_sql(
            """
            SELECT schema_version_after
            FROM schema_migrations
            WHERE status = 'applied'
              AND schema_version_after IS NOT NULL
              AND TRIM(schema_version_after) <> ''
            ORDER BY migration_entry_id DESC
            LIMIT 1
            """,
            (),
            fetch="one",
            query_name="schema_migrations.latest_schema_version_from_registry",
        )
    except Exception:
        row = None
    if isinstance(row, (list, tuple)) and row:
        value = row[0]
        return str(value).strip() or None
    if isinstance(row, Mapping):
        value = row.get("schema_version_after")
        return str(value).strip() or None
    try:
        row = run_sql(
            "SELECT version FROM schema_version ORDER BY applied_at_utc DESC LIMIT 1",
            (),
            fetch="one",
            query_name="schema_migrations.latest_schema_version",
        )
    except Exception:
        return None
    if isinstance(row, (list, tuple)) and row:
        value = row[0]
        return str(value).strip() or None
    if isinstance(row, Mapping):
        value = row.get("version")
        return str(value).strip() or None
    return None


def load_schema_migration_rows(run_sql: RunSql) -> list[dict[str, Any]]:
    rows = run_sql(
        """
        SELECT
          migration_entry_id,
          migration_id,
          migration_name,
          applied_at_utc,
          repo_git_commit,
          schema_version_before,
          schema_version_after,
          migration_checksum,
          applied_by,
          host_name,
          status,
          notes,
          receipt_path
        FROM schema_migrations
        ORDER BY applied_at_utc ASC, migration_entry_id ASC
        """,
        (),
        fetch="all",
        dictionary=True,
        query_name="schema_migrations.load_rows",
    ) or []
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def latest_rows_by_migration(run_sql: RunSql) -> dict[str, dict[str, Any]]:
    rows = load_schema_migration_rows(run_sql)
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        migration_id = str(row.get("migration_id") or "").strip()
        if migration_id:
            latest[migration_id] = row
    return latest


def build_schema_migration_report(run_sql: RunSql) -> dict[str, Any]:
    registry = list(registered_migrations())
    registry_dupes = duplicate_registry_ids()
    chain_issues = registry_version_chain_issues()
    applied_rows = load_schema_migration_rows(run_sql)
    latest_by_id = latest_rows_by_migration(run_sql)

    applied_counts: dict[str, int] = {}
    attempt_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    for row in applied_rows:
        migration_id = str(row.get("migration_id") or "").strip()
        status = str(row.get("status") or "").strip() or "<blank>"
        status_counts[status] = status_counts.get(status, 0) + 1
        if migration_id:
            attempt_counts[migration_id] = attempt_counts.get(migration_id, 0) + 1
            if status.lower() == "applied":
                applied_counts[migration_id] = applied_counts.get(migration_id, 0) + 1
    db_dupes = {key: value for key, value in applied_counts.items() if value > 1}
    retry_histories = {key: value for key, value in attempt_counts.items() if value > 1}

    registered_payload: list[dict[str, Any]] = []
    missing: list[str] = []
    checksum_mismatches: list[dict[str, Any]] = []
    for spec in registry:
        latest = latest_by_id.get(spec.migration_id) or {}
        latest_status = str(latest.get("status") or "").strip().lower()
        if latest_status != "applied":
            missing.append(spec.migration_id)
        db_checksum = str(latest.get("migration_checksum") or "").strip()
        if db_checksum and db_checksum != spec.checksum:
            checksum_mismatches.append(
                {
                    "migration_id": spec.migration_id,
                    "expected_checksum": spec.checksum,
                    "db_checksum": db_checksum,
                    "db_status": str(latest.get("status") or ""),
                }
            )
        registered_payload.append(
            {
                "migration_id": spec.migration_id,
                "migration_name": spec.migration_name,
                "schema_version_before": spec.schema_version_before,
                "schema_version_after": spec.schema_version_after,
                "checksum": spec.checksum,
                "apply_mode": spec.apply_mode,
                "stage": spec.stage,
                "description": spec.description,
                "latest_db_status": str(latest.get("status") or "") or None,
                "latest_db_applied_at_utc": latest.get("applied_at_utc"),
                "latest_db_receipt_path": latest.get("receipt_path"),
            }
        )

    registered_ids = {spec.migration_id for spec in registry}
    unregistered_applied_rows = [
        row
        for row in applied_rows
        if str(row.get("migration_id") or "").strip()
        and str(row.get("migration_id") or "").strip() not in registered_ids
    ]

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "live_schema_version": latest_schema_version(run_sql),
        "registered_migration_count": len(registry),
        "applied_row_count": len(applied_rows),
        "missing_migration_count": len(missing),
        "duplicate_registry_id_count": len(registry_dupes),
        "duplicate_applied_migration_id_count": len(db_dupes),
        "migration_retry_history_count": len(retry_histories),
        "registry_chain_issue_count": len(chain_issues),
        "checksum_mismatch_count": len(checksum_mismatches),
        "unregistered_applied_row_count": len(unregistered_applied_rows),
        "applied_status_counts": status_counts,
    }
    return {
        "summary": summary,
        "registered_migrations": registered_payload,
        "applied_rows": applied_rows,
        "missing_migrations": missing,
        "duplicate_registry_ids": registry_dupes,
        "duplicate_applied_migration_ids": db_dupes,
        "migration_retry_histories": retry_histories,
        "registry_chain_issues": chain_issues,
        "checksum_mismatches": checksum_mismatches,
        "unregistered_applied_rows": unregistered_applied_rows,
    }


def write_schema_migration_report_bundle(report: Mapping[str, Any], output_dir: Path, *, stem: str) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    base = str(stem)
    files: dict[str, str] = {}

    json_path = output_dir / f"{base}.json"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    files["json"] = str(json_path.resolve())

    csv_sections = {
        f"{base}_registered_migrations.csv": report.get("registered_migrations") or [],
        f"{base}_applied_rows.csv": report.get("applied_rows") or [],
        f"{base}_migration_retry_histories.csv": [
            {"migration_id": key, "attempt_count": value}
            for key, value in (report.get("migration_retry_histories") or {}).items()
        ],
        f"{base}_chain_issues.csv": report.get("registry_chain_issues") or [],
        f"{base}_checksum_mismatches.csv": report.get("checksum_mismatches") or [],
        f"{base}_unregistered_applied_rows.csv": report.get("unregistered_applied_rows") or [],
    }
    for filename, rows in csv_sections.items():
        path = output_dir / filename
        row_list = list(rows) if isinstance(rows, list) else []
        if not row_list:
            path.write_text("", encoding="utf-8")
            files[filename] = str(path.resolve())
            continue
        fieldnames: list[str] = []
        for row in row_list:
            if not isinstance(row, Mapping):
                continue
            for key in row:
                if str(key) not in fieldnames:
                    fieldnames.append(str(key))
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for row in row_list:
                writer.writerow({key: row.get(key) for key in fieldnames})
        files[filename] = str(path.resolve())

    missing_path = output_dir / f"{base}_missing_migrations.txt"
    missing_values = [str(value).strip() for value in (report.get("missing_migrations") or []) if str(value).strip()]
    missing_path.write_text("\n".join(missing_values) + ("\n" if missing_values else ""), encoding="utf-8")
    files["missing_migrations_txt"] = str(missing_path.resolve())
    return files


def record_schema_migration(
    run_sql: RunSql,
    *,
    spec: MigrationSpec,
    status: str,
    schema_version_before: str | None = None,
    schema_version_after: str | None = None,
    notes: str | None = None,
    receipt_path: str | None = None,
    payload: Mapping[str, Any] | None = None,
) -> None:
    applied_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    run_sql(
        """
        INSERT INTO schema_migrations (
          migration_id,
          migration_name,
          applied_at_utc,
          repo_git_commit,
          schema_version_before,
          schema_version_after,
          migration_checksum,
          applied_by,
          host_name,
          status,
          notes,
          receipt_path,
          payload_json
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            spec.migration_id,
            spec.migration_name,
            applied_at,
            get_git_commit(),
            schema_version_before or spec.schema_version_before,
            schema_version_after or spec.schema_version_after,
            spec.checksum,
            getpass.getuser(),
            socket.gethostname(),
            status,
            notes,
            receipt_path,
            json.dumps(payload, sort_keys=True) if payload else None,
        ),
        query_name="schema_migrations.insert",
    )


def append_schema_version(run_sql: RunSql, version: str | None) -> None:
    text = str(version or "").strip()
    if not text:
        return
    run_sql(
        "INSERT INTO schema_version (version, applied_at_utc) VALUES (%s, %s)",
        (text, datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")),
        query_name="schema_migrations.append_schema_version",
    )


def attach_receipt_path_to_latest_migration(
    run_sql: RunSql,
    *,
    migration_id: str,
    receipt_path: str | None,
) -> None:
    if not str(migration_id or "").strip() or not str(receipt_path or "").strip():
        return
    run_sql(
        """
        UPDATE schema_migrations
        SET receipt_path = %s
        WHERE migration_entry_id = (
          SELECT migration_entry_id
          FROM (
            SELECT migration_entry_id
            FROM schema_migrations
            WHERE migration_id = %s
            ORDER BY migration_entry_id DESC
            LIMIT 1
          ) latest_row
        )
        """,
        (receipt_path, migration_id),
        query_name="schema_migrations.attach_receipt_path",
    )


def ensure_governance_baseline(run_sql: RunSql) -> bool:
    spec = registered_migrations()[0]
    row = run_sql(
        """
        SELECT migration_entry_id
        FROM schema_migrations
        WHERE migration_id = %s
          AND status = 'applied'
        ORDER BY migration_entry_id DESC
        LIMIT 1
        """,
        (spec.migration_id,),
        fetch="one",
        query_name="schema_migrations.baseline_present",
    )
    if row:
        return False
    before = latest_schema_version(run_sql) or spec.schema_version_before
    record_schema_migration(
        run_sql,
        spec=spec,
        status="applied",
        schema_version_before=before,
        schema_version_after=spec.schema_version_after,
        notes="bootstrap-managed migration governance baseline",
    )
    append_schema_version(run_sql, spec.schema_version_after)
    return True


__all__ = [
    "MigrationSpec",
    "PHASE_A_MIGRATIONS",
    "PHASE_B_MIGRATIONS",
    "RESEARCH_COHORT_MIGRATIONS",
    "DYNAMIC_DOMAIN_CONTEXT_MIGRATIONS",
    "DYNAMIC_SERVICE_SIGNAL_MIGRATIONS",
    "attach_receipt_path_to_latest_migration",
    "append_schema_version",
    "build_schema_migration_report",
    "duplicate_registry_ids",
    "ensure_governance_baseline",
    "latest_registered_schema_version",
    "latest_rows_by_migration",
    "latest_schema_version",
    "load_schema_migration_rows",
    "record_schema_migration",
    "registry_version_chain_issues",
    "registered_migrations",
    "schema_version_gte",
    "write_schema_migration_report_bundle",
]
