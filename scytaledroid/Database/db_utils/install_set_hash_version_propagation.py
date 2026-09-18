"""Governed, fail-closed 0.3.17 install-set hash-version migration support.

MariaDB DDL implicitly commits, so schema statements are applied one at a time
and resumed from physical posture. Historical dynamic rows are never given a
version; they remain ``VERSION_UNKNOWN_LEGACY``. Static backfill writes only
when the linked apk_set digest agrees and the stored set version is v1 or v2.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Literal

from .schema_migration_registry import (
    MigrationSpec,
    append_schema_version,
    latest_schema_version,
    record_schema_migration,
)

RunSql = Callable[..., Any]
SchemaStatus = Literal["absent", "partial", "complete"]

MIGRATION_ID = "20260918_install_set_hash_version_propagation_v1"
SCHEMA_VERSION_BEFORE = "0.3.16-dynamic-domain-normalization-v2"
SCHEMA_VERSION_AFTER = "0.3.17-install-set-hash-version-propagation-v1"
VERSION_UNKNOWN_LEGACY = "VERSION_UNKNOWN_LEGACY"
IDENTITY_CONFLICT = "IDENTITY_CONFLICT"
APPLY_SUPPORTED = True
WRITER_MODE = "v1"
PRODUCTION_DATABASES = frozenset({"scytaledroid_core_prod"})
STATIC_COLUMN = "artifact_set_hash_version"
DYNAMIC_COLUMN = "artifact_set_hash_version"
STATIC_INDEX = "ix_static_runs_artifact_set_identity"
DYNAMIC_INDEX = "ix_dynamic_sessions_artifact_set_identity"

DDL = (
    "ALTER TABLE static_analysis_runs ADD COLUMN IF NOT EXISTS artifact_set_hash_version VARCHAR(16) NULL",
    "ALTER TABLE dynamic_sessions ADD COLUMN IF NOT EXISTS artifact_set_hash_version VARCHAR(16) NULL",
    "CREATE INDEX IF NOT EXISTS ix_static_runs_artifact_set_identity ON static_analysis_runs (artifact_set_hash_version, artifact_set_hash)",
    "CREATE INDEX IF NOT EXISTS ix_dynamic_sessions_artifact_set_identity ON dynamic_sessions (artifact_set_hash_version, artifact_set_hash)",
)

INSTALL_SET_HASH_VERSION_PROPAGATION_MIGRATION = MigrationSpec(
    migration_id=MIGRATION_ID,
    migration_name="Propagate versioned portable install-set identity",
    schema_version_before=SCHEMA_VERSION_BEFORE,
    schema_version_after=SCHEMA_VERSION_AFTER,
    statements=DDL,
    description="Adds nullable identity-version provenance; historical dynamic rows remain unknown.",
    apply_mode="manual_script",
    stage="identity",
)


@dataclass(frozen=True)
class StaticVersionDecision:
    run_id: int
    version: str | None
    classification: str


@dataclass(frozen=True)
class SchemaPosture:
    static_column: bool
    dynamic_column: bool
    static_index: bool
    dynamic_index: bool

    @property
    def status(self) -> SchemaStatus:
        flags = (self.static_column, self.dynamic_column, self.static_index, self.dynamic_index)
        if all(flags):
            return "complete"
        if not any(flags):
            return "absent"
        return "partial"

    def missing_statements(self) -> tuple[str, ...]:
        missing: list[str] = []
        if not self.static_column:
            missing.append(DDL[0])
        if not self.dynamic_column:
            missing.append(DDL[1])
        if not self.static_index:
            missing.append(DDL[2])
        if not self.dynamic_index:
            missing.append(DDL[3])
        return tuple(missing)


def decide_static_version(row: Mapping[str, Any]) -> StaticVersionDecision:
    run_id = int(row.get("id") or 0)
    run_hash = str(row.get("artifact_set_hash") or "").strip().lower()
    set_id = row.get("apk_set_id")
    set_hash = str(row.get("linked_artifact_set_hash") or "").strip().lower()
    version = str(row.get("linked_artifact_set_hash_version") or "").strip()
    if not set_id or not run_hash or not set_hash or not version:
        return StaticVersionDecision(run_id, None, VERSION_UNKNOWN_LEGACY)
    if run_hash != set_hash:
        return StaticVersionDecision(run_id, None, IDENTITY_CONFLICT)
    if version not in {"v1", "v2"}:
        return StaticVersionDecision(run_id, None, VERSION_UNKNOWN_LEGACY)
    return StaticVersionDecision(run_id, version, f"KNOWN_{version.upper()}")


def summarize_static_backfill(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    decisions = [decide_static_version(row) for row in rows]
    return summarize_static_decisions(decisions)


def summarize_static_decisions(decisions: Sequence[StaticVersionDecision]) -> dict[str, int]:
    return {
        "static_total": len(decisions),
        "static_safe_candidates": sum(d.version is not None for d in decisions),
        "static_conflicts": sum(d.classification == IDENTITY_CONFLICT for d in decisions),
        "static_insufficient_proof": sum(d.classification == VERSION_UNKNOWN_LEGACY for d in decisions),
    }


def dynamic_legacy_classification(_: Mapping[str, Any]) -> str:
    return VERSION_UNKNOWN_LEGACY


def summarize_dynamic_history(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "dynamic_total": len(rows),
        "dynamic_version_unknown_legacy": sum(
            dynamic_legacy_classification(row) == VERSION_UNKNOWN_LEGACY
            and not str(row.get("artifact_set_hash_version") or "").strip()
            for row in rows
        ),
        "dynamic_automatic_version_backfill": 0,
        "dynamic_preexisting_version": sum(
            1 for row in rows if str(row.get("artifact_set_hash_version") or "").strip()
        ),
    }


def is_production_database(name: str | None) -> bool:
    return str(name or "").strip().lower() in PRODUCTION_DATABASES


def worklist_sha256(decisions: Sequence[StaticVersionDecision]) -> str:
    payload = [
        [decision.run_id, decision.version, decision.classification]
        for decision in sorted(decisions, key=lambda item: item.run_id)
    ]
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return sha256(encoded).hexdigest()


def migration_already_applied(run_sql: RunSql) -> bool:
    row = run_sql(
        """
        SELECT migration_entry_id
        FROM schema_migrations
        WHERE migration_id = %s AND status = 'applied'
        ORDER BY migration_entry_id DESC
        LIMIT 1
        """,
        (MIGRATION_ID,),
        fetch="one",
        query_name="install_set_hash_version.migration_applied",
    )
    return bool(row)


def inspect_schema_posture(run_sql: RunSql) -> SchemaPosture:
    return SchemaPosture(
        static_column=_column_exists(run_sql, "static_analysis_runs", STATIC_COLUMN),
        dynamic_column=_column_exists(run_sql, "dynamic_sessions", DYNAMIC_COLUMN),
        static_index=_index_exists(run_sql, "static_analysis_runs", STATIC_INDEX),
        dynamic_index=_index_exists(run_sql, "dynamic_sessions", DYNAMIC_INDEX),
    )


def _column_exists(run_sql: RunSql, table_name: str, column_name: str) -> bool:
    row = run_sql(
        """
        SELECT COUNT(*) AS n
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name = %s
        """,
        (table_name, column_name),
        fetch="one",
        dictionary=True,
        query_name=f"install_set_hash_version.column.{table_name}",
    )
    return bool(isinstance(row, Mapping) and int(row.get("n") or 0) > 0)


def _index_exists(run_sql: RunSql, table_name: str, index_name: str) -> bool:
    row = run_sql(
        """
        SELECT COUNT(*) AS n
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND index_name = %s
        """,
        (table_name, index_name),
        fetch="one",
        dictionary=True,
        query_name=f"install_set_hash_version.index.{table_name}",
    )
    return bool(isinstance(row, Mapping) and int(row.get("n") or 0) > 0)


def apply_missing_ddl(run_sql: RunSql, *, crash_after: int | None = None) -> dict[str, Any]:
    """Apply only missing DDL. Each statement is treated as an implicit commit."""

    before = inspect_schema_posture(run_sql)
    applied: list[str] = []
    skipped = list(DDL)
    for statement in before.missing_statements():
        if crash_after is not None and len(applied) >= crash_after:
            raise RuntimeError(
                f"simulated implicit-commit interrupt after {len(applied)} DDL statement(s)"
            )
        run_sql(statement, (), query_name="install_set_hash_version.apply_ddl")
        applied.append(statement)
    after = inspect_schema_posture(run_sql)
    skipped = [statement for statement in DDL if statement not in applied]
    return {
        "implicit_commit_aware": True,
        "schema_posture_before": before.status,
        "schema_posture_after": after.status,
        "statements_applied": applied,
        "statements_already_present": skipped if after.status == "complete" else [
            statement for statement in DDL if statement not in applied and statement not in before.missing_statements()
        ],
        "statements_remaining": list(after.missing_statements()),
        "complete": after.status == "complete",
    }


def load_static_identity_rows(run_sql: RunSql) -> list[dict[str, Any]]:
    rows = (
        run_sql(
            """
            SELECT
              sar.id,
              sar.apk_set_id,
              sar.artifact_set_hash,
              sar.artifact_set_hash_version AS stored_artifact_set_hash_version,
              s.artifact_set_hash AS linked_artifact_set_hash,
              s.artifact_set_hash_version AS linked_artifact_set_hash_version
            FROM static_analysis_runs sar
            LEFT JOIN apk_sets s ON s.apk_set_id = sar.apk_set_id
            ORDER BY sar.id
            """,
            (),
            fetch="all",
            dictionary=True,
            query_name="install_set_hash_version.load_static",
        )
        or []
    )
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def load_dynamic_identity_rows(run_sql: RunSql) -> list[dict[str, Any]]:
    rows = (
        run_sql(
            """
            SELECT
              dynamic_run_id,
              apk_set_id,
              artifact_set_hash,
              artifact_set_hash_version
            FROM dynamic_sessions
            ORDER BY dynamic_run_id
            """,
            (),
            fetch="all",
            dictionary=True,
            query_name="install_set_hash_version.load_dynamic",
        )
        or []
    )
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def count_written_static(
    rows: Sequence[Mapping[str, Any]],
    decisions: Sequence[StaticVersionDecision],
) -> int:
    wanted = {decision.run_id: decision.version for decision in decisions if decision.version}
    written = 0
    for row in rows:
        run_id = int(row.get("id") or 0)
        stored = str(row.get("stored_artifact_set_hash_version") or "").strip()
        if run_id in wanted and stored == wanted[run_id]:
            written += 1
    return written


def apply_static_backfill(
    run_sql: RunSql,
    decisions: Sequence[StaticVersionDecision],
) -> int:
    """Write only safe versions for an explicit ID set. Never rewrite a stored version."""

    safe = [decision for decision in decisions if decision.version]
    if not safe:
        return 0
    updated = 0
    for decision in safe:
        result = run_sql(
            """
            UPDATE static_analysis_runs
               SET artifact_set_hash_version = %s
             WHERE id = %s
               AND artifact_set_hash_version IS NULL
            """,
            (decision.version, decision.run_id),
            query_name="install_set_hash_version.static_backfill",
        )
        if isinstance(result, int):
            updated += result
        else:
            updated += 1
    return updated


def reconcile_result(
    *,
    static_summary: Mapping[str, int],
    dynamic_summary: Mapping[str, int],
    updated_static: int,
    schema_complete: bool,
    conflicts_block_apply: bool = True,
) -> dict[str, Any]:
    residual_safe = max(int(static_summary["static_safe_candidates"]) - int(updated_static), 0)
    ok = (
        schema_complete
        and residual_safe == 0
        and int(dynamic_summary["dynamic_automatic_version_backfill"]) == 0
        and (not conflicts_block_apply or int(static_summary["static_conflicts"]) == 0)
    )
    return {
        "ok": ok,
        "schema_complete": schema_complete,
        "static_updated": int(updated_static),
        "static_safe_unwritten": residual_safe,
        "static_conflicts": int(static_summary["static_conflicts"]),
        "dynamic_automatic_version_backfill": int(dynamic_summary["dynamic_automatic_version_backfill"]),
    }


def build_preflight(
    run_sql: RunSql,
    *,
    database_name: str | None = None,
) -> dict[str, Any]:
    current_version = latest_schema_version(run_sql)
    posture = inspect_schema_posture(run_sql)
    static_rows = load_static_identity_rows(run_sql) if posture.static_column else _load_static_without_version(run_sql)
    dynamic_rows = (
        load_dynamic_identity_rows(run_sql) if posture.dynamic_column else _load_dynamic_without_version(run_sql)
    )
    decisions = [decide_static_version(row) for row in static_rows]
    static_summary = summarize_static_decisions(decisions)
    dynamic_summary = summarize_dynamic_history(dynamic_rows)
    conflict_ids = [decision.run_id for decision in decisions if decision.classification == IDENTITY_CONFLICT]
    return {
        "migration_id": MIGRATION_ID,
        "schema_version_before": current_version,
        "schema_version_after": SCHEMA_VERSION_AFTER,
        "apply_supported": APPLY_SUPPORTED,
        "writer_mode": WRITER_MODE,
        "dynamic_legacy_policy": VERSION_UNKNOWN_LEGACY,
        "database_name": database_name,
        "production_database": is_production_database(database_name),
        "migration_already_applied": migration_already_applied(run_sql),
        "schema_posture": {
            "status": posture.status,
            "static_column": posture.static_column,
            "dynamic_column": posture.dynamic_column,
            "static_index": posture.static_index,
            "dynamic_index": posture.dynamic_index,
            "missing_statements": list(posture.missing_statements()),
        },
        "static": static_summary,
        "dynamic": dynamic_summary,
        "conflict_static_run_ids": conflict_ids,
        "worklist_sha256": worklist_sha256(decisions),
        "apply_blocked_reason": _apply_blocked_reason(
            current_version=current_version,
            conflicts=static_summary["static_conflicts"],
        ),
    }


def _apply_blocked_reason(*, current_version: str | None, conflicts: int) -> str | None:
    current = str(current_version or "").strip()
    if conflicts:
        return "unexplained_static_identity_conflict"
    if not current:
        return "schema_version_unreadable"
    if current != SCHEMA_VERSION_BEFORE and current != SCHEMA_VERSION_AFTER:
        return f"unexpected_schema_version:{current}"
    return None


def _load_static_without_version(run_sql: RunSql) -> list[dict[str, Any]]:
    rows = (
        run_sql(
            """
            SELECT
              sar.id,
              sar.apk_set_id,
              sar.artifact_set_hash,
              NULL AS stored_artifact_set_hash_version,
              s.artifact_set_hash AS linked_artifact_set_hash,
              s.artifact_set_hash_version AS linked_artifact_set_hash_version
            FROM static_analysis_runs sar
            LEFT JOIN apk_sets s ON s.apk_set_id = sar.apk_set_id
            ORDER BY sar.id
            """,
            (),
            fetch="all",
            dictionary=True,
            query_name="install_set_hash_version.load_static_pre_ddl",
        )
        or []
    )
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def _load_dynamic_without_version(run_sql: RunSql) -> list[dict[str, Any]]:
    rows = (
        run_sql(
            """
            SELECT
              dynamic_run_id,
              apk_set_id,
              artifact_set_hash,
              NULL AS artifact_set_hash_version
            FROM dynamic_sessions
            ORDER BY dynamic_run_id
            """,
            (),
            fetch="all",
            dictionary=True,
            query_name="install_set_hash_version.load_dynamic_pre_ddl",
        )
        or []
    )
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def apply_install_set_hash_version_propagation(
    run_sql: RunSql,
    *,
    database_name: str | None = None,
    receipt_path: str | None = None,
    allow_production: bool = False,
    crash_after_ddl: int | None = None,
) -> dict[str, Any]:
    preflight = build_preflight(run_sql, database_name=database_name)
    if preflight["production_database"] and not allow_production:
        raise RuntimeError("refusing to apply 0.3.17 to a production catalog without allow_production")
    if preflight["apply_blocked_reason"]:
        raise RuntimeError(f"0.3.17 apply blocked: {preflight['apply_blocked_reason']}")

    ddl = apply_missing_ddl(run_sql, crash_after=crash_after_ddl)
    if not ddl["complete"]:
        raise RuntimeError(
            "0.3.17 DDL incomplete after implicit-commit apply; remaining="
            + ",".join(ddl["statements_remaining"])
        )

    static_rows = load_static_identity_rows(run_sql)
    dynamic_rows = load_dynamic_identity_rows(run_sql)
    decisions = [decide_static_version(row) for row in static_rows]
    locked_sha = worklist_sha256(decisions)
    if locked_sha != preflight["worklist_sha256"]:
        raise RuntimeError("static identity worklist changed after preflight; no version backfill applied")

    already_stored = {
        int(row.get("id") or 0)
        for row in static_rows
        if str(row.get("stored_artifact_set_hash_version") or "").strip()
    }
    pending = [
        decision
        for decision in decisions
        if decision.version and decision.run_id not in already_stored
    ]
    apply_static_backfill(run_sql, pending)
    after_rows = load_static_identity_rows(run_sql)
    updated = count_written_static(after_rows, decisions)

    static_summary = summarize_static_decisions(decisions)
    dynamic_summary = summarize_dynamic_history(dynamic_rows)
    verification = reconcile_result(
        static_summary=static_summary,
        dynamic_summary=dynamic_summary,
        updated_static=updated,
        schema_complete=True,
    )
    if not verification["ok"]:
        raise RuntimeError(f"0.3.17 reconciliation failed: {verification}")

    recorded = bool(preflight["migration_already_applied"])
    if not recorded:
        before = preflight["schema_version_before"] or SCHEMA_VERSION_BEFORE
        record_schema_migration(
            run_sql,
            spec=INSTALL_SET_HASH_VERSION_PROPAGATION_MIGRATION,
            status="applied",
            schema_version_before=before,
            schema_version_after=SCHEMA_VERSION_AFTER,
            notes="nullable identity-version columns; static safe backfill; historical dynamic unknown",
            receipt_path=receipt_path,
            payload={"worklist_sha256": locked_sha, "ddl": ddl, "verification": verification},
        )
        append_schema_version(run_sql, SCHEMA_VERSION_AFTER)

    return {
        "mode": "apply",
        "migration_id": MIGRATION_ID,
        "schema_version_after": SCHEMA_VERSION_AFTER,
        "writer_mode": WRITER_MODE,
        "ddl": ddl,
        "static": static_summary,
        "dynamic": dynamic_summary,
        "verification": verification,
        "worklist_sha256": locked_sha,
        "recorded_migration": True,
    }


@dataclass
class IsolatedIdentityRehearsal:
    """In-memory MariaDB stand-in: each DDL statement is an implicit commit."""

    static_rows: list[dict[str, Any]]
    dynamic_rows: list[dict[str, Any]]
    columns: dict[str, set[str]] = field(default_factory=lambda: {
        "static_analysis_runs": set(),
        "dynamic_sessions": set(),
    })
    indexes: set[str] = field(default_factory=set)
    schema_versions: list[str] = field(default_factory=lambda: [SCHEMA_VERSION_BEFORE])
    applied_migrations: list[str] = field(default_factory=list)
    executed: list[str] = field(default_factory=list)

    def run_sql(self, sql: str, params: Sequence[Any] = (), **kwargs: Any) -> Any:
        query_name = str(kwargs.get("query_name") or "")
        self.executed.append(query_name or sql.split()[0])
        if query_name.startswith("install_set_hash_version.column."):
            table = "static_analysis_runs" if "static_analysis_runs" in query_name else "dynamic_sessions"
            present = STATIC_COLUMN in self.columns[table]
            return {"n": 1 if present else 0}
        if query_name.startswith("install_set_hash_version.index."):
            index_name = STATIC_INDEX if "static_analysis_runs" in query_name else DYNAMIC_INDEX
            return {"n": 1 if index_name in self.indexes else 0}
        if query_name == "install_set_hash_version.migration_applied":
            return (1,) if MIGRATION_ID in self.applied_migrations else None
        if query_name == "schema_migrations.latest_schema_version_from_registry":
            return (self.schema_versions[-1],) if self.schema_versions else None
        if query_name in {
            "install_set_hash_version.load_static",
            "install_set_hash_version.load_static_pre_ddl",
        }:
            return [dict(row) for row in self.static_rows]
        if query_name in {
            "install_set_hash_version.load_dynamic",
            "install_set_hash_version.load_dynamic_pre_ddl",
        }:
            return [dict(row) for row in self.dynamic_rows]
        if query_name == "install_set_hash_version.apply_ddl":
            self._apply_ddl(sql)
            return None
        if query_name == "install_set_hash_version.static_backfill":
            version, run_id = params
            for row in self.static_rows:
                if int(row.get("id") or 0) == int(run_id) and not row.get("stored_artifact_set_hash_version"):
                    row["stored_artifact_set_hash_version"] = version
                    return 1
            return 0
        if query_name == "schema_migrations.insert":
            self.applied_migrations.append(str(params[0]))
            return None
        if query_name == "schema_migrations.append_schema_version":
            self.schema_versions.append(str(params[0]))
            return None
        raise AssertionError(f"unexpected SQL in rehearsal: {query_name or sql}")

    def _apply_ddl(self, sql: str) -> None:
        if "static_analysis_runs ADD COLUMN" in sql:
            self.columns["static_analysis_runs"].add(STATIC_COLUMN)
        elif "dynamic_sessions ADD COLUMN" in sql:
            self.columns["dynamic_sessions"].add(DYNAMIC_COLUMN)
        elif STATIC_INDEX in sql:
            self.indexes.add(STATIC_INDEX)
        elif DYNAMIC_INDEX in sql:
            self.indexes.add(DYNAMIC_INDEX)
        else:
            raise AssertionError(sql)
