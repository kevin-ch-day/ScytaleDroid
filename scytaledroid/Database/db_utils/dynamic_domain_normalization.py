"""Staged migration helpers for additive PSL registrant identities."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any, Literal

from scytaledroid.Utils.domain_identity import build_root_domain_identity

from ..db_core import db_config
from .schema_migration_registry import (
    MigrationSpec,
    append_schema_version,
    latest_schema_version,
    record_schema_migration,
)

RunSql = Callable[..., Any]
NormalizationSchemaPosture = Literal["absent", "complete", "partial"]

MIGRATION_ID = "20260816_dynamic_domain_normalization_v2"
SCHEMA_VERSION_AFTER = "0.3.16-dynamic-domain-normalization-v2"
_PROVENANCE_COLUMNS = {
    "registrable_domain_psl",
    "registrable_domain_normalization",
    "registrable_domain_reference_sha256",
}

DYNAMIC_DOMAIN_NORMALIZATION_MIGRATION = MigrationSpec(
    migration_id=MIGRATION_ID,
    migration_name="Add versioned dynamic registrable-domain identity",
    schema_version_before="0.3.15-dynamic-session-qfg-metadata",
    schema_version_after=SCHEMA_VERSION_AFTER,
    statements=(
        "ALTER TABLE dynamic_domain_observations "
        "ADD COLUMN IF NOT EXISTS registrable_domain_psl VARCHAR(255) DEFAULT NULL, "
        "ADD COLUMN IF NOT EXISTS registrable_domain_normalization VARCHAR(96) NOT NULL DEFAULT 'legacy_suffix_v1', "
        "ADD COLUMN IF NOT EXISTS registrable_domain_reference_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin DEFAULT NULL",
        "CREATE INDEX IF NOT EXISTS ix_dyn_domain_obs_registrable_psl "
        "ON dynamic_domain_observations (registrable_domain_psl)",
    ),
    description=(
        "Preserves dynamic aggregation roots while adding a separate pinned-PSL "
        "registrant boundary and normalization provenance."
    ),
    apply_mode="manual_script",
    stage="dynamic_context",
)


@dataclass(frozen=True)
class DomainNormalizationCandidate:
    observation_id: int
    dynamic_run_id: str
    package_name: str
    indicator_type: str
    observed_domain: str
    root_domain: str
    registrable_domain_psl: str
    normalization_key: str
    reference_sha256: str | None
    psl_boundary_differs: bool
    needs_update: bool

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


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
    )
    return bool(row)


def normalization_schema_posture(
    run_sql: RunSql,
    *,
    dialect: str | None = None,
) -> NormalizationSchemaPosture:
    """Return physical column posture; query failures deliberately propagate."""
    effective_dialect = str(dialect or db_config.DB_CONFIG.get("engine") or "").lower()
    if effective_dialect == "sqlite":
        rows = (
            run_sql(
                "PRAGMA table_info(dynamic_domain_observations)",
                (),
                fetch="all",
                dictionary=True,
                query_name="dynamic_domain_normalization.provenance_columns",
            )
            or []
        )
        column_key = "name"
    else:
        rows = (
            run_sql(
                """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = 'dynamic_domain_observations'
              AND column_name IN (
                'registrable_domain_psl',
                'registrable_domain_normalization',
                'registrable_domain_reference_sha256'
              )
            """,
                (),
                fetch="all",
                dictionary=True,
                query_name="dynamic_domain_normalization.provenance_columns",
            )
            or []
        )
        column_key = "column_name"
    present = {
        str(row.get(column_key) or "").strip().lower() for row in rows if isinstance(row, Mapping)
    } & _PROVENANCE_COLUMNS
    if not present:
        return "absent"
    if present == _PROVENANCE_COLUMNS:
        return "complete"
    return "partial"


def normalization_columns_available(
    run_sql: RunSql,
    *,
    dialect: str | None = None,
) -> bool:
    """Return availability, rejecting unsafe partially migrated schemas."""
    posture = normalization_schema_posture(run_sql, dialect=dialect)
    if posture == "partial":
        raise RuntimeError(
            "dynamic_domain_observations has a partial registrable-domain schema; "
            "stop writes and repair the migration before continuing"
        )
    return posture == "complete"


def normalization_index_available(run_sql: RunSql) -> bool:
    """Return whether the expected PSL lookup index is physically present."""
    row = run_sql(
        """
        SELECT COUNT(*) AS n
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
          AND table_name = 'dynamic_domain_observations'
          AND index_name = 'ix_dyn_domain_obs_registrable_psl'
          AND column_name = 'registrable_domain_psl'
        """,
        (),
        fetch="one",
        dictionary=True,
        query_name="dynamic_domain_normalization.provenance_index",
    )
    return bool(isinstance(row, Mapping) and int(row.get("n") or 0) > 0)


def apply_dynamic_domain_normalization_schema(run_sql: RunSql) -> bool:
    """Apply additive columns/index and record the migration once."""
    recorded = migration_already_applied(run_sql)
    posture = normalization_schema_posture(run_sql)
    index_present = normalization_index_available(run_sql) if posture == "complete" else False
    if recorded and (posture != "complete" or not index_present):
        raise RuntimeError(
            f"migration {MIGRATION_ID} is recorded as applied but physical schema posture "
            f"is columns={posture}, index_present={index_present}; refusing to conceal "
            "schema-registry drift"
        )
    if recorded:
        return False
    if posture == "partial":
        raise RuntimeError(
            "partial registrable-domain schema detected without an applied migration record; "
            "review and repair it before retrying"
        )
    before = (
        latest_schema_version(run_sql)
        or DYNAMIC_DOMAIN_NORMALIZATION_MIGRATION.schema_version_before
    )
    for statement in DYNAMIC_DOMAIN_NORMALIZATION_MIGRATION.statements:
        run_sql(statement, (), query_name="dynamic_domain_normalization.apply_schema")
    if normalization_schema_posture(run_sql) != "complete" or not normalization_index_available(
        run_sql
    ):
        raise RuntimeError(
            "registrable-domain DDL completed without all required columns/index becoming visible"
        )
    record_schema_migration(
        run_sql,
        spec=DYNAMIC_DOMAIN_NORMALIZATION_MIGRATION,
        status="applied",
        schema_version_before=before,
        schema_version_after=SCHEMA_VERSION_AFTER,
        notes=(
            "additive provenance columns; row migration is separately receipt-backed; "
            f"physical_schema_before={posture}"
        ),
    )
    append_schema_version(run_sql, SCHEMA_VERSION_AFTER)
    return True


def load_observation_rows(
    run_sql: RunSql,
    *,
    include_provenance: bool,
    for_update: bool = False,
) -> list[dict[str, Any]]:
    provenance_sql = (
        ", registrable_domain_psl, registrable_domain_normalization, registrable_domain_reference_sha256"
        if include_provenance
        else ""
    )
    rows = (
        run_sql(
            f"""
        SELECT
          observation_id,
          dynamic_run_id,
          package_name,
          indicator_type,
          observed_domain,
          root_domain
          {provenance_sql}
        FROM dynamic_domain_observations
        ORDER BY observation_id
        {"FOR UPDATE" if for_update else ""}
        """,
            (),
            fetch="all",
            dictionary=True,
            query_name="dynamic_domain_normalization.load_observations",
        )
        or []
    )
    return [dict(row) for row in rows if isinstance(row, Mapping)]


def build_candidates(
    rows: Sequence[Mapping[str, Any]],
) -> list[DomainNormalizationCandidate]:
    candidates: list[DomainNormalizationCandidate] = []
    for row in rows:
        try:
            observation_id = int(row.get("observation_id") or 0)
        except (TypeError, ValueError):
            continue
        observed = str(row.get("observed_domain") or "").strip().lower()
        current_root = str(row.get("root_domain") or "").strip().lower()
        if observation_id <= 0 or not observed or not current_root:
            continue
        indicator_type = str(row.get("indicator_type") or "").strip().lower()
        identity = build_root_domain_identity(
            observed,
            current_root,
            is_ip=indicator_type == "ip_dst",
        )
        stored_registrable = str(row.get("registrable_domain_psl") or "").strip().lower()
        stored_normalization = str(row.get("registrable_domain_normalization") or "").strip()
        stored_reference = str(row.get("registrable_domain_reference_sha256") or "").strip() or None
        needs_update = (
            stored_registrable != identity.registrable_domain_psl
            or stored_normalization != identity.normalization_key
            or stored_reference != identity.reference_sha256
        )
        candidates.append(
            DomainNormalizationCandidate(
                observation_id=observation_id,
                dynamic_run_id=str(row.get("dynamic_run_id") or "").strip(),
                package_name=str(row.get("package_name") or "").strip(),
                indicator_type=indicator_type,
                observed_domain=observed,
                root_domain=current_root,
                registrable_domain_psl=identity.registrable_domain_psl,
                normalization_key=identity.normalization_key,
                reference_sha256=identity.reference_sha256,
                psl_boundary_differs=current_root != identity.registrable_domain_psl,
                needs_update=needs_update,
            )
        )
    return candidates


def summarize_candidates(
    candidates: Sequence[DomainNormalizationCandidate],
) -> dict[str, Any]:
    update_rows = [candidate for candidate in candidates if candidate.needs_update]
    differing_rows = [candidate for candidate in candidates if candidate.psl_boundary_differs]
    return {
        "candidate_rows": len(candidates),
        "rows_needing_update": len(update_rows),
        "psl_boundary_difference_rows": len(differing_rows),
        "same_boundary_provenance_rows": len(update_rows) - len(differing_rows),
        "packages_affected": len({candidate.package_name for candidate in update_rows}),
        "runs_affected": len({candidate.dynamic_run_id for candidate in update_rows}),
        "root_domain_boundary_difference_counts": dict(
            sorted(
                Counter(candidate.root_domain for candidate in differing_rows).items(),
                key=lambda item: (-item[1], item[0]),
            )
        ),
    }


def candidate_worklist_sha256(
    candidates: Sequence[DomainNormalizationCandidate],
) -> str:
    """Hash the ordered, exact candidate worklist for stale-plan detection."""
    encoded = json.dumps(
        [candidate.as_dict() for candidate in candidates],
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def apply_candidate_updates(
    run_sql: RunSql,
    candidates: Sequence[DomainNormalizationCandidate],
) -> int:
    """Update only explicitly enumerated observation IDs inside caller transaction."""
    updated = 0
    for candidate in candidates:
        if not candidate.needs_update:
            continue
        run_sql(
            """
            UPDATE dynamic_domain_observations
            SET
              registrable_domain_psl = %s,
              registrable_domain_normalization = %s,
              registrable_domain_reference_sha256 = %s
            WHERE observation_id = %s
              AND dynamic_run_id = %s
            """,
            (
                candidate.registrable_domain_psl,
                candidate.normalization_key,
                candidate.reference_sha256,
                candidate.observation_id,
                candidate.dynamic_run_id,
            ),
            query_name="dynamic_domain_normalization.update_observation",
        )
        updated += 1
    return updated


def verify_candidates(
    rows: Sequence[Mapping[str, Any]],
    candidates: Sequence[DomainNormalizationCandidate],
) -> dict[str, Any]:
    expected = {candidate.observation_id: candidate for candidate in candidates}
    verified = 0
    mismatches: list[dict[str, Any]] = []
    for row in rows:
        try:
            observation_id = int(row.get("observation_id") or 0)
        except (TypeError, ValueError):
            continue
        candidate = expected.get(observation_id)
        if candidate is None:
            continue
        actual = (
            str(row.get("root_domain") or "").strip().lower(),
            str(row.get("registrable_domain_psl") or "").strip().lower(),
            str(row.get("registrable_domain_normalization") or "").strip(),
            str(row.get("registrable_domain_reference_sha256") or "").strip() or None,
        )
        wanted = (
            candidate.root_domain,
            candidate.registrable_domain_psl,
            candidate.normalization_key,
            candidate.reference_sha256,
        )
        if actual == wanted:
            verified += 1
        else:
            mismatches.append(
                {
                    "observation_id": observation_id,
                    "expected": wanted,
                    "actual": actual,
                }
            )
    seen_ids: set[int] = set()
    for row in rows:
        try:
            seen_ids.add(int(row.get("observation_id") or 0))
        except (TypeError, ValueError):
            continue
    missing = sorted(set(expected) - seen_ids)
    return {
        "expected_rows": len(expected),
        "verified_rows": verified,
        "missing_observation_ids": missing,
        "mismatch_count": len(mismatches),
        "mismatch_sample": mismatches[:20],
        "ok": verified == len(expected) and not missing and not mismatches,
    }


__all__ = [
    "DYNAMIC_DOMAIN_NORMALIZATION_MIGRATION",
    "DomainNormalizationCandidate",
    "MIGRATION_ID",
    "SCHEMA_VERSION_AFTER",
    "apply_candidate_updates",
    "apply_dynamic_domain_normalization_schema",
    "build_candidates",
    "candidate_worklist_sha256",
    "load_observation_rows",
    "migration_already_applied",
    "normalization_columns_available",
    "normalization_index_available",
    "normalization_schema_posture",
    "summarize_candidates",
    "verify_candidates",
]
