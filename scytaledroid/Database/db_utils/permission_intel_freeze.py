"""Freeze duplicate permission-intel managed tables in the operational DB."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from scytaledroid.Database.db_core import permission_intel as intel_db
from scytaledroid.Database.db_core.session import database_session


@dataclass(slots=True)
class FrozenManagedTable:
    table: str
    archived_as: str
    row_count: int


@dataclass(slots=True)
class PermissionIntelFreezeOutcome:
    frozen: list[FrozenManagedTable]
    missing: list[str]
    skipped: list[str]

    def as_lines(self) -> Iterable[str]:
        if self.frozen:
            yield "Frozen tables: " + ", ".join(
                f"{item.table}->{item.archived_as} ({item.row_count})" for item in self.frozen
            )
        if self.missing:
            yield "Already absent: " + ", ".join(self.missing)
        if self.skipped:
            yield "Skipped: " + ", ".join(self.skipped)


@dataclass(slots=True)
class PermissionIntelDropOutcome:
    dropped: list[str]
    missing: list[str]
    skipped: list[str]

    def as_lines(self) -> Iterable[str]:
        if self.dropped:
            yield "Dropped archived tables: " + ", ".join(self.dropped)
        if self.missing:
            yield "Already absent: " + ", ".join(self.missing)
        if self.skipped:
            yield "Skipped due to live references: " + ", ".join(self.skipped)


@dataclass(slots=True)
class GovernanceLegacyDetachOutcome:
    dropped_constraints: list[str]
    missing_constraints: list[str]

    def as_lines(self) -> Iterable[str]:
        if self.dropped_constraints:
            yield "Dropped legacy governance FKs: " + ", ".join(self.dropped_constraints)
        if self.missing_constraints:
            yield "Already absent: " + ", ".join(self.missing_constraints)


def _archive_name(table: str, stamp: str) -> str:
    candidate = f"{table}__legacy_{stamp}"
    if len(candidate) <= 64:
        return candidate
    overflow = len(candidate) - 64
    trimmed = table[:-overflow] if overflow < len(table) else table[:8]
    return f"{trimmed}__legacy_{stamp}"


def list_operational_managed_tables() -> list[dict[str, object]]:
    """Return presence and row-count info for managed tables in the operational DB."""

    rows: list[dict[str, object]] = []
    with database_session(reuse_connection=False) as engine:
        for table in intel_db.MANAGED_TABLES:
            exists_row = engine.fetch_one(
                """
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = DATABASE()
                  AND table_name = %s
                """,
                (table,),
                query_name="permission_intel.inventory.exists",
                context={"table": table},
            )
            exists = bool(exists_row and int(exists_row[0] or 0) > 0)
            row_count = None
            if exists:
                count_row = engine.fetch_one(
                    f"SELECT COUNT(*) FROM `{table}`",
                    query_name="permission_intel.inventory.row_count",
                    context={"table": table},
                )
                row_count = int(count_row[0] or 0) if count_row else 0
            rows.append(
                {
                    "table": table,
                    "exists": exists,
                    "row_count": row_count,
                }
            )
    return rows


def _archived_drop_order(engine, archived_tables: list[str]) -> list[str]:
    remaining = list(dict.fromkeys(archived_tables))
    if not remaining:
        return []

    deps: dict[str, set[str]] = {name: set() for name in remaining}
    placeholders = ", ".join(["%s"] * len(remaining))
    rows = engine.fetch_all(
        f"""
        SELECT table_name, referenced_table_name
        FROM information_schema.key_column_usage
        WHERE table_schema = DATABASE()
          AND table_name IN ({placeholders})
          AND referenced_table_name IN ({placeholders})
          AND referenced_table_name IS NOT NULL
        """,
        tuple(remaining + remaining),
        query_name="permission_intel.drop_archive.dependencies",
        context={"table_count": len(remaining)},
    ) or []

    for row in rows:
        child = str(row[0] or "")
        parent = str(row[1] or "")
        if child and parent and child in deps:
            deps[child].add(parent)

    creation_order: list[str] = []
    remaining_set = set(remaining)
    while remaining_set:
        ready = sorted(name for name in remaining_set if not (deps.get(name, set()) & remaining_set))
        if not ready:
            creation_order.extend(sorted(remaining_set))
            break
        creation_order.extend(ready)
        for name in ready:
            remaining_set.remove(name)
    return list(reversed(creation_order))


def _externally_referenced_archives(engine, archived_tables: list[str]) -> set[str]:
    if not archived_tables:
        return set()
    placeholders = ", ".join(["%s"] * len(archived_tables))
    rows = engine.fetch_all(
        f"""
        SELECT DISTINCT referenced_table_name
        FROM information_schema.key_column_usage
        WHERE table_schema = DATABASE()
          AND referenced_table_name IN ({placeholders})
          AND referenced_table_name IS NOT NULL
          AND table_name NOT IN ({placeholders})
        """,
        tuple(archived_tables + archived_tables),
        query_name="permission_intel.drop_archive.external_refs",
        context={"table_count": len(archived_tables)},
    ) or []
    return {str(row[0] or "") for row in rows if row and row[0]}


def detach_legacy_governance_snapshot_dependencies() -> GovernanceLegacyDetachOutcome:
    """Drop live FK constraints that still point at archived governance snapshots.

    The live tables keep governance_version/governance_sha256 lineage fields, but
    should no longer enforce a foreign-key dependency on the archived local copy
    once the dedicated permission-intel DB is authoritative.
    """

    targets = (
        ("permission_signal_observations", "fk_sig_gov_version"),
        ("static_correlation_results", "fk_corr_gov_version"),
    )
    dropped: list[str] = []
    missing: list[str] = []

    with database_session(reuse_connection=False) as engine:
        for table, constraint in targets:
            exists_row = engine.fetch_one(
                """
                SELECT COUNT(*)
                FROM information_schema.table_constraints
                WHERE table_schema = DATABASE()
                  AND table_name = %s
                  AND constraint_name = %s
                  AND constraint_type = 'FOREIGN KEY'
                """,
                (table, constraint),
                query_name="permission_intel.detach_legacy_fk.exists",
                context={"table": table, "constraint": constraint},
            )
            if not exists_row or int(exists_row[0] or 0) == 0:
                missing.append(f"{table}.{constraint}")
                continue
            engine.execute(
                f"ALTER TABLE `{table}` DROP FOREIGN KEY `{constraint}`",
                query_name="permission_intel.detach_legacy_fk.drop",
                context={"table": table, "constraint": constraint},
            )
            dropped.append(f"{table}.{constraint}")

    return GovernanceLegacyDetachOutcome(
        dropped_constraints=dropped,
        missing_constraints=missing,
    )


def freeze_operational_managed_tables(*, stamp: str | None = None) -> PermissionIntelFreezeOutcome:
    """Rename duplicate managed tables out of the operational DB schema.

    The dedicated permission-intel target must be active before freezing.
    """

    target = intel_db.describe_target()
    if target.get("compatibility_mode"):
        raise RuntimeError("Permission-intel cutover is not active; refusing to freeze operational tables.")

    missing_in_target = [table for table in intel_db.MANAGED_TABLES if not intel_db.intel_table_exists(table)]
    if missing_in_target:
        raise RuntimeError(
            "Dedicated permission-intel DB is incomplete; refusing to freeze operational tables: "
            + ", ".join(missing_in_target)
        )

    suffix = (stamp or datetime.now(UTC).strftime("%Y%m%d")).strip()
    frozen: list[FrozenManagedTable] = []
    missing: list[str] = []
    skipped: list[str] = []

    with database_session(reuse_connection=False) as engine:
        for info in list_operational_managed_tables():
            table = str(info["table"])
            exists = bool(info["exists"])
            if not exists:
                missing.append(table)
                continue

            archived_as = _archive_name(table, suffix)
            archived_exists_row = engine.fetch_one(
                """
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = DATABASE()
                  AND table_name = %s
                """,
                (archived_as,),
                query_name="permission_intel.freeze.archive_exists",
                context={"table": table, "archived_as": archived_as},
            )
            if archived_exists_row and int(archived_exists_row[0] or 0) > 0:
                skipped.append(table)
                continue

            row_count = int(info["row_count"] or 0)
            engine.execute(
                f"RENAME TABLE `{table}` TO `{archived_as}`",
                query_name="permission_intel.freeze.rename",
                context={"table": table, "archived_as": archived_as},
            )
            frozen.append(
                FrozenManagedTable(
                    table=table,
                    archived_as=archived_as,
                    row_count=row_count,
                )
            )

    return PermissionIntelFreezeOutcome(frozen=frozen, missing=missing, skipped=skipped)


def drop_archived_operational_managed_tables(*, stamp: str) -> PermissionIntelDropOutcome:
    """Drop previously archived operational copies of managed permission-intel tables."""

    suffix = stamp.strip()
    if not suffix:
        raise RuntimeError("Archive stamp is required.")

    dropped: list[str] = []
    missing: list[str] = []
    skipped: list[str] = []

    archived_names = [_archive_name(table, suffix) for table in intel_db.MANAGED_TABLES]

    with database_session(reuse_connection=False) as engine:
        blocked = _externally_referenced_archives(engine, archived_names)
        for archived_as in _archived_drop_order(engine, archived_names):
            exists_row = engine.fetch_one(
                """
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = DATABASE()
                  AND table_name = %s
                """,
                (archived_as,),
                query_name="permission_intel.drop_archive.exists",
                context={"archived_as": archived_as},
            )
            if not exists_row or int(exists_row[0] or 0) == 0:
                missing.append(archived_as)
                continue
            if archived_as in blocked:
                skipped.append(archived_as)
                continue
            engine.execute(
                f"DROP TABLE `{archived_as}`",
                query_name="permission_intel.drop_archive.drop",
                context={"archived_as": archived_as},
            )
            dropped.append(archived_as)

    return PermissionIntelDropOutcome(dropped=dropped, missing=missing, skipped=skipped)


__all__ = [
    "FrozenManagedTable",
    "GovernanceLegacyDetachOutcome",
    "PermissionIntelDropOutcome",
    "detach_legacy_governance_snapshot_dependencies",
    "PermissionIntelFreezeOutcome",
    "drop_archived_operational_managed_tables",
    "freeze_operational_managed_tables",
    "list_operational_managed_tables",
]
