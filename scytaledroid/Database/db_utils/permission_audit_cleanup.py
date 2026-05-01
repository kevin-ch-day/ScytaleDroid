"""Maintenance helpers for permission-audit snapshot integrity."""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime

from scytaledroid.Database.db_core import database_session
from scytaledroid.StaticAnalysis.risk.permission import permission_risk_grade


@dataclass(slots=True)
class PermissionAuditCleanupOutcome:
    updated_totals: int = 0
    updated_lineage: int = 0
    clamped_negative_scores: int = 0
    deleted_empty_snapshots: int = 0

    def as_lines(self) -> Iterable[str]:
        yield (
            "Permission-audit cleanup:"
            f" totals={self.updated_totals}"
            f" lineage={self.updated_lineage}"
            f" clamped_scores={self.clamped_negative_scores}"
            f" deleted_empty_snapshots={self.deleted_empty_snapshots}"
        )


@dataclass(slots=True)
class PermissionAuditSnapshotIssue:
    snapshot_id: int
    snapshot_key: str
    scope_label: str | None
    apps_total: int
    child_rows: int
    distinct_static_run_ids: int
    distinct_run_ids: int
    min_static_run_id: int | None
    max_static_run_id: int | None
    created_at: str | None

    @property
    def is_empty(self) -> bool:
        return self.child_rows <= 0

    @property
    def has_single_static_run_id(self) -> bool:
        return self.distinct_static_run_ids == 1 and self.min_static_run_id is not None

    @property
    def has_single_run_id(self) -> bool:
        return self.distinct_run_ids == 1


def extract_session_label_from_snapshot_key(snapshot_key: str | None) -> str | None:
    key = str(snapshot_key or "").strip()
    if not key:
        return None
    prefix = "perm-audit:app:"
    if key.startswith(prefix):
        return key[len(prefix) :]
    return None


def list_permission_audit_snapshot_issues() -> list[PermissionAuditSnapshotIssue]:
    with database_session(reuse_connection=False) as engine:
        rows = engine.fetch_all(
            """
            SELECT
              s.snapshot_id,
              s.snapshot_key,
              s.scope_label,
              COALESCE(s.apps_total, 0) AS apps_total,
              COUNT(a.audit_id) AS child_rows,
              COUNT(DISTINCT a.static_run_id) AS distinct_static_run_ids,
              COUNT(DISTINCT a.run_id) AS distinct_run_ids,
              MIN(a.static_run_id) AS min_static_run_id,
              MAX(a.static_run_id) AS max_static_run_id,
              MAX(s.created_at) AS created_at
            FROM permission_audit_snapshots s
            LEFT JOIN permission_audit_apps a ON a.snapshot_id = s.snapshot_id
            GROUP BY s.snapshot_id, s.snapshot_key, s.scope_label, s.apps_total
            ORDER BY MAX(s.created_at) DESC
            """
        )
    issues: list[PermissionAuditSnapshotIssue] = []
    for row in rows or []:
        if not row:
            continue
        issues.append(
            PermissionAuditSnapshotIssue(
                snapshot_id=int(row[0]),
                snapshot_key=str(row[1] or ""),
                scope_label=str(row[2]) if row[2] is not None else None,
                apps_total=int(row[3] or 0),
                child_rows=int(row[4] or 0),
                distinct_static_run_ids=int(row[5] or 0),
                distinct_run_ids=int(row[6] or 0),
                min_static_run_id=int(row[7]) if row[7] is not None else None,
                max_static_run_id=int(row[8]) if row[8] is not None else None,
                created_at=str(row[9]) if row[9] is not None else None,
            )
        )
    return issues


def repair_permission_audit_snapshot_totals(*, dry_run: bool = False) -> int:
    issues = list_permission_audit_snapshot_issues()
    targets = [issue for issue in issues if issue.apps_total != issue.child_rows]
    if dry_run or not targets:
        return len(targets)
    updated = 0
    with database_session(reuse_connection=False) as engine:
        for issue in targets:
            engine.execute(
                """
                UPDATE permission_audit_snapshots
                SET apps_total=%s
                WHERE snapshot_id=%s
                """,
                (issue.child_rows, issue.snapshot_id),
            )
            updated += 1
    return updated


def repair_permission_audit_snapshot_lineage(*, dry_run: bool = False) -> int:
    issues = list_permission_audit_snapshot_issues()
    updated = 0
    with database_session(reuse_connection=False) as engine:
        for issue in issues:
            if not issue.has_single_static_run_id:
                continue
            row = engine.fetch_one(
                """
                SELECT static_run_id, run_id
                FROM permission_audit_snapshots
                WHERE snapshot_id=%s
                """,
                (issue.snapshot_id,),
            )
            if not row:
                continue
            current_static = int(row[0]) if row[0] is not None else None
            current_run = int(row[1]) if row[1] is not None else None
            target_static = issue.min_static_run_id
            target_run = current_run
            if issue.has_single_run_id:
                with suppress(Exception):
                    run_row = engine.fetch_one(
                        """
                        SELECT MIN(run_id)
                        FROM permission_audit_apps
                        WHERE snapshot_id=%s
                        """,
                        (issue.snapshot_id,),
                    )
                    if run_row and run_row[0] is not None:
                        target_run = int(run_row[0])
            if current_static == target_static and current_run == target_run:
                continue
            if dry_run:
                updated += 1
                continue
            engine.execute(
                """
                UPDATE permission_audit_snapshots
                SET static_run_id=%s, run_id=%s
                WHERE snapshot_id=%s
                """,
                (target_static, target_run, issue.snapshot_id),
            )
            updated += 1
    return updated


def clamp_negative_permission_audit_scores(*, dry_run: bool = False) -> int:
    updated = 0
    with database_session(reuse_connection=False) as engine:
        rows = engine.fetch_all(
            """
            SELECT audit_id, score_raw, score_capped
            FROM permission_audit_apps
            WHERE score_capped < 0
            ORDER BY audit_id
            """
        )
        for row in rows or []:
            audit_id = int(row[0])
            score_raw = max(0.0, float(row[1] or 0.0))
            score_capped = max(0.0, float(row[2] or 0.0))
            target_score = max(score_raw, score_capped)
            target_grade = permission_risk_grade(target_score)
            if dry_run:
                updated += 1
                continue
            engine.execute(
                """
                UPDATE permission_audit_apps
                SET score_raw=%s,
                    score_capped=%s,
                    grade=%s
                WHERE audit_id=%s
                """,
                (target_score, target_score, target_grade, audit_id),
            )
            updated += 1
    return updated


def delete_empty_permission_audit_snapshots(
    *,
    older_than: datetime | None = None,
    dry_run: bool = False,
) -> int:
    issues = list_permission_audit_snapshot_issues()
    updated = 0
    with database_session(reuse_connection=False) as engine:
        for issue in issues:
            if not issue.is_empty:
                continue
            row = engine.fetch_one(
                """
                SELECT run_id, static_run_id, created_at
                FROM permission_audit_snapshots
                WHERE snapshot_id=%s
                """,
                (issue.snapshot_id,),
            )
            if not row:
                continue
            run_id = row[0]
            static_run_id = row[1]
            created_at = row[2]
            if run_id is not None or static_run_id is not None:
                continue
            if older_than is not None and created_at is not None:
                created_dt = created_at if isinstance(created_at, datetime) else None
                if created_dt is None:
                    with suppress(Exception):
                        created_dt = datetime.fromisoformat(str(created_at).replace("Z", ""))
                if created_dt is not None and created_dt >= older_than:
                    continue
            if dry_run:
                updated += 1
                continue
            engine.execute(
                "DELETE FROM permission_audit_snapshots WHERE snapshot_id=%s",
                (issue.snapshot_id,),
            )
            updated += 1
    return updated


def repair_permission_audit_integrity(
    *,
    older_than_for_empty_delete: datetime | None = None,
    dry_run: bool = False,
) -> PermissionAuditCleanupOutcome:
    return PermissionAuditCleanupOutcome(
        updated_totals=repair_permission_audit_snapshot_totals(dry_run=dry_run),
        updated_lineage=repair_permission_audit_snapshot_lineage(dry_run=dry_run),
        clamped_negative_scores=clamp_negative_permission_audit_scores(dry_run=dry_run),
        deleted_empty_snapshots=delete_empty_permission_audit_snapshots(
            older_than=older_than_for_empty_delete,
            dry_run=dry_run,
        ),
    )


__all__ = [
    "PermissionAuditCleanupOutcome",
    "PermissionAuditSnapshotIssue",
    "clamp_negative_permission_audit_scores",
    "delete_empty_permission_audit_snapshots",
    "extract_session_label_from_snapshot_key",
    "list_permission_audit_snapshot_issues",
    "repair_permission_audit_integrity",
    "repair_permission_audit_snapshot_lineage",
    "repair_permission_audit_snapshot_totals",
]
