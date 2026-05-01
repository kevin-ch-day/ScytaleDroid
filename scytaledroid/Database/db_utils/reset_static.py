"""Helpers for resetting static-analysis persistence tables."""

from __future__ import annotations

import shutil
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import database_session
from scytaledroid.Database.db_core.db_engine import DatabaseEngine

PROTECTED_TABLES: Sequence[str] = (
    "android_app_categories",
    "apps",
    "perm_groups",
    "schema_version",
    "db_ops_log",
)

STATIC_ANALYSIS_TABLES: Sequence[str] = (
    # Static analysis result tables
    "static_string_samples",
    "static_string_selected_samples",
    "static_string_sample_sets",
    "static_string_summary",
    "static_provider_acl",
    "static_fileproviders",
    "static_findings",
    "static_findings_summary",
    "static_analysis_findings",
    "static_permission_risk_vnext",
    "static_permission_matrix",
    "static_correlation_results",
    "masvs_control_coverage",
    "doc_hosts",
    # Linkage/ledger tables (resetting findings without these leaves confusing "orphan" runs)
    "static_session_rollups",
    "static_session_run_links",
    "static_analysis_runs",
    # Run-level persistence
    "metrics",
    "buckets",
    "contributors",
    "findings",
    "risk_scores",
    "permission_audit_snapshots",
    "permission_audit_apps",
    "runs",
    # Optional detector caches
)

HARVEST_TABLES: Sequence[str] = (
    "harvest_artifact_paths",
    "harvest_source_paths",
    "android_apk_repository",
    "apk_split_groups",
    "harvest_storage_roots",
)


@dataclass(slots=True)
class ResetOutcome:
    truncated: list[str]
    cleared: list[str]
    skipped_protected: list[str]
    skipped_missing: list[str]
    failed: list[tuple[str, str]]

    def as_lines(self) -> Iterable[str]:
        if self.truncated:
            yield f"Cleared via TRUNCATE ({len(self.truncated)}): {', '.join(self.truncated)}"
        if self.cleared:
            yield f"Cleared via DELETE ({len(self.cleared)}): {', '.join(self.cleared)}"
        if self.skipped_protected:
            yield f"Protected ({len(self.skipped_protected)}): {', '.join(self.skipped_protected)}"
        if self.skipped_missing:
            yield f"Not found ({len(self.skipped_missing)}): {', '.join(self.skipped_missing)}"
        if self.failed:
            formatted = ", ".join(f"{name} ({reason})" for name, reason in self.failed)
            yield f"Failed: {formatted}"


@dataclass(slots=True)
class ArtifactPurgeOutcome:
    removed: list[str]
    missing: list[str]
    failed: list[tuple[str, str]]

    def as_lines(self) -> Iterable[str]:
        if self.removed:
            yield f"Removed artifacts ({len(self.removed)}): {', '.join(self.removed)}"
        if self.missing:
            yield f"Not found ({len(self.missing)}): {', '.join(self.missing)}"
        if self.failed:
            formatted = ", ".join(f"{name} ({reason})" for name, reason in self.failed)
            yield f"Failed: {formatted}"


@dataclass(slots=True)
class StaticSessionCandidate:
    session_label: str
    latest_created_at: str | None
    runs_total: int
    canonical_runs: int
    session_type_key: str
    hidden_by_default: bool
    snapshot_apps_total: int | None = None
    snapshot_key: str | None = None


@dataclass(slots=True)
class SessionPruneOutcome:
    removed_sessions: list[str]
    skipped_sessions: list[str]
    failed_sessions: list[tuple[str, str]]
    removed_artifacts: list[str]
    missing_artifacts: list[str]

    def as_lines(self) -> Iterable[str]:
        if self.removed_sessions:
            yield f"Pruned sessions ({len(self.removed_sessions)}): {', '.join(self.removed_sessions)}"
        if self.skipped_sessions:
            yield f"Skipped sessions ({len(self.skipped_sessions)}): {', '.join(self.skipped_sessions)}"
        if self.removed_artifacts:
            yield f"Removed artifacts ({len(self.removed_artifacts)}): {', '.join(self.removed_artifacts)}"
        if self.missing_artifacts:
            yield f"Missing artifacts ({len(self.missing_artifacts)}): {', '.join(self.missing_artifacts)}"
        if self.failed_sessions:
            formatted = ", ".join(f"{name} ({reason})" for name, reason in self.failed_sessions)
            yield f"Failed: {formatted}"


@dataclass(slots=True)
class FailedStaticSessionCandidate:
    session_label: str
    failed_runs: int
    latest_created_at: str | None


def classify_static_session_type(session_label: str) -> tuple[str, bool]:
    label = str(session_label or "").strip().lower()
    if not label:
        return ("session", False)
    if "qa" in label or "debug" in label or "interrupt" in label:
        return ("qa", True)
    if "static-batch" in label:
        return ("qa", True)
    if "probe" in label:
        return ("qa", True)
    if "smoke" in label:
        return ("smoke", True)
    if "rerun" in label:
        return ("rerun", False)
    if "fast" in label:
        return ("fast", False)
    return ("full", False)


def reset_static_analysis_data(
    *,
    include_harvest: bool = False,
    extra_exclusions: Iterable[str] | None = None,
    session_label: str | None = None,
    truncate_all: bool = False,
) -> ResetOutcome:
    """Reset static-analysis tables.

    Default behavior is session-scoped deletion (non-destructive to historical runs).
    Set ``truncate_all=True`` for maintenance-level full table truncation.
    """

    if not truncate_all:
        return _reset_static_analysis_session_scoped(
            include_harvest=include_harvest,
            extra_exclusions=extra_exclusions,
            session_label=session_label,
        )

    exclusions = set(PROTECTED_TABLES)
    if extra_exclusions:
        exclusions.update(extra_exclusions)

    candidate_tables: list[str] = list(STATIC_ANALYSIS_TABLES)
    if include_harvest:
        candidate_tables.extend(HARVEST_TABLES)

    # Preserve original ordering while removing duplicates
    seen: set[str] = set()
    ordered_candidates: list[str] = []
    for table in candidate_tables:
        if table in seen:
            continue
        ordered_candidates.append(table)
        seen.add(table)

    protected = [table for table in ordered_candidates if table in exclusions]
    to_truncate = [table for table in ordered_candidates if table not in exclusions]

    truncated: list[str] = []
    cleared: list[str] = []
    skipped_missing: list[str] = []
    failed: list[tuple[str, str]] = []

    with database_session(reuse_connection=False) as engine:
        foreign_key_reset_error: tuple[str, str] | None = None
        try:
            engine.execute("SET FOREIGN_KEY_CHECKS=0")
        except RuntimeError as exc:  # pragma: no cover - defensive
            failed.append(("SET FOREIGN_KEY_CHECKS=0", str(exc)))
            foreign_key_reset_error = ("SET FOREIGN_KEY_CHECKS=0", str(exc))

        for table in to_truncate:
            if not _table_exists(engine, table):
                skipped_missing.append(table)
                continue
            try:
                engine.execute(f"TRUNCATE TABLE `{table}`")
                truncated.append(table)
            except RuntimeError as exc:  # pragma: no cover - requires specific DB state
                error_text = str(exc)
                if "command denied" in error_text.lower():
                    try:
                        engine.execute(f"DELETE FROM `{table}`")
                        cleared.append(table)
                        continue
                    except RuntimeError as delete_exc:  # pragma: no cover - requires specific DB state
                        failed.append((table, str(delete_exc)))
                        continue
                failed.append((table, error_text))

        try:
            engine.execute("SET FOREIGN_KEY_CHECKS=1")
        except RuntimeError as exc:  # pragma: no cover - defensive
            failed.append(("SET FOREIGN_KEY_CHECKS=1", str(exc)))
            foreign_key_reset_error = ("SET FOREIGN_KEY_CHECKS=1", str(exc))

        if foreign_key_reset_error and not failed:
            failed.append(foreign_key_reset_error)

    return ResetOutcome(
        truncated=truncated,
        cleared=cleared,
        skipped_protected=list(dict.fromkeys(protected)),
        skipped_missing=skipped_missing,
        failed=failed,
    )


def _column_exists(engine: DatabaseEngine, table: str, column: str) -> bool:
    try:
        row = engine.fetch_one(
            """
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = %s
              AND column_name = %s
            """,
            (table, column),
        )
        return bool(row and int(row[0] or 0) > 0)
    except RuntimeError:
        return False


def _reset_static_analysis_session_scoped(
    *,
    include_harvest: bool,
    extra_exclusions: Iterable[str] | None,
    session_label: str | None,
) -> ResetOutcome:
    exclusions = set(PROTECTED_TABLES)
    if extra_exclusions:
        exclusions.update(extra_exclusions)

    target_session = str(session_label or "").strip()
    if not target_session:
        # Safety-first default: if no session is supplied, do not wipe global history.
        return ResetOutcome(
            truncated=[],
            cleared=[],
            skipped_protected=[],
            skipped_missing=[],
            failed=[("session_scope", "session_label required for session-scoped reset")],
        )

    candidate_tables: list[str] = list(STATIC_ANALYSIS_TABLES)
    if include_harvest:
        candidate_tables.extend(HARVEST_TABLES)

    seen: set[str] = set()
    ordered_candidates: list[str] = []
    for table in candidate_tables:
        if table in seen or table in exclusions:
            continue
        ordered_candidates.append(table)
        seen.add(table)
    if "static_analysis_runs" in ordered_candidates:
        ordered_candidates = [t for t in ordered_candidates if t != "static_analysis_runs"] + ["static_analysis_runs"]

    cleared: list[str] = []
    skipped_missing: list[str] = []
    failed: list[tuple[str, str]] = []

    with database_session(reuse_connection=False) as engine:
        static_ids: list[int] = []
        try:
            rows = engine.fetch_all(
                "SELECT id FROM static_analysis_runs WHERE session_label=%s",
                (target_session,),
            )
            static_ids = [int(row[0]) for row in rows if row and row[0] is not None]
        except RuntimeError as exc:
            failed.append(("static_analysis_runs.lookup", str(exc)))

        try:
            _unlink_dynamic_static_links(engine, static_ids)
        except RuntimeError as exc:
            failed.append(("dynamic_sessions.unlink_static_run_id", str(exc)))

        # Delete by foreign keys first, then parent tables.
        for table in ordered_candidates:
            if not _table_exists(engine, table):
                skipped_missing.append(table)
                continue
            try:
                if table == "static_analysis_runs":
                    engine.execute(
                        "DELETE FROM static_analysis_runs WHERE session_label=%s",
                        (target_session,),
                    )
                    cleared.append(table)
                    continue
                if _column_exists(engine, table, "session_stamp"):
                    engine.execute(f"DELETE FROM `{table}` WHERE session_stamp=%s", (target_session,))
                    cleared.append(table)
                    continue
                if _column_exists(engine, table, "session_label"):
                    engine.execute(f"DELETE FROM `{table}` WHERE session_label=%s", (target_session,))
                    cleared.append(table)
                    continue
                if static_ids and _column_exists(engine, table, "static_run_id"):
                    placeholders = ",".join(["%s"] * len(static_ids))
                    engine.execute(
                        f"DELETE FROM `{table}` WHERE static_run_id IN ({placeholders})",
                        tuple(static_ids),
                    )
                    cleared.append(table)
                    continue
                if static_ids and _column_exists(engine, table, "run_id"):
                    placeholders = ",".join(["%s"] * len(static_ids))
                    engine.execute(
                        f"DELETE FROM `{table}` WHERE run_id IN ({placeholders})",
                        tuple(static_ids),
                    )
                    cleared.append(table)
                    continue
                # Keep table untouched when no safe session partition key exists.
            except RuntimeError as exc:
                failed.append((table, str(exc)))

        # runs table is linked via session_stamp and/or static_run_id.
        if _table_exists(engine, "runs"):
            try:
                if _column_exists(engine, "runs", "session_stamp"):
                    engine.execute("DELETE FROM runs WHERE session_stamp=%s", (target_session,))
                if static_ids and _column_exists(engine, "runs", "static_run_id"):
                    placeholders = ",".join(["%s"] * len(static_ids))
                    engine.execute(
                        f"DELETE FROM runs WHERE static_run_id IN ({placeholders})",
                        tuple(static_ids),
                    )
                if "runs" not in cleared:
                    cleared.append("runs")
            except RuntimeError as exc:
                failed.append(("runs", str(exc)))

    try:
        _clear_local_session_metadata(target_session)
    except OSError as exc:
        failed.append(("local_session_metadata", str(exc)))

    return ResetOutcome(
        truncated=[],
        cleared=cleared,
        skipped_protected=[],
        skipped_missing=skipped_missing,
        failed=failed,
    )


def _unlink_dynamic_static_links(engine: DatabaseEngine, static_ids: Sequence[int]) -> None:
    """Null out dynamic-session links before removing referenced static rows."""

    if not static_ids:
        return
    if not _table_exists(engine, "dynamic_sessions"):
        return
    if not _column_exists(engine, "dynamic_sessions", "static_run_id"):
        return

    placeholders = ",".join(["%s"] * len(static_ids))
    engine.execute(
        f"UPDATE dynamic_sessions SET static_run_id=NULL WHERE static_run_id IN ({placeholders})",
        tuple(static_ids),
    )


def reset_all_analysis_data(*, extra_exclusions: Iterable[str] | None = None) -> ResetOutcome:
    """Truncate all non-protected tables (static + dynamic + registry + harvest)."""

    exclusions = set(PROTECTED_TABLES)
    if extra_exclusions:
        exclusions.update(extra_exclusions)

    with database_session(reuse_connection=False) as engine:
        tables = []
        try:
            rows = engine.fetch_all("SHOW TABLES;")
            for row in rows or []:
                if isinstance(row, (list, tuple)) and row:
                    tables.append(str(row[0]))
        except RuntimeError:
            tables = []

    candidate_tables = [table for table in tables if table not in exclusions]
    truncated: list[str] = []
    cleared: list[str] = []
    skipped_missing: list[str] = []
    failed: list[tuple[str, str]] = []

    with database_session(reuse_connection=False) as engine:
        foreign_key_reset_error: tuple[str, str] | None = None
        try:
            engine.execute("SET FOREIGN_KEY_CHECKS=0")
        except RuntimeError as exc:  # pragma: no cover - defensive
            failed.append(("SET FOREIGN_KEY_CHECKS=0", str(exc)))
            foreign_key_reset_error = ("SET FOREIGN_KEY_CHECKS=0", str(exc))

        for table in candidate_tables:
            if not _table_exists(engine, table):
                skipped_missing.append(table)
                continue
            try:
                engine.execute(f"TRUNCATE TABLE `{table}`")
                truncated.append(table)
            except RuntimeError as exc:  # pragma: no cover - requires specific DB state
                error_text = str(exc)
                if "command denied" in error_text.lower():
                    try:
                        engine.execute(f"DELETE FROM `{table}`")
                        cleared.append(table)
                        continue
                    except RuntimeError as delete_exc:  # pragma: no cover - requires specific DB state
                        failed.append((table, str(delete_exc)))
                        continue
                failed.append((table, error_text))

        try:
            engine.execute("SET FOREIGN_KEY_CHECKS=1")
        except RuntimeError as exc:  # pragma: no cover - defensive
            failed.append(("SET FOREIGN_KEY_CHECKS=1", str(exc)))
            foreign_key_reset_error = ("SET FOREIGN_KEY_CHECKS=1", str(exc))

        if foreign_key_reset_error and not failed:
            failed.append(foreign_key_reset_error)

    return ResetOutcome(
        truncated=truncated,
        cleared=cleared,
        skipped_protected=list(dict.fromkeys(exclusions)),
        skipped_missing=skipped_missing,
        failed=failed,
    )


def _table_exists(engine: DatabaseEngine, table: str) -> bool:
    try:
        result = engine.fetch_one("SHOW TABLES LIKE %s", (table,))
    except RuntimeError:  # pragma: no cover - unlikely
        return False
    return bool(result)


def _clear_local_session_metadata(session_label: str) -> None:
    session_dir = Path(app_config.DATA_DIR) / "sessions" / str(session_label).strip()
    if not session_dir.exists():
        return
    if session_dir.is_file():
        session_dir.unlink()
        return
    shutil.rmtree(session_dir)


def purge_static_session_artifacts(session_label: str) -> ArtifactPurgeOutcome:
    """Delete session-scoped static artifacts so the session can be re-run cleanly."""

    target_session = str(session_label or "").strip()
    if not target_session:
        return ArtifactPurgeOutcome(
            removed=[],
            missing=[],
            failed=[("artifact_purge", "session_label required")],
        )

    static_ids: list[int] = []
    try:
        with database_session(reuse_connection=False) as engine:
            rows = engine.fetch_all(
                "SELECT id FROM static_analysis_runs WHERE session_label=%s",
                (target_session,),
            )
            static_ids = [int(row[0]) for row in rows if row and row[0] is not None]
    except RuntimeError:
        static_ids = []

    candidates: list[Path] = [
        Path(app_config.DATA_DIR) / "sessions" / target_session,
        Path(app_config.DATA_DIR) / "static_analysis" / "reports" / "archive" / target_session,
        Path(app_config.OUTPUT_DIR) / "audit" / "persistence" / f"{target_session}_persistence_audit.json",
        Path(app_config.OUTPUT_DIR) / "audit" / "persistence" / f"{target_session}_reconcile_audit.json",
        Path(app_config.OUTPUT_DIR) / "audit" / "selection" / f"{target_session}_selected_artifacts.json",
    ]
    for static_run_id in static_ids:
        candidates.append(Path("evidence") / "static_runs" / str(static_run_id))
        candidates.append(Path(app_config.OUTPUT_DIR) / "evidence" / "static_runs" / str(static_run_id))

    removed: list[str] = []
    missing: list[str] = []
    failed: list[tuple[str, str]] = []
    seen: set[Path] = set()
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        try:
            if not path.exists():
                missing.append(str(path))
                continue
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            removed.append(str(path))
        except OSError as exc:
            failed.append((str(path), str(exc)))

    return ArtifactPurgeOutcome(removed=removed, missing=missing, failed=failed)


def list_static_session_candidates(
    *,
    include_hidden_only: bool = False,
    older_than: datetime | None = None,
) -> list[StaticSessionCandidate]:
    candidates: list[StaticSessionCandidate] = []
    with database_session(reuse_connection=False) as engine:
        rows = engine.fetch_all(
            """
            SELECT
              sar.session_label,
              COUNT(*) AS runs_total,
              SUM(CASE WHEN COALESCE(sar.is_canonical, 0) = 1 THEN 1 ELSE 0 END) AS canonical_runs,
              MAX(sar.created_at) AS latest_created_at
            FROM static_analysis_runs sar
            GROUP BY sar.session_label
            ORDER BY latest_created_at DESC
            """
        )
        snapshot_rows = engine.fetch_all(
            """
            SELECT snapshot_key, apps_total, created_at
            FROM permission_audit_snapshots
            ORDER BY created_at DESC
            """
        )

    snapshot_map: dict[str, tuple[int | None, str]] = {}
    for row in snapshot_rows or []:
        if not row:
            continue
        snapshot_key = str(row[0] or "")
        if not snapshot_key.startswith("perm-audit:app:"):
            continue
        session_label = snapshot_key.removeprefix("perm-audit:app:")
        if session_label not in snapshot_map:
            apps_total = int(row[1]) if row[1] is not None else None
            snapshot_map[session_label] = (apps_total, snapshot_key)

    for row in rows or []:
        if not row or not row[0]:
            continue
        session_label = str(row[0])
        latest_created_at = str(row[3]) if row[3] is not None else None
        session_type_key, hidden_by_default = classify_static_session_type(session_label)
        if include_hidden_only and not hidden_by_default:
            continue
        if older_than is not None and latest_created_at:
            try:
                dt = datetime.fromisoformat(latest_created_at.replace("Z", ""))
            except ValueError:
                dt = None
            if dt is not None and dt >= older_than:
                continue
        snapshot_apps_total, snapshot_key = snapshot_map.get(session_label, (None, None))
        candidates.append(
            StaticSessionCandidate(
                session_label=session_label,
                latest_created_at=latest_created_at,
                runs_total=int(row[1] or 0),
                canonical_runs=int(row[2] or 0),
                session_type_key=session_type_key,
                hidden_by_default=hidden_by_default,
                snapshot_apps_total=snapshot_apps_total,
                snapshot_key=snapshot_key,
            )
        )
    return candidates


def prune_static_sessions(
    session_labels: Sequence[str],
    *,
    purge_artifacts: bool = True,
    include_harvest: bool = False,
) -> SessionPruneOutcome:
    removed_sessions: list[str] = []
    skipped_sessions: list[str] = []
    failed_sessions: list[tuple[str, str]] = []
    removed_artifacts: list[str] = []
    missing_artifacts: list[str] = []

    seen: set[str] = set()
    for raw_label in session_labels:
        session_label = str(raw_label or "").strip()
        if not session_label or session_label in seen:
            continue
        seen.add(session_label)

        outcome = reset_static_analysis_data(
            include_harvest=include_harvest,
            truncate_all=False,
            session_label=session_label,
        )
        if outcome.failed:
            failed_sessions.extend((session_label, reason) for _name, reason in outcome.failed)
            continue
        if not outcome.cleared and not outcome.truncated:
            skipped_sessions.append(session_label)
        else:
            removed_sessions.append(session_label)

        if purge_artifacts:
            artifact_outcome = purge_static_session_artifacts(session_label)
            removed_artifacts.extend(artifact_outcome.removed)
            missing_artifacts.extend(artifact_outcome.missing)
            failed_sessions.extend((session_label, reason) for _name, reason in artifact_outcome.failed)

    return SessionPruneOutcome(
        removed_sessions=removed_sessions,
        skipped_sessions=skipped_sessions,
        failed_sessions=failed_sessions,
        removed_artifacts=removed_artifacts,
        missing_artifacts=missing_artifacts,
    )


def list_failed_static_session_candidates(
    *,
    older_than: datetime | None = None,
) -> list[FailedStaticSessionCandidate]:
    candidates: list[FailedStaticSessionCandidate] = []
    with database_session(reuse_connection=False) as engine:
        rows = engine.fetch_all(
            """
            SELECT
              sar.session_label,
              SUM(CASE WHEN sar.status='FAILED' THEN 1 ELSE 0 END) AS failed_runs,
              SUM(CASE WHEN sar.status='COMPLETED' THEN 1 ELSE 0 END) AS completed_runs,
              SUM(CASE WHEN sar.status='STARTED' THEN 1 ELSE 0 END) AS started_runs,
              MAX(sar.created_at) AS latest_created_at
            FROM static_analysis_runs sar
            GROUP BY sar.session_label
            HAVING failed_runs > 0
               AND completed_runs = 0
               AND started_runs = 0
            ORDER BY latest_created_at DESC
            """
        )
    for row in rows or []:
        if not row or not row[0]:
            continue
        latest_created_at = str(row[4]) if row[4] is not None else None
        if older_than is not None and latest_created_at:
            try:
                dt = datetime.fromisoformat(latest_created_at.replace("Z", ""))
            except ValueError:
                dt = None
            if dt is not None and dt >= older_than:
                continue
        candidates.append(
            FailedStaticSessionCandidate(
                session_label=str(row[0]),
                failed_runs=int(row[1] or 0),
                latest_created_at=latest_created_at,
            )
        )
    return candidates


def prune_failed_static_sessions(
    *,
    older_than: datetime | None = None,
    purge_artifacts: bool = True,
    include_harvest: bool = False,
) -> SessionPruneOutcome:
    candidates = list_failed_static_session_candidates(older_than=older_than)
    return prune_static_sessions(
        [item.session_label for item in candidates],
        purge_artifacts=purge_artifacts,
        include_harvest=include_harvest,
    )


def prune_completed_static_sessions(
    *,
    keep_latest: int = 3,
    older_than: datetime | None = None,
    purge_artifacts: bool = True,
    include_harvest: bool = False,
    include_hidden: bool = False,
    protected_sessions: Sequence[str] | None = None,
) -> SessionPruneOutcome:
    """Prune older completed static sessions while preserving the newest labels.

    This is a retention helper for historical session debt, not a recovery path
    for stale partial sessions.
    """

    keep_latest = max(0, int(keep_latest))
    protected = {str(item or "").strip() for item in (protected_sessions or ()) if str(item or "").strip()}
    candidates = list_static_session_candidates(
        include_hidden_only=False,
        older_than=older_than,
    )

    eligible: list[StaticSessionCandidate] = []
    for row in candidates:
        if row.session_label in protected:
            continue
        if row.hidden_by_default and not include_hidden:
            continue
        if row.runs_total <= 0:
            continue
        if row.canonical_runs <= 0:
            continue
        eligible.append(row)

    eligible.sort(key=lambda item: item.latest_created_at or "", reverse=True)
    prune_labels = [row.session_label for row in eligible[keep_latest:]]
    return prune_static_sessions(
        prune_labels,
        purge_artifacts=purge_artifacts,
        include_harvest=include_harvest,
    )


__all__ = [
    "reset_static_analysis_data",
    "reset_all_analysis_data",
    "purge_static_session_artifacts",
    "list_static_session_candidates",
    "list_failed_static_session_candidates",
    "prune_static_sessions",
    "prune_failed_static_sessions",
    "prune_completed_static_sessions",
    "classify_static_session_type",
    "ArtifactPurgeOutcome",
    "FailedStaticSessionCandidate",
    "ResetOutcome",
    "SessionPruneOutcome",
    "StaticSessionCandidate",
    "PROTECTED_TABLES",
    "STATIC_ANALYSIS_TABLES",
    "HARVEST_TABLES",
]
