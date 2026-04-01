"""Helpers for resetting static-analysis persistence tables."""

from __future__ import annotations

import shutil
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Database.db_core import database_session
from scytaledroid.Database.db_core.db_engine import DatabaseEngine

PROTECTED_TABLES: Sequence[str] = (
    "android_app_categories",
    "apps",
    "perm_groups",
    "android_permission_dict_aosp",
    "android_permission_dict_oem",
    "android_permission_dict_queue",
    "android_permission_dict_unknown",
    "android_permission_meta_oem_prefix",
    "android_permission_meta_oem_vendor",
    "permission_signal_catalog",
    "permission_signal_mappings",
    "permission_cohort_expectations",
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
    "static_permission_risk",
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
    "correlations",
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


__all__ = [
    "reset_static_analysis_data",
    "reset_all_analysis_data",
    "ResetOutcome",
    "PROTECTED_TABLES",
    "STATIC_ANALYSIS_TABLES",
    "HARVEST_TABLES",
]
