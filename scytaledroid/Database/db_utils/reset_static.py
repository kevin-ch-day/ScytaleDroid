"""Helpers for resetting static-analysis persistence tables."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple

from scytaledroid.Database.db_core import database_session
from scytaledroid.Database.db_core.db_engine import DatabaseEngine

PROTECTED_TABLES: Sequence[str] = (
    "android_app_categories",
    "apps",
    "android_framework_permissions",
    "android_perm_map",
    "android_perm_override",
    "perm_groups",
    "android_unknown_permissions",
    "android_vendor_permissions",
)

STATIC_ANALYSIS_TABLES: Sequence[str] = (
    # Static analysis result tables
    "static_string_samples",
    "static_string_summary",
    "static_provider_acl",
    "static_fileproviders",
    "static_findings",
    "static_findings_summary",
    "static_permission_risk",
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
    "android_detected_permissions",
    "harvest_artifact_paths",
    "harvest_source_paths",
    "android_apk_repository",
    "apk_split_groups",
    "harvest_storage_roots",
)


@dataclass(slots=True)
class ResetOutcome:
    truncated: List[str]
    cleared: List[str]
    skipped_protected: List[str]
    skipped_missing: List[str]
    failed: List[tuple[str, str]]

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
) -> ResetOutcome:
    """Truncate dynamic static-analysis tables, preserving protected catalogs."""

    exclusions = set(PROTECTED_TABLES)
    if extra_exclusions:
        exclusions.update(extra_exclusions)

    candidate_tables: List[str] = list(STATIC_ANALYSIS_TABLES)
    if include_harvest:
        candidate_tables.extend(HARVEST_TABLES)

    # Preserve original ordering while removing duplicates
    seen: set[str] = set()
    ordered_candidates: List[str] = []
    for table in candidate_tables:
        if table in seen:
            continue
        ordered_candidates.append(table)
        seen.add(table)

    protected = [table for table in ordered_candidates if table in exclusions]
    to_truncate = [table for table in ordered_candidates if table not in exclusions]

    truncated: List[str] = []
    cleared: List[str] = []
    skipped_missing: List[str] = []
    failed: List[tuple[str, str]] = []

    with database_session(reuse_connection=False) as engine:
        foreign_key_reset_error: Tuple[str, str] | None = None
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


def _table_exists(engine: DatabaseEngine, table: str) -> bool:
    try:
        result = engine.fetch_one("SHOW TABLES LIKE %s", (table,))
    except RuntimeError:  # pragma: no cover - unlikely
        return False
    return bool(result)


__all__ = [
    "reset_static_analysis_data",
    "ResetOutcome",
    "PROTECTED_TABLES",
    "STATIC_ANALYSIS_TABLES",
    "HARVEST_TABLES",
]
