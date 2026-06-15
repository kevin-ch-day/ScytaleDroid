"""Runtime helpers for active research cohort UX and selection."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Config import app_config


def _selection_state_path() -> Path:
    return Path(app_config.DATA_DIR) / "state" / "dynamic_active_research_cohort.json"


def _read_selection_state() -> dict[str, object]:
    path = _selection_state_path()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def persisted_active_research_cohort_key() -> str | None:
    try:
        from scytaledroid.Database.db_func.research_cohorts import normalize_research_cohort_key

        return normalize_research_cohort_key(_read_selection_state().get("cohort_key"))
    except Exception:
        return None


def active_research_cohort_context(preferred_key: str | None = None) -> dict[str, object]:
    try:
        from scytaledroid.Database.db_func.research_cohorts import resolve_research_cohort_context

        preferred = preferred_key or persisted_active_research_cohort_key()
        context = resolve_research_cohort_context(preferred)
    except Exception:
        context = {}
    return dict(context) if isinstance(context, dict) else {}


def active_research_cohort_label(preferred_key: str | None = None) -> str:
    context = active_research_cohort_context(preferred_key)
    label = str(context.get("display_name") or "").strip()
    return label or "Research cohort"


def active_research_cohort_packages(preferred_key: str | None = None) -> tuple[str, ...]:
    context = active_research_cohort_context(preferred_key)
    packages = context.get("packages")
    if not isinstance(packages, (tuple, list)):
        return tuple()
    return tuple(
        str(package).strip().lower()
        for package in packages
        if str(package).strip()
    )


def active_research_cohort_key(preferred_key: str | None = None) -> str | None:
    context = active_research_cohort_context(preferred_key)
    key = str(context.get("cohort_key") or "").strip().lower()
    return key or None


def chooseable_active_research_cohorts() -> list[dict[str, object]]:
    try:
        from scytaledroid.Database.db_func.research_cohorts import list_active_research_cohorts

        rows = list_active_research_cohorts()
    except Exception:
        rows = []
    return [dict(row) for row in rows if isinstance(row, dict)]


def persist_active_research_cohort_key(cohort_key: str, *, label: str | None = None) -> Path:
    path = _selection_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "cohort_key": str(cohort_key or "").strip().lower(),
        "display_name": str(label or "").strip() or None,
        "saved_at_utc": datetime.now(UTC).isoformat(),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


__all__ = [
    "active_research_cohort_context",
    "active_research_cohort_key",
    "active_research_cohort_label",
    "active_research_cohort_packages",
    "chooseable_active_research_cohorts",
    "persist_active_research_cohort_key",
    "persisted_active_research_cohort_key",
]
