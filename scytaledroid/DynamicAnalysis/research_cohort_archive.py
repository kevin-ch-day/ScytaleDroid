"""Cohort-aware archive paths for dynamic tracker and freeze artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scytaledroid.Config import app_config
from scytaledroid.DynamicAnalysis.research_cohort_runtime import active_research_cohort_key
from scytaledroid.Utils.IO.atomic_write import atomic_write_text


def legacy_archive_dir() -> Path:
    return Path(app_config.DATA_DIR) / "archive"


def legacy_dataset_plan_path() -> Path:
    return legacy_archive_dir() / "dataset_plan.json"


def legacy_dataset_freeze_path() -> Path:
    return legacy_archive_dir() / "dataset_freeze.json"


def active_research_cohort_archive_dir(*, cohort_key: str | None = None) -> Path:
    key = str(cohort_key or active_research_cohort_key() or "").strip().lower()
    if not key:
        return legacy_archive_dir()
    return legacy_archive_dir() / "research_cohorts" / key


def active_dataset_plan_path(*, cohort_key: str | None = None) -> Path:
    return active_research_cohort_archive_dir(cohort_key=cohort_key) / "dataset_plan.json"


def active_dataset_freeze_path(*, cohort_key: str | None = None) -> Path:
    return active_research_cohort_archive_dir(cohort_key=cohort_key) / "dataset_freeze.json"


def resolve_dataset_plan_read_path(*, cohort_key: str | None = None) -> Path:
    active = active_dataset_plan_path(cohort_key=cohort_key)
    if active.exists():
        return active
    return legacy_dataset_plan_path()


def resolve_dataset_freeze_read_path(*, cohort_key: str | None = None) -> Path:
    active = active_dataset_freeze_path(cohort_key=cohort_key)
    if active.exists():
        return active
    return legacy_dataset_freeze_path()


def write_dataset_plan_payload(payload: dict[str, Any], *, cohort_key: str | None = None) -> Path:
    primary = active_dataset_plan_path(cohort_key=cohort_key)
    legacy = legacy_dataset_plan_path()
    primary.parent.mkdir(parents=True, exist_ok=True)
    legacy.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    atomic_write_text(primary, text)
    if primary.resolve() != legacy.resolve():
        atomic_write_text(legacy, text)
    return primary


def write_dataset_freeze_payload(payload: dict[str, Any], *, cohort_key: str | None = None) -> Path:
    primary = active_dataset_freeze_path(cohort_key=cohort_key)
    legacy = legacy_dataset_freeze_path()
    primary.parent.mkdir(parents=True, exist_ok=True)
    legacy.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True)
    primary.write_text(text, encoding="utf-8")
    if primary.resolve() != legacy.resolve():
        legacy.write_text(text, encoding="utf-8")
    return primary


__all__ = [
    "active_dataset_freeze_path",
    "active_dataset_plan_path",
    "active_research_cohort_archive_dir",
    "legacy_archive_dir",
    "legacy_dataset_freeze_path",
    "legacy_dataset_plan_path",
    "resolve_dataset_freeze_read_path",
    "resolve_dataset_plan_read_path",
    "write_dataset_freeze_payload",
    "write_dataset_plan_payload",
]
