"""Small static-run utilities (worker count, cache purge, module list) used by scan dispatch."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from scytaledroid.Config import app_config

from ..core.analysis_profiles import run_modules_for_profile
from ..core.models import RunParameters


def modules_for_run(params: RunParameters) -> tuple[str, ...]:
    return run_modules_for_profile(params.profile)


def resolve_workers(value: str | int) -> int:
    if isinstance(value, int):
        return max(1, value)
    text = (value or "").strip().lower()
    if text.isdigit():
        return max(1, int(text))
    return max(1, os.cpu_count() or 1)


def purge_run_cache() -> None:
    cache_roots = [
        Path(app_config.DATA_DIR) / "static_analysis" / "cache",
        Path(app_config.DATA_DIR) / "static_analysis" / "tmp",
    ]
    for root in cache_roots:
        try:
            if root.exists():
                shutil.rmtree(root)
        except OSError:
            continue
