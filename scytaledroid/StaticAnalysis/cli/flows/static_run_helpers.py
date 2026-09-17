"""Small static-run utilities (cache purge and module list) used by scan dispatch."""

from __future__ import annotations

import shutil
from pathlib import Path

from scytaledroid.Config import app_config

from ..core.analysis_profiles import run_modules_for_profile
from ..core.models import RunParameters


def modules_for_run(params: RunParameters) -> tuple[str, ...]:
    return run_modules_for_profile(params.profile)


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
