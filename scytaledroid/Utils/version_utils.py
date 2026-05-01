"""Version helpers for reproducibility metadata."""

from __future__ import annotations

import os
import subprocess
from functools import lru_cache


@lru_cache(maxsize=1)
def get_git_commit() -> str:
    """Return the current git commit hash (short), or a safe fallback."""
    env_commit = os.getenv("SCYTALEDROID_GIT_COMMIT")
    if env_commit:
        return env_commit.strip()
    try:
        output = subprocess.check_output(
            ["git", "rev-parse", "--short=12", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        commit = output.strip()
        if commit:
            return commit
    except Exception:
        pass
    return "<unknown>"


__all__ = ["get_git_commit"]
