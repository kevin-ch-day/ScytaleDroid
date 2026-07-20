"""Minimal environment-file loading shared by runtime configuration modules."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_ENV_FILE = _REPO_ROOT / ".env"
_ENV_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def load_dotenv(*, env_path: Path | None = None, allow_in_tests: bool = False) -> bool:
    """Load simple ``KEY=VALUE`` entries without overriding process environment.

    The project deliberately avoids shell-sourcing ``.env`` files: they can
    contain passwords and should not be evaluated as shell code. Test imports
    remain isolated unless a test explicitly opts in.
    """

    if os.environ.get("SCYTALEDROID_NO_DOTENV") == "1":
        return False
    if not allow_in_tests and (
        "PYTEST_CURRENT_TEST" in os.environ or any("pytest" in arg for arg in sys.argv[:1])
    ):
        return False

    path = Path(env_path or os.environ.get("SCYTALEDROID_ENV_FILE") or _DEFAULT_ENV_FILE)
    if not path.exists():
        return False

    loaded_any = False
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if _ENV_KEY_PATTERN.fullmatch(key) and key not in os.environ:
                os.environ[key] = value
                loaded_any = True
    except OSError:
        return False
    return loaded_any


def resolve_workspace_path(value: str | Path, *, repo_root: Path | None = None) -> Path:
    """Resolve a configured workspace path relative to the repository when needed."""

    candidate = Path(value).expanduser()
    return candidate if candidate.is_absolute() else (repo_root or _REPO_ROOT) / candidate


__all__ = ["load_dotenv", "resolve_workspace_path"]
