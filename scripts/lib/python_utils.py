"""Utilities shared across Python maintenance scripts."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable, Union

PathLike = Union[str, Path]


def prepend_to_sys_path(paths: Iterable[PathLike]) -> None:
    """Prepend paths to ``sys.path`` if they are not already present."""
    for path in paths:
        resolved = Path(path).resolve()
        resolved_str = str(resolved)
        if resolved_str not in sys.path:
            sys.path.insert(0, resolved_str)


def ensure_repo_root_on_path(anchor: PathLike, levels: int = 1) -> Path:
    """Ensure the repository root relative to *anchor* is on ``sys.path``."""
    anchor_path = Path(anchor).resolve()
    try:
        repo_root = anchor_path.parents[levels]
    except IndexError as exc:  # pragma: no cover - defensive programming
        raise ValueError("levels points above filesystem root") from exc

    prepend_to_sys_path([repo_root])
    return repo_root
