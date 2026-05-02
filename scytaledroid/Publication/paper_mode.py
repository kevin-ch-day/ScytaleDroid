"""Shared helpers for paper/demo strict-mode execution.

The project has multiple entrypoints (TUI + scripts). Historically, "strict" was
propagated via scattered environment reads. This module provides a small, stable
mode-carrier that scripts can use to keep receipts and behavior consistent.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

TRUTHY = {"1", "true", "yes", "on", "y"}


def truthy_env(name: str, *, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() in TRUTHY


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git_commit(repo_root: Path) -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=str(repo_root),
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return out or "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def git_dirty(repo_root: Path) -> bool:
    try:
        out = subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=str(repo_root),
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return bool(out.strip())
    except Exception:
        return False


def minima_source_hashes(repo_root: Path) -> dict[str, str]:
    """Hash the Python sources that define paper-grade minima (prevents constants drift ambiguity)."""
    sources = {
        "ml_parameters_profile.py": repo_root
        / "scytaledroid"
        / "DynamicAnalysis"
        / "ml"
        / "ml_parameters_profile.py",
        "dataset_tracker.py": repo_root
        / "scytaledroid"
        / "DynamicAnalysis"
        / "pcap"
        / "dataset_tracker.py",
    }
    out: dict[str, str] = {}
    for name, path in sources.items():
        try:
            if path.exists():
                out[name] = sha256_file(path)
        except Exception:
            continue
    return out


@dataclass(frozen=True)
class PaperModeContext:
    repo_root: Path
    strict: bool
    fail_on_dirty: bool
    pinned_snapshot: str | None
    commit: str
    dirty: bool

    @classmethod
    def detect(
        cls,
        *,
        repo_root: Path,
        strict_arg: bool = False,
        fail_on_dirty_arg: bool = False,
        pinned_snapshot: str | None = None,
    ) -> PaperModeContext:
        strict = bool(strict_arg) or truthy_env("SCYTALEDROID_PAPER_STRICT", default=False)
        fail_on_dirty = bool(fail_on_dirty_arg) or truthy_env("SCYTALEDROID_FAIL_ON_DIRTY", default=False)
        commit = git_commit(repo_root)
        dirty = git_dirty(repo_root)
        return cls(
            repo_root=repo_root,
            strict=strict,
            fail_on_dirty=fail_on_dirty,
            pinned_snapshot=str(pinned_snapshot).strip() if pinned_snapshot else None,
            commit=commit,
            dirty=dirty,
        )

    def apply_env(self) -> None:
        if self.strict:
            os.environ["SCYTALEDROID_PAPER_STRICT"] = "1"
        if self.fail_on_dirty:
            os.environ["SCYTALEDROID_FAIL_ON_DIRTY"] = "1"

    def assert_clean_if_required(self) -> None:
        if self.strict and self.fail_on_dirty and self.dirty:
            raise SystemExit("PAPER_STRICT_DIRTY_TREE: strict mode requires a clean git tree")

    def receipt_fields(self) -> dict[str, object]:
        return {
            "git_commit": self.commit,
            "git_dirty": bool(self.dirty),
            "strict": bool(self.strict),
            "fail_on_dirty": bool(self.fail_on_dirty),
            "pinned_snapshot": self.pinned_snapshot,
            "minima_source_sha256": minima_source_hashes(self.repo_root),
        }

