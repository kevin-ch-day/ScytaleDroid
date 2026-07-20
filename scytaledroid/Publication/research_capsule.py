"""Build a hash-locked, paper-level research-capsule manifest.

The manifest is deliberately an inventory, not an archive creator.  It pins the
files that must be copied to durable storage without silently copying a large
corpus, dumping a database, or reading secrets from ``.env``.  A separate
operator-controlled archive step can then package exactly the manifested files.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SENSITIVE_CONFIG_NAMES = {".env"}


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest for a regular file."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_value(repo_root: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ("git", *args),
            cwd=repo_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return (completed.stdout or "").strip() if completed.returncode == 0 else "unknown"


def _display_path(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _is_sensitive_config(path: Path) -> bool:
    name = path.name
    return name in _SENSITIVE_CONFIG_NAMES or (name.startswith(".env.") and name != ".env.example")


def _file_record(path: Path, *, repo_root: Path, role: str) -> dict[str, Any]:
    return {
        "role": role,
        "path": _display_path(path, repo_root),
        "sha256": sha256_file(path),
        "size_bytes": int(path.stat().st_size),
    }


def _directory_record(path: Path, *, repo_root: Path, role: str) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for child in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        if child.name.startswith(".") or child.suffix == ".pyc":
            continue
        files.append(_file_record(child, repo_root=repo_root, role=role))

    tree = hashlib.sha256()
    for record in files:
        tree.update(str(record["path"]).encode("utf-8"))
        tree.update(b"\0")
        tree.update(str(record["sha256"]).encode("ascii"))
        tree.update(b"\0")
    return {
        "role": role,
        "path": _display_path(path, repo_root),
        "kind": "directory",
        "file_count": len(files),
        "size_bytes": sum(int(record["size_bytes"]) for record in files),
        "sha256_tree": tree.hexdigest(),
        "files": files,
    }


def inventory_item(path: Path | str, *, repo_root: Path | str, role: str) -> dict[str, Any]:
    """Inventory one explicit capsule input without reading configuration values."""

    root = Path(repo_root).resolve()
    candidate = Path(path).expanduser().resolve()
    normalized_role = str(role).strip().lower() or "artifact"
    if normalized_role == "config" and _is_sensitive_config(candidate):
        raise ValueError("refusing to inventory .env; use a redacted config or .env.example")
    if not candidate.exists():
        return {
            "role": normalized_role,
            "path": _display_path(candidate, root),
            "missing": True,
        }
    if candidate.is_file():
        return _file_record(candidate, repo_root=root, role=normalized_role) | {"kind": "file", "missing": False}
    if candidate.is_dir():
        return _directory_record(candidate, repo_root=root, role=normalized_role) | {"missing": False}
    return {"role": normalized_role, "path": _display_path(candidate, root), "missing": True}


def build_research_capsule_manifest(
    *,
    paper_id: str,
    repo_root: Path | str,
    items: Mapping[str, Iterable[Path | str]],
    required_roles: Iterable[str] = (),
    archive_root: Path | str | None = None,
    selection_validation: Mapping[str, Iterable[str]] | None = None,
    generated_at_utc: str | None = None,
) -> dict[str, Any]:
    """Create a manifest for explicitly selected research materials.

    ``items`` is intentionally explicit.  This avoids accidentally hashing or
    packaging the entire workspace, including unreviewed evidence or secrets.
    """

    root = Path(repo_root).resolve()
    normalized_paper_id = str(paper_id).strip()
    if not normalized_paper_id:
        raise ValueError("paper_id is required")

    records: list[dict[str, Any]] = []
    for role in sorted(items):
        for item in items[role]:
            records.append(inventory_item(item, repo_root=root, role=role))

    role_set = {str(record["role"]) for record in records}
    required = sorted({str(role).strip().lower() for role in required_roles if str(role).strip()})
    missing_required_roles = [role for role in required if role not in role_set]
    missing_items = [str(record["path"]) for record in records if record.get("missing")]
    validation = {str(name): sorted({str(issue) for issue in issues}) for name, issues in (selection_validation or {}).items()}
    unresolved_selection = {name: issues for name, issues in validation.items() if issues}

    archive: dict[str, Any] = {"configured": archive_root is not None}
    if archive_root is not None:
        destination = Path(archive_root).expanduser().resolve()
        archive.update(
            {
                "path": str(destination),
                "exists": destination.exists(),
                "mounted": os.path.ismount(destination),
                "writable": bool(destination.exists() and os.access(destination, os.W_OK)),
            }
        )

    commit = _git_value(root, "rev-parse", "HEAD")
    dirty = _git_value(root, "status", "--porcelain")
    ready = bool(records) and not missing_items and not missing_required_roles and not unresolved_selection
    if archive_root is not None:
        ready = ready and bool(archive.get("writable"))

    return {
        "schema_version": 1,
        "artifact_type": "research_capsule_manifest",
        "paper_id": normalized_paper_id,
        "generated_at_utc": generated_at_utc or datetime.now(UTC).isoformat(),
        "provenance": {
            "repo_root": str(root),
            "git_commit": commit,
            "git_dirty": dirty not in {"", "unknown"},
        },
        "archive_destination": archive,
        "required_roles": required,
        "missing_required_roles": missing_required_roles,
        "missing_items": missing_items,
        "selection_validation": validation,
        "unresolved_selection": unresolved_selection,
        "items": records,
        "ready_to_archive": ready,
        "operator_note": (
            "This manifest records explicit inputs only. Create the database export and archive "
            "copy through separately reviewed, operator-controlled steps."
        ),
    }
