"""Path helpers for dynamic analysis."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from scytaledroid.Config import app_config


def dynamic_evidence_root() -> Path:
    """Canonical root for newly written dynamic evidence packs."""

    configured = str(getattr(app_config, "DYNAMIC_EVIDENCE_ROOT", "") or "").strip()
    if not configured or configured == "data/evidence/dynamic":
        return Path(app_config.DATA_DIR) / "evidence" / "dynamic"
    return Path(configured)


def legacy_dynamic_evidence_root() -> Path:
    """Legacy dynamic evidence root kept for read compatibility."""

    return Path(app_config.OUTPUT_DIR) / "evidence" / "dynamic"


def dynamic_evidence_roots(*, include_legacy: bool = True) -> tuple[Path, ...]:
    """Return evidence roots in preferred lookup order."""

    roots: list[Path] = [dynamic_evidence_root()]
    if include_legacy:
        legacy = legacy_dynamic_evidence_root()
        if legacy != roots[0]:
            roots.append(legacy)
    return tuple(roots)


def _uuid_name(path: Path) -> str | None:
    for part in reversed(path.parts):
        try:
            UUID(part)
        except (TypeError, ValueError):
            continue
        return part
    return None


def resolve_dynamic_run_dir(dynamic_run_id: str | None) -> Path | None:
    """Resolve a dynamic run directory across canonical and legacy roots."""

    run_id = str(dynamic_run_id or "").strip()
    if not run_id:
        return None
    for root in dynamic_evidence_roots():
        candidate = root / run_id
        if candidate.exists():
            return candidate
    return dynamic_evidence_root() / run_id


def iter_dynamic_run_dirs(*, include_legacy: bool = True) -> tuple[Path, ...]:
    """Return known dynamic run directories, preferring canonical over legacy."""

    by_name: dict[str, Path] = {}
    for root in reversed(dynamic_evidence_roots(include_legacy=include_legacy)):
        if not root.exists():
            continue
        for path in root.iterdir():
            if path.is_dir():
                by_name[path.name] = path
    return tuple(sorted(by_name.values(), key=lambda p: p.name))


def ensure_legacy_dynamic_symlink(run_dir: Path) -> Path | None:
    """Create output/evidence/dynamic/<run_id> symlink for a canonical run dir.

    The symlink is a transition aid: legacy direct path consumers keep working
    while primary bytes live under data/evidence/dynamic.
    """

    run_id = run_dir.name
    canonical_root = dynamic_evidence_root()
    legacy_root = legacy_dynamic_evidence_root()
    if legacy_root == canonical_root:
        return None
    try:
        if not _is_run_dir_under(run_dir, canonical_root):
            return None
        legacy_root.mkdir(parents=True, exist_ok=True)
        link_path = legacy_root / run_id
        if link_path.exists() or link_path.is_symlink():
            return link_path
        link_path.symlink_to(run_dir.resolve(), target_is_directory=True)
        return link_path
    except OSError:
        return None


def _is_run_dir_under(path: Path, root: Path) -> bool:
    try:
        resolved = path.resolve()
        root_resolved = root.resolve()
    except OSError:
        return False
    return root_resolved == resolved or root_resolved in resolved.parents


def resolve_evidence_path(evidence_path: str | None) -> Path | None:
    if not evidence_path:
        return None
    path = Path(evidence_path)
    if path.is_absolute():
        run_id = _uuid_name(path)
        if run_id:
            canonical = dynamic_evidence_root() / run_id
            if canonical.exists():
                return canonical
        return path
    run_id = _uuid_name(path)
    if run_id:
        canonical = dynamic_evidence_root() / run_id
        if canonical.exists():
            return canonical
        legacy = legacy_dynamic_evidence_root() / run_id
        if legacy.exists():
            return legacy
    candidate = Path.cwd() / path
    if candidate.exists():
        return candidate
    output_root = Path(app_config.OUTPUT_DIR)
    output_candidate = output_root / path
    if output_candidate.exists():
        return output_candidate
    return candidate


__all__ = [
    "dynamic_evidence_root",
    "dynamic_evidence_roots",
    "ensure_legacy_dynamic_symlink",
    "iter_dynamic_run_dirs",
    "legacy_dynamic_evidence_root",
    "resolve_dynamic_run_dir",
    "resolve_evidence_path",
]
