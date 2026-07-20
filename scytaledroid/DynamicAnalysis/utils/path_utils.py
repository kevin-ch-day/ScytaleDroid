"""Path helpers for dynamic analysis."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from scytaledroid.Config import app_config


@dataclass(frozen=True)
class LegacyDynamicAliasSummary:
    """Compatibility-alias health for canonical dynamic evidence packs."""

    canonical_runs: int
    valid: int
    missing: int
    stale: int
    conflicts: int
    orphaned: int


@dataclass(frozen=True)
class LegacyDynamicAliasRepair:
    """One planned or applied compatibility-alias action."""

    run_id: str
    action: str
    detail: str


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


def inspect_legacy_dynamic_aliases(
    *,
    canonical_root: Path | None = None,
    legacy_root: Path | None = None,
) -> LegacyDynamicAliasSummary:
    """Summarize output aliases without changing canonical evidence or links."""

    canonical = canonical_root or dynamic_evidence_root()
    legacy = legacy_root or legacy_dynamic_evidence_root()
    canonical_runs = {path.name: path for path in canonical.iterdir() if path.is_dir()} if canonical.is_dir() else {}
    valid = missing = stale = conflicts = 0
    for run_id, run_dir in canonical_runs.items():
        alias = legacy / run_id
        if not alias.exists() and not alias.is_symlink():
            missing += 1
        elif not alias.is_symlink():
            conflicts += 1
        elif alias.resolve(strict=False) == run_dir.resolve():
            valid += 1
        else:
            stale += 1

    orphaned = 0
    if legacy.is_dir():
        for alias in legacy.iterdir():
            if alias.is_symlink() and alias.name not in canonical_runs:
                orphaned += 1
    return LegacyDynamicAliasSummary(
        canonical_runs=len(canonical_runs),
        valid=valid,
        missing=missing,
        stale=stale,
        conflicts=conflicts,
        orphaned=orphaned,
    )


def rebuild_legacy_dynamic_aliases(
    *,
    canonical_root: Path | None = None,
    legacy_root: Path | None = None,
    apply: bool = False,
    prune_orphans: bool = False,
) -> tuple[LegacyDynamicAliasRepair, ...]:
    """Plan or repair compatibility aliases from canonical dynamic evidence.

    ``apply=False`` is read-only. With ``apply=True``, only a missing alias or a
    symlink that points away from its same-named canonical run is changed. A
    non-symlink conflict remains untouched. ``prune_orphans=True`` additionally
    removes only symlink aliases that have no same-named canonical evidence pack.
    """

    canonical = canonical_root or dynamic_evidence_root()
    legacy = legacy_root or legacy_dynamic_evidence_root()
    if not canonical.is_dir():
        return ()

    canonical_runs = {path.name: path for path in canonical.iterdir() if path.is_dir()}
    repairs: list[LegacyDynamicAliasRepair] = []
    for run_dir in sorted(canonical_runs.values(), key=lambda path: path.name):
        alias = legacy / run_dir.name
        expected = run_dir.resolve()
        if alias.is_symlink() and alias.resolve(strict=False) == expected:
            continue
        if alias.exists() and not alias.is_symlink():
            repairs.append(LegacyDynamicAliasRepair(run_dir.name, "conflict", "existing non-symlink left unchanged"))
            continue
        action = "create" if not alias.is_symlink() else "replace-stale"
        repairs.append(LegacyDynamicAliasRepair(run_dir.name, action, str(expected)))
        if apply:
            legacy.mkdir(parents=True, exist_ok=True)
            if alias.is_symlink():
                alias.unlink()
            alias.symlink_to(expected, target_is_directory=True)

    if prune_orphans and legacy.is_dir():
        for alias in sorted(legacy.iterdir(), key=lambda path: path.name):
            if alias.name in canonical_runs or not alias.is_symlink():
                continue
            repairs.append(LegacyDynamicAliasRepair(alias.name, "remove-orphan", "no canonical evidence pack"))
            if apply:
                alias.unlink()
    return tuple(repairs)


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
    "inspect_legacy_dynamic_aliases",
    "iter_dynamic_run_dirs",
    "LegacyDynamicAliasRepair",
    "LegacyDynamicAliasSummary",
    "legacy_dynamic_evidence_root",
    "rebuild_legacy_dynamic_aliases",
    "resolve_dynamic_run_dir",
    "resolve_evidence_path",
]
