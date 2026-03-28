"""Persisted APK-library selection service for static-analysis scopes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from scytaledroid.Config import app_config

if TYPE_CHECKING:
    from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup


def _default_manifest_path() -> Path:
    return Path(app_config.DATA_DIR) / "static_analysis" / "library_selection.json"


def _normalize_path(path: object) -> str | None:
    if path is None:
        return None
    try:
        normalized = Path(str(path)).expanduser().resolve(strict=False)
    except Exception:
        return None
    text = str(normalized).strip()
    return text or None


@dataclass(frozen=True)
class StaticScopeManifest:
    version: int
    updated_at_utc: str
    selected_artifact_paths: tuple[str, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "version": self.version,
            "updated_at_utc": self.updated_at_utc,
            "selected_artifact_paths": list(self.selected_artifact_paths),
        }


class StaticScopeService:
    """Persist and expose APK library selections for static-analysis runs."""

    def __init__(self, manifest_path: Path | None = None) -> None:
        self._manifest_path = manifest_path or _default_manifest_path()
        self._selected: set[str] = set()
        self._load()

    def clear(self) -> None:
        self._selected.clear()
        self._persist()

    def select_groups(self, groups: list[ArtifactGroup]) -> None:
        changed = False
        for group in groups:
            changed = self._select_group_paths(group) or changed
        if changed:
            self._persist()

    def select_group(self, group: ArtifactGroup) -> None:
        if self._select_group_paths(group):
            self._persist()

    def select_paths(self, paths: list[str] | tuple[str, ...]) -> None:
        changed = False
        for path in paths:
            normalized = _normalize_path(path)
            if normalized and normalized not in self._selected:
                self._selected.add(normalized)
                changed = True
        if changed:
            self._persist()

    def remove_paths(self, paths: list[str] | tuple[str, ...]) -> None:
        changed = False
        for path in paths:
            normalized = _normalize_path(path)
            if normalized and normalized in self._selected:
                self._selected.discard(normalized)
                changed = True
        if changed:
            self._persist()

    def remove_group(self, group: ArtifactGroup) -> None:
        changed = False
        for path in self._iter_group_paths(group):
            if path in self._selected:
                self._selected.discard(path)
                changed = True
        if changed:
            self._persist()

    def is_selected(self, path: str) -> bool:
        normalized = _normalize_path(path)
        return bool(normalized and normalized in self._selected)

    def is_group_selected(self, group: ArtifactGroup) -> bool:
        return any(path in self._selected for path in self._iter_group_paths(group))

    def get_selected(self) -> list[str]:
        return sorted(self._selected)

    def selected_set(self) -> set[str]:
        return set(self._selected)

    def count(self) -> int:
        return len(self._selected)

    def manifest_snapshot(self) -> StaticScopeManifest:
        return StaticScopeManifest(
            version=1,
            updated_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            selected_artifact_paths=tuple(sorted(self._selected)),
        )

    def prune_missing_paths(self, valid_paths: list[str] | tuple[str, ...]) -> int:
        valid = {
            normalized
            for path in valid_paths
            if (normalized := _normalize_path(path))
        }
        stale = self._selected - valid
        if not stale:
            return 0
        self._selected.difference_update(stale)
        self._persist()
        return len(stale)

    def _iter_group_paths(self, group: ArtifactGroup):
        for artifact in getattr(group, "artifacts", ()) or ():
            normalized = _normalize_path(getattr(artifact, "path", None))
            if normalized:
                yield normalized

    def _select_group_paths(self, group: ArtifactGroup) -> bool:
        changed = False
        for path in self._iter_group_paths(group):
            if path not in self._selected:
                self._selected.add(path)
                changed = True
        return changed

    def _load(self) -> None:
        try:
            payload = json.loads(self._manifest_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except Exception:
            return
        if not isinstance(payload, dict):
            return
        selected_paths = payload.get("selected_artifact_paths")
        if not isinstance(selected_paths, list):
            return
        for item in selected_paths:
            normalized = _normalize_path(item)
            if normalized:
                self._selected.add(normalized)

    def _persist(self) -> None:
        if not self._selected:
            try:
                self._manifest_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
            return

        payload = self.manifest_snapshot().to_payload()
        self._manifest_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._manifest_path.with_suffix(f"{self._manifest_path.suffix}.tmp")
        tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        tmp_path.replace(self._manifest_path)


static_scope_service = StaticScopeService()

__all__ = ["StaticScopeManifest", "static_scope_service", "StaticScopeService"]
