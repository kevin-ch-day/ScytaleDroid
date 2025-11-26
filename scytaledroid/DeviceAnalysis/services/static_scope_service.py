"""Service to prepare static-analysis scopes from APK library selections (placeholder)."""

from __future__ import annotations

from typing import Iterable, List, Set

from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup


class StaticScopeService:
    """Placeholder selection store for APKs to be scanned."""

    def __init__(self) -> None:
        self._selected: Set[str] = set()  # store unique apk paths

    def clear(self) -> None:
        self._selected.clear()

    def select_groups(self, groups: List[ArtifactGroup]) -> None:
        for group in groups:
            for artifact in group.artifacts:
                self._selected.add(str(artifact.path))

    def select_group(self, group: ArtifactGroup) -> None:
        self.select_groups([group])

    def select_paths(self, paths: Iterable[str]) -> None:
        for path in paths:
            self._selected.add(str(path))

    def remove_paths(self, paths: Iterable[str]) -> None:
        for path in paths:
            self._selected.discard(str(path))

    def remove_group(self, group: ArtifactGroup) -> None:
        for artifact in group.artifacts:
            self._selected.discard(str(artifact.path))

    def is_selected(self, path: str) -> bool:
        return str(path) in self._selected

    def is_group_selected(self, group: ArtifactGroup) -> bool:
        return any(str(artifact.path) in self._selected for artifact in group.artifacts)

    def get_selected(self) -> List[str]:
        return sorted(self._selected)

    def selected_set(self) -> Set[str]:
        return set(self._selected)

    def count(self) -> int:
        return len(self._selected)


static_scope_service = StaticScopeService()

__all__ = ["static_scope_service", "StaticScopeService"]
