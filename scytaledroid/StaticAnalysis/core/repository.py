"""Helpers for discovering static-analysis artifacts in the repository."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from scytaledroid.Config import app_config
from ..modules import resolve_category


@dataclass(frozen=True)
class RepositoryArtifact:
    """Represents an APK artifact available for static analysis."""

    path: Path
    display_path: str
    metadata: Mapping[str, object]

    @property
    def package_name(self) -> str:
        meta_value = self.metadata.get("package_name")
        if isinstance(meta_value, str) and meta_value.strip():
            return meta_value
        return self.path.stem

    @property
    def version_display(self) -> str:
        version_name = self.metadata.get("version_name")
        version_code = self.metadata.get("version_code")
        for candidate in (version_name, version_code):
            if isinstance(candidate, str) and candidate.strip():
                return candidate
        if isinstance(version_code, (int, float)):
            return str(version_code)
        return "-"

    @property
    def split_group_id(self) -> Optional[str]:
        value = self.metadata.get("split_group_id")
        if value is None:
            return None
        return str(value)

    @property
    def sha256(self) -> Optional[str]:
        value = self.metadata.get("sha256")
        if isinstance(value, str) and value.strip():
            return value
        return None

    @property
    def is_split_member(self) -> bool:
        value = self.metadata.get("is_split_member")
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        return False

    @property
    def artifact_label(self) -> str:
        value = self.metadata.get("artifact")
        if isinstance(value, str) and value.strip():
            return value
        return "artifact"

    @property
    def session_stamp(self) -> Optional[str]:
        value = self.metadata.get("session_stamp")
        if isinstance(value, str) and value.strip():
            return value
        return None

    @property
    def apk_id(self) -> Optional[str]:
        value = self.metadata.get("apk_id")
        if value is None:
            return None
        return str(value)

    @property
    def category(self) -> str:
        package = self.package_name
        return resolve_category(package, self.metadata)


@dataclass(frozen=True)
class ArtifactGroup:
    """Represents a group of APK artifacts that belong together (base + splits)."""

    group_key: str
    package_name: str
    version_display: str
    session_stamp: Optional[str]
    artifacts: Tuple[RepositoryArtifact, ...]

    @property
    def base_artifact(self) -> Optional[RepositoryArtifact]:
        for artifact in self.artifacts:
            if not artifact.is_split_member:
                return artifact
        return None

    @property
    def category(self) -> str:
        if not self.artifacts:
            return "Uncategorized"
        return self.artifacts[0].category


def _load_metadata(apk_path: Path) -> Mapping[str, object]:
    meta_path = apk_path.with_suffix(apk_path.suffix + ".meta.json")
    if not meta_path.exists():
        return {}
    try:
        with meta_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(payload, Mapping):
        return payload
    return {}


def discover_repository_artifacts(base_dir: Optional[Path] = None) -> List[RepositoryArtifact]:
    """Return every APK artifact tracked within the repository."""

    if base_dir is None:
        base_dir = (Path(app_config.DATA_DIR) / "apks").resolve()
    else:
        base_dir = base_dir.resolve()

    artifacts: List[RepositoryArtifact] = []
    if not base_dir.exists():
        return artifacts

    for apk_path in sorted(base_dir.rglob("*.apk")):
        metadata = _load_metadata(apk_path)
        try:
            display = apk_path.resolve().relative_to(base_dir).as_posix()
        except ValueError:
            display = apk_path.name
        artifacts.append(RepositoryArtifact(path=apk_path, display_path=display, metadata=metadata))
    return artifacts


def group_artifacts(
    base_dir: Optional[Path] = None,
    *,
    predicate: Optional[Callable[[ArtifactGroup], bool]] = None,
) -> List[ArtifactGroup]:
    """Group repository artifacts by split group id (base + splits)."""

    artifacts = discover_repository_artifacts(base_dir)
    if not artifacts:
        return []

    buckets: Dict[str, List[RepositoryArtifact]] = {}

    for artifact in artifacts:
        group_key = _group_key_for_artifact(artifact)
        buckets.setdefault(group_key, []).append(artifact)

    groups: List[ArtifactGroup] = []
    for key, members in buckets.items():
        members.sort(key=lambda item: (item.is_split_member, item.display_path))
        package_name = members[0].package_name if members else "unknown"
        version = members[0].version_display if members else "-"
        session_stamp = members[0].session_stamp if members else None
        group = ArtifactGroup(
            group_key=key,
            package_name=package_name,
            version_display=version,
            session_stamp=session_stamp,
            artifacts=tuple(members),
        )
        if predicate and not predicate(group):
            continue
        groups.append(group)

    groups.sort(
        key=lambda group: (
            group.package_name.lower(),
            group.version_display,
            group.session_stamp or "",
            group.group_key,
        )
    )
    return groups


def _group_key_for_artifact(artifact: RepositoryArtifact) -> str:
    """Return a deterministic grouping key for an artifact."""

    if artifact.split_group_id:
        return f"split-{artifact.split_group_id}"
    if artifact.apk_id:
        return f"apk-{artifact.apk_id}"
    if artifact.sha256:
        return f"sha256-{artifact.sha256}"
    return f"path-{artifact.display_path}"


def list_packages(groups: Sequence[ArtifactGroup]) -> List[tuple[str, str, int]]:
    """Return sorted unique package names with representative versions."""

    snapshot: Dict[str, Dict[str, object]] = {}
    for group in groups:
        entry = snapshot.setdefault(group.package_name, {"count": 0, "versions": set(), "fallback": "-"})
        entry["count"] = int(entry.get("count", 0)) + 1
        version = (group.version_display or "-").strip() or "-"
        if version != "-":
            entry.setdefault("versions", set()).add(version)
        entry["fallback"] = entry.get("fallback") or version

    packages: List[tuple[str, str, int]] = []
    for package_name, data in snapshot.items():
        versions = data.get("versions") or set()
        if isinstance(versions, set) and versions:
            # Prefer a deterministic ordering so the table remains stable between runs.
            version_label = sorted(versions, key=lambda value: value.lower())[0]
        else:
            fallback = data.get("fallback") or "-"
            version_label = fallback if isinstance(fallback, str) else "-"
        packages.append((package_name, version_label, int(data.get("count", 0))))

    packages.sort(key=lambda item: item[0].lower())
    return packages


def list_categories(groups: Sequence[ArtifactGroup]) -> List[tuple[str, int]]:
    """Return sorted unique categories with group counts."""

    tally: Dict[str, int] = {}
    for group in groups:
        label = group.category or "Uncategorized"
        tally[label] = tally.get(label, 0) + 1
    return sorted(tally.items(), key=lambda item: item[0].lower())


__all__ = [
    "RepositoryArtifact",
    "ArtifactGroup",
    "discover_repository_artifacts",
    "group_artifacts",
    "list_packages",
    "list_categories",
]
