"""Helpers for discovering static-analysis artifacts in the repository."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from scytaledroid.Config import app_config
from ..modules import resolve_category

try:  # optional dependency (CLI can run without DB)
    from scytaledroid.Database.db_core import run_sql
except Exception:  # pragma: no cover - database module may be absent
    run_sql = None


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
        try:
            package_dir = self.path.parent.parent.name
            if package_dir:
                return package_dir
        except Exception:  # pragma: no cover - defensive
            pass
        stem = self.path.stem
        if "__" in stem:
            candidate = stem.split("__", 1)[0]
            if candidate:
                return candidate.replace("_", ".")
        return stem

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
    path_group = _path_prefix_group_key(artifact)
    if path_group:
        return path_group
    return f"path-{artifact.display_path}"


def _path_prefix_group_key(artifact: RepositoryArtifact) -> Optional[str]:
    """Best-effort grouping based on common filename prefixes (base + splits)."""

    def _coerce_prefix(token: str) -> Optional[str]:
        normalised = token.replace("\\", "/")
        parent, _, name = normalised.rpartition("/")
        if not name or "__" not in name:
            return None
        prefix = name.split("__", 1)[0]
        if not prefix:
            return None
        return f"{parent}/{prefix}" if parent else prefix

    display_path = getattr(artifact, "display_path", None)
    if isinstance(display_path, str) and display_path:
        prefix = _coerce_prefix(display_path)
        if prefix:
            return f"pathgroup-{prefix}"

    try:
        path_str = artifact.path.as_posix()
    except Exception:
        path_str = ""
    if path_str:
        prefix = _coerce_prefix(path_str)
        if prefix:
            return f"pathgroup-{prefix}"

    return None


def _extract_app_label(group: ArtifactGroup) -> Optional[str]:
    for artifact in group.artifacts:
        label = artifact.metadata.get("app_label")
        if isinstance(label, str) and label.strip():
            return label.strip()
        label = artifact.metadata.get("display_name")
        if isinstance(label, str) and label.strip():
            return label.strip()
    base = group.base_artifact
    if base:
        label = base.metadata.get("app_name")
        if isinstance(label, str) and label.strip():
            return label.strip()
        label = base.metadata.get("display_name")
        if isinstance(label, str) and label.strip():
            return label.strip()
    return None


def _hydrate_app_labels(packages: Dict[str, Dict[str, object]]) -> None:
    if run_sql is None:
        return
    missing = [name for name, data in packages.items() if not data.get("app_label")]
    if not missing:
        return
    placeholders = ", ".join(["%s"] * len(missing))
    query = (
        "SELECT package_name, display_name "
        "FROM apps "
        f"WHERE package_name IN ({placeholders})"
    )
    try:
        rows = run_sql(query, tuple(missing), fetch="all", dictionary=True) or []
    except Exception:
        return
    for row in rows:
        package = row.get("package_name")
        label = row.get("display_name")
        if not isinstance(package, str) or package not in packages:
            continue
        if isinstance(label, str) and label.strip():
            packages[package]["app_label"] = label.strip()


def list_packages(groups: Sequence[ArtifactGroup]) -> List[tuple[str, str, int, Optional[str]]]:
    """Return sorted unique package names with representative versions and labels."""

    snapshot: Dict[str, Dict[str, object]] = {}
    for group in groups:
        entry = snapshot.setdefault(
            group.package_name,
            {"count": 0, "versions": set(), "fallback": "-", "app_label": None},
        )
        entry["count"] = int(entry.get("count", 0)) + 1
        version = (group.version_display or "-").strip() or "-"
        if version != "-":
            entry.setdefault("versions", set()).add(version)
        entry["fallback"] = entry.get("fallback") or version
        if not entry.get("app_label"):
            label = _extract_app_label(group)
            if label:
                entry["app_label"] = label

    _hydrate_app_labels(snapshot)

    packages: List[tuple[str, str, int, Optional[str]]] = []
    for package_name, data in snapshot.items():
        versions = data.get("versions") or set()
        if isinstance(versions, set) and versions:
            # Prefer a deterministic ordering so the table remains stable between runs.
            version_label = sorted(versions, key=lambda value: value.lower())[0]
        else:
            fallback = data.get("fallback") or "-"
            version_label = fallback if isinstance(fallback, str) else "-"
        app_label = data.get("app_label")
        if isinstance(app_label, str) and app_label.strip():
            label_value: Optional[str] = app_label.strip()
        else:
            label_value = None
        packages.append((package_name, version_label, int(data.get("count", 0)), label_value))

    packages.sort(key=lambda item: (item[3] or item[0]).lower())
    return packages


def load_profile_map(groups: Sequence[ArtifactGroup]) -> Dict[str, str]:
    """Return package -> profile label map for the provided artifact groups."""

    if not run_sql or not groups:
        return {}

    packages = sorted({group.package_name for group in groups})
    placeholders = ", ".join(["%s"] * len(packages))
    try:
        rows = run_sql(
            (
                "SELECT d.package_name, p.display_name "
                "FROM apps d "
                "LEFT JOIN android_app_profiles p ON p.profile_key = d.profile_key "
                f"WHERE d.package_name IN ({placeholders})"
            ),
            tuple(packages),
            fetch="all",
            dictionary=True,
        )
    except Exception:
        return {}

    profile_map: Dict[str, str] = {}
    for row in rows or []:
        pkg = str(row.get("package_name") or "").strip()
        label = str(row.get("display_name") or "").strip()
        if pkg and label:
            profile_map[pkg] = label
    return profile_map


def list_categories(groups: Sequence[ArtifactGroup]) -> List[tuple[str, int]]:
    """Return sorted unique categories with unique package counts."""

    profile_map = load_profile_map(groups)
    tally: Dict[str, set[str]] = {}
    for group in groups:
        label = profile_map.get(group.package_name) or group.category or "Uncategorized"
        bucket = tally.setdefault(label, set())
        bucket.add(group.package_name)
    return sorted(((category, len(packages)) for category, packages in tally.items()), key=lambda item: item[0].lower())


__all__ = [
    "RepositoryArtifact",
    "ArtifactGroup",
    "discover_repository_artifacts",
    "group_artifacts",
    "list_packages",
    "list_categories",
    "load_profile_map",
]
