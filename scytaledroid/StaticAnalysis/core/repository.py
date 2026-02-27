"""Helpers for discovering static-analysis artifacts in the repository."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Config import app_config
from scytaledroid.Utils.LoggingUtils import logging_utils as log

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
            return meta_value.strip().lower()
        try:
            package_dir = self.path.parent.name
            if package_dir:
                return package_dir.lower()
        except Exception:  # pragma: no cover - defensive
            pass
        stem = self.path.stem
        if "__" in stem:
            candidate = stem.split("__", 1)[0]
            if candidate:
                return candidate.replace("_", ".").lower()
        return stem.lower()

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
    def version_key(self) -> str:
        for candidate in (self.metadata.get("version_code"), self.metadata.get("version_name")):
            token = _normalise_token(candidate)
            if token:
                return token
        return "unknown"

    @property
    def split_group_id(self) -> str | None:
        value = self.metadata.get("split_group_id")
        if value is None:
            return None
        return str(value)

    @property
    def sha256(self) -> str | None:
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
    def session_stamp(self) -> str | None:
        value = self.metadata.get("session_stamp")
        if isinstance(value, str) and value.strip():
            return value
        return None

    @property
    def capture_id(self) -> str:
        capture = self.session_stamp
        if capture:
            return capture

        captured_at = self.metadata.get("captured_at_utc") or self.metadata.get("snapshot_captured_at")
        capture_day = _capture_day_token(captured_at)
        if capture_day:
            return f"legacy-{capture_day}"

        path_token = _capture_token_from_path(self.path)
        if path_token:
            return f"legacy-{path_token}"

        digest = hashlib.sha1(str(self.path.resolve()).encode("utf-8")).hexdigest()[:10]
        return f"legacy-unknown-{digest}"

    @property
    def apk_id(self) -> str | None:
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
    session_stamp: str | None
    capture_id: str | None
    artifacts: tuple[RepositoryArtifact, ...]
    grouping_reason: str | None = None
    grouping_confidence: str | None = None

    @property
    def base_artifact(self) -> RepositoryArtifact | None:
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


def discover_repository_artifacts(base_dir: Path | None = None) -> list[RepositoryArtifact]:
    """Return every APK artifact tracked within the repository."""

    if base_dir is None:
        base_dir = (Path(app_config.DATA_DIR) / "device_apks").resolve()
    else:
        base_dir = base_dir.resolve()

    artifacts: list[RepositoryArtifact] = []
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
    base_dir: Path | None = None,
    *,
    predicate: Callable[[ArtifactGroup | None, bool]] = None,
) -> list[ArtifactGroup]:
    """Group repository artifacts by split group id (base + splits)."""

    artifacts = discover_repository_artifacts(base_dir)
    if not artifacts:
        return []

    buckets: dict[str, list[RepositoryArtifact]] = {}

    grouping_meta: dict[str, tuple[str, str]] = {}
    for artifact in artifacts:
        group_key, reason, confidence = _group_key_for_artifact(artifact)
        buckets.setdefault(group_key, []).append(artifact)
        grouping_meta.setdefault(group_key, (reason, confidence))

    groups: list[ArtifactGroup] = []
    for key, members in buckets.items():
        members.sort(key=lambda item: (item.is_split_member, item.display_path))
        package_name = members[0].package_name if members else "unknown"
        version = members[0].version_display if members else "-"
        session_stamp = members[0].session_stamp if members else None
        capture_id = members[0].capture_id if members else None
        reason, confidence = grouping_meta.get(key, ("unknown", "low"))
        group = ArtifactGroup(
            group_key=key,
            package_name=package_name,
            version_display=version,
            session_stamp=session_stamp,
            capture_id=capture_id,
            artifacts=tuple(members),
            grouping_reason=reason,
            grouping_confidence=confidence,
        )
        if predicate and not predicate(group):
            continue
        if confidence == "low":
            log.warning(
                "Low-confidence artifact grouping used; verify split metadata.",
                category="static",
                extra={"group_key": key, "grouping_reason": reason},
            )
        groups.append(group)

    groups.sort(
        key=lambda group: (
            group.package_name.lower(),
            group.capture_id or "",
            group.version_display,
            group.session_stamp or "",
            group.group_key,
        )
    )
    return groups


def _group_key_for_artifact(
    artifact: RepositoryArtifact,
) -> tuple[str, str, str]:
    """Return a deterministic grouping key for an artifact."""

    package = artifact.package_name.lower()
    capture_id = artifact.capture_id

    if artifact.split_group_id:
        if package:
            return (
                f"split-{package}-{artifact.split_group_id}-{capture_id}-{artifact.version_key}",
                "split_group_capture_id",
                "high",
            )
        return (
            f"split-{artifact.split_group_id}-{capture_id}-{artifact.version_key}",
            "split_group_capture_id",
            "high",
        )
    if package:
        return f"pkg-{package}-{capture_id}-{artifact.version_key}", "package_capture_id", "high"
    if artifact.apk_id:
        return f"apk-{artifact.apk_id}-{capture_id}", "apk_id_capture_id", "high"
    if artifact.sha256:
        return f"sha256-{artifact.sha256}-{capture_id}", "sha256_capture_id", "high"
    path_group = _path_prefix_group_key(artifact)
    if path_group:
        return f"{path_group}-{capture_id}", "pathgroup_capture_id", "low"
    return f"path-{artifact.display_path}-{capture_id}", "path_capture_id", "low"


_TOKEN_SANITISE_RE = re.compile(r"[^A-Za-z0-9._-]+")
_DATE_TOKEN_RE = re.compile(r"^\d{8}(?:[-_]\d{6})?$")


def _normalise_token(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return _TOKEN_SANITISE_RE.sub("-", text)


def _capture_day_token(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) >= 10 and text[4] == "-" and text[7] == "-":
        return f"{text[0:4]}{text[5:7]}{text[8:10]}"
    if len(text) >= 8 and text[:8].isdigit():
        return text[:8]
    return None


def _capture_token_from_path(path: Path) -> str | None:
    for parent in path.parents:
        token = parent.name.strip()
        if _DATE_TOKEN_RE.match(token):
            return token
    return None


def _path_prefix_group_key(artifact: RepositoryArtifact) -> str | None:
    """Best-effort grouping based on common filename prefixes (base + splits)."""

    def _coerce_prefix(token: str) -> str | None:
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


def _extract_app_label(group: ArtifactGroup) -> str | None:
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


def _hydrate_app_labels(packages: dict[str, dict[str, object]]) -> None:
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


def list_packages(groups: Sequence[ArtifactGroup]) -> list[tuple[str, str, int, str | None]]:
    """Return sorted unique package names with representative versions and labels."""

    snapshot: dict[str, dict[str, object]] = {}
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

    packages: list[tuple[str, str, int, str | None]] = []
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
            label_value: str | None = app_label.strip()
        else:
            label_value = None
        packages.append((package_name, version_label, int(data.get("count", 0)), label_value))

    packages.sort(key=lambda item: (item[3] or item[0]).lower())
    return packages


def load_profile_map(groups: Sequence[ArtifactGroup]) -> dict[str, str]:
    """Return package -> profile label map for the provided artifact groups."""

    if not run_sql or not groups:
        return {}

    packages = sorted({group.package_name.lower() for group in groups if group.package_name})
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

    profile_map: dict[str, str] = {}
    for row in rows or []:
        pkg = str(row.get("package_name") or "").strip().lower()
        label = _normalise_profile_label(str(row.get("display_name") or "").strip())
        if pkg and label:
            profile_map[pkg] = label
    return profile_map


def _normalise_profile_label(label: str) -> str:
    """Normalize legacy profile display names for operator-facing static CLI views."""
    text = (label or "").strip()
    if not text:
        return text
    lowered = text.lower()
    # Legacy suffix: "(Paper #N)" where N is an integer. Strip it for display.
    if lowered.endswith(")") and "paper #" in lowered:
        import re

        m = re.search(r"\s*\(\s*paper\s*#\s*\d+\s*\)\s*$", text, flags=re.IGNORECASE)
        if m:
            return text[: m.start()].rstrip()
    return text


def load_display_name_map(groups: Sequence[ArtifactGroup]) -> dict[str, str]:
    """Return package -> display name map for the provided artifact groups."""

    if not run_sql or not groups:
        return {}

    packages = sorted({group.package_name.lower() for group in groups if group.package_name})
    placeholders = ", ".join(["%s"] * len(packages))
    try:
        rows = run_sql(
            (
                "SELECT package_name, display_name "
                f"FROM apps WHERE package_name IN ({placeholders})"
            ),
            tuple(packages),
            fetch="all",
            dictionary=True,
        )
    except Exception:
        return {}

    display_map: dict[str, str] = {}
    for row in rows or []:
        pkg = str(row.get("package_name") or "").strip().lower()
        label = str(row.get("display_name") or "").strip()
        if pkg and label:
            display_map[pkg] = label
    return display_map


def list_categories(groups: Sequence[ArtifactGroup]) -> list[tuple[str, int]]:
    """Return sorted unique categories with unique package counts."""

    profile_map = load_profile_map(groups)
    tally: dict[str, set[str]] = {}
    for group in groups:
        label = (
            profile_map.get(group.package_name.lower())
            or group.category
            or "Uncategorized"
        )
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
    "load_display_name_map",
    "load_profile_map",
]
