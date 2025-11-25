"""Service helpers for browsing harvested APKs and sessions."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from scytaledroid.Config import app_config
from scytaledroid.StaticAnalysis.core.repository import ArtifactGroup, group_artifacts


def list_groups(
    *,
    base_dir: Optional[Path] = None,
    device_filter: Optional[Sequence[str]] = None,
    session_filter: Optional[Sequence[str]] = None,
) -> List[ArtifactGroup]:
    """Return grouped APK artifacts with optional device/session filters."""

    resolved_dir = base_dir or Path(app_config.DATA_DIR) / "apks"
    device_filter_set = {s.strip() for s in device_filter or () if s} or None
    session_filter_set = {s.strip() for s in session_filter or () if s} or None

    def _predicate(group: ArtifactGroup) -> bool:
        if device_filter_set:
            # Device serial is stored in metadata; filter at artifact level
            has_match = False
            for artifact in group.artifacts:
                serial = artifact.metadata.get("device_serial")
                if isinstance(serial, str) and serial in device_filter_set:
                    has_match = True
                    break
            if not has_match:
                return False
        if session_filter_set and group.session_stamp:
            return group.session_stamp in session_filter_set
        if session_filter_set and not group.session_stamp:
            return False
        return True

    return list(group_artifacts(resolved_dir, predicate=_predicate))


def list_sessions(groups: Iterable[ArtifactGroup]) -> List[str]:
    """Return unique session stamps from artifact groups."""
    sessions = []
    seen = set()
    for group in groups:
        stamp = group.session_stamp
        if isinstance(stamp, str) and stamp and stamp not in seen:
            seen.add(stamp)
            sessions.append(stamp)
    return sessions


__all__ = ["list_groups", "list_sessions"]
