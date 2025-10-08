"""Data models used by the correlation detector."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

from ...persistence.reports import StoredReport


@dataclass(frozen=True)
class NetworkSnapshot:
    """Normalised network security posture extracted from detector metrics."""

    base_cleartext: Optional[bool]
    debug_cleartext: Optional[bool]
    trust_user_certs: bool
    cleartext_domains: tuple[str, ...]
    pinned_domains: tuple[str, ...]
    http_hosts: tuple[str, ...]
    https_hosts: tuple[str, ...]
    policy_hash: Optional[str] = None


@dataclass(frozen=True)
class NetworkDiff:
    """Network posture delta between two snapshots."""

    http_added: tuple[str, ...] = tuple()
    https_added: tuple[str, ...] = tuple()
    cleartext_flip: Optional[tuple[Optional[bool], Optional[bool]]] = None
    debug_flip: Optional[tuple[Optional[bool], Optional[bool]]] = None
    user_certs_flip: Optional[tuple[bool, bool]] = None
    cleartext_domains_added: tuple[str, ...] = tuple()
    pinning_removed: tuple[str, ...] = tuple()
    policy_hash_changed: bool = False


@dataclass(frozen=True)
class DiffBundle:
    """Aggregated diff artefacts when comparing with a baseline report."""

    previous: Optional[StoredReport]
    new_exported: Mapping[str, Sequence[str]]
    new_permissions: Sequence[str]
    flipped_flags: Mapping[str, tuple[object, object]]
    network_diff: NetworkDiff


__all__ = [
    "NetworkSnapshot",
    "NetworkDiff",
    "DiffBundle",
]
