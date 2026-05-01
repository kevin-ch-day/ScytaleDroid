"""Data models used by the correlation detector."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ...persistence.reports import StoredReport


@dataclass(frozen=True)
class NetworkSnapshot:
    """Normalised network security posture extracted from detector metrics."""

    base_cleartext: bool | None
    debug_cleartext: bool | None
    trust_user_certs: bool
    cleartext_domains: tuple[str, ...]
    pinned_domains: tuple[str, ...]
    http_hosts: tuple[str, ...]
    https_hosts: tuple[str, ...]
    policy_hash: str | None = None


@dataclass(frozen=True)
class NetworkDiff:
    """Network posture delta between two snapshots."""

    http_added: tuple[str, ...] = tuple()
    https_added: tuple[str, ...] = tuple()
    cleartext_flip: tuple[bool | None, bool | None | None] = None
    debug_flip: tuple[bool | None, bool | None | None] = None
    user_certs_flip: tuple[bool, bool | None] = None
    cleartext_domains_added: tuple[str, ...] = tuple()
    pinning_removed: tuple[str, ...] = tuple()
    policy_hash_changed: bool = False


@dataclass(frozen=True)
class DiffBundle:
    """Aggregated diff artefacts when comparing with a baseline report."""

    previous: StoredReport | None
    new_exported: Mapping[str, Sequence[str]]
    new_permissions: Sequence[str]
    flipped_flags: Mapping[str, tuple[object, object]]
    network_diff: NetworkDiff


__all__ = [
    "NetworkSnapshot",
    "NetworkDiff",
    "DiffBundle",
]