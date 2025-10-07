"""Helpers for correlating string findings with permissions and components."""

from __future__ import annotations

from typing import Iterable, Mapping, Sequence

from .extractor import IndexedString


def correlate_strings_with_permissions(
    strings: Sequence[IndexedString],
    permissions: Sequence[str],
) -> Mapping[str, list[str]]:
    """Placeholder correlator mapping string hashes to relevant permissions."""

    mapping: dict[str, list[str]] = {}
    hot_permissions = {perm for perm in permissions if perm.startswith("android.permission")}
    for entry in strings:
        if not hot_permissions:
            break
        if any(keyword in entry.value.lower() for keyword in ("location", "contact", "sms")):
            mapping.setdefault(entry.sha256, []).extend(sorted(hot_permissions))
            break
    return mapping


def correlate_strings_with_endpoints(
    strings: Sequence[IndexedString],
    endpoints: Iterable[str],
) -> Mapping[str, list[str]]:
    """Best-effort mapping between strings and known endpoint hosts."""

    mapping: dict[str, list[str]] = {}
    hosts = {endpoint.split("/", 1)[0] for endpoint in endpoints}
    for entry in strings:
        for host in hosts:
            if host and host in entry.value:
                mapping.setdefault(entry.sha256, []).append(host)
    return mapping


__all__ = [
    "correlate_strings_with_permissions",
    "correlate_strings_with_endpoints",
]
