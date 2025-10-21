"""Host normalisation helpers."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ..constants import MULTI_LEVEL_SUFFIXES


@dataclass(frozen=True)
class NormalizedHost:
    full_host: str | None
    etld_plus_one: str | None
    is_ip: bool


def registrable_domain(host: str | None) -> str | None:
    """Return the eTLD+1 (registrable root) for *host* if available."""

    if not host:
        return None
    lowered = host.strip(".").lower()
    if not lowered:
        return None
    if lowered == "localhost":
        return "localhost"
    parts = lowered.split(".")
    if len(parts) <= 2:
        return lowered
    suffix_two = ".".join(parts[-2:])
    if suffix_two in MULTI_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix_two


def normalize_host(host: str | None) -> NormalizedHost:
    """Return a normalized host representation suitable for policy checks."""

    if not host:
        return NormalizedHost(full_host=None, etld_plus_one=None, is_ip=False)

    candidate = host.strip().lower().strip(".")
    if not candidate:
        return NormalizedHost(full_host=None, etld_plus_one=None, is_ip=False)

    is_ip_host = False
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        is_ip_host = False
    else:
        is_ip_host = True

    normalized = candidate
    if not is_ip_host:
        try:
            normalized = candidate.encode("idna").decode("ascii")
        except UnicodeError:
            normalized = candidate

    registrable = registrable_domain(normalized)
    return NormalizedHost(
        full_host=normalized,
        etld_plus_one=registrable,
        is_ip=is_ip_host,
    )


__all__ = ["NormalizedHost", "normalize_host", "registrable_domain"]
