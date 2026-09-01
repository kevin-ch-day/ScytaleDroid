"""Deterministic registrable-domain identity shared across analysis layers."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from publicsuffixlist import PSLFILE, PublicSuffixList

_PUBLIC_SUFFIX_LIST = PublicSuffixList(accept_unknown=False)

LEGACY_DOMAIN_NORMALIZATION_KEY = "legacy_suffix_v1"
IP_CONTEXT_NORMALIZATION_KEY = "ip_context_v1"


@dataclass(frozen=True)
class RootDomainIdentity:
    """Parallel legacy aggregation-root and PSL registrant-boundary identities."""

    root_domain: str
    registrable_domain_psl: str
    normalization_key: str
    reference_sha256: str | None


def _unknown_suffix_fallback(host: str) -> str:
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def registrable_domain(host: str | None) -> str | None:
    """Return the pinned-PSL registrable domain with deterministic fallback."""
    if not host:
        return None
    lowered = host.strip(".").lower()
    if not lowered:
        return None
    if lowered == "localhost":
        return "localhost"
    try:
        resolved = _PUBLIC_SUFFIX_LIST.privatesuffix(lowered)
    except (TypeError, UnicodeError, ValueError):
        resolved = None
    return str(resolved).lower() if resolved else _unknown_suffix_fallback(lowered)


@lru_cache(maxsize=1)
def registrable_domain_resolver_metadata() -> dict[str, Any]:
    """Describe the exact offline suffix resolver used by this installation."""
    try:
        package_version = version("publicsuffixlist")
    except PackageNotFoundError:
        package_version = "unknown"

    list_path = Path(PSLFILE)
    list_sha256 = sha256(list_path.read_bytes()).hexdigest() if list_path.is_file() else None
    return {
        "resolver": "publicsuffixlist",
        "resolver_version": package_version,
        "public_suffix_list_file": list_path.name,
        "public_suffix_list_sha256": list_sha256,
        "accept_unknown_suffixes": False,
        "private_suffixes_included": True,
        "unknown_suffix_fallback": "last_two_labels",
    }


def domain_normalization_key() -> str:
    """Return the compact normalization algorithm identity stored with DB rows."""
    metadata = registrable_domain_resolver_metadata()
    return f"psl:{metadata['resolver']}:{metadata['resolver_version']}"


def build_root_domain_identity(
    observed_domain: str,
    root_domain: str,
    *,
    is_ip: bool = False,
) -> RootDomainIdentity:
    """Preserve the existing aggregation root and derive a separate PSL boundary."""
    observed = str(observed_domain or "").strip().lower()
    root = str(root_domain or observed).strip().lower()
    if is_ip:
        return RootDomainIdentity(
            root_domain=root,
            registrable_domain_psl=root,
            normalization_key=IP_CONTEXT_NORMALIZATION_KEY,
            reference_sha256=None,
        )

    metadata = registrable_domain_resolver_metadata()
    registrable = registrable_domain(observed) or root
    reference_sha = metadata.get("public_suffix_list_sha256")
    return RootDomainIdentity(
        root_domain=root,
        registrable_domain_psl=registrable,
        normalization_key=domain_normalization_key(),
        reference_sha256=str(reference_sha) if reference_sha else None,
    )


__all__ = [
    "IP_CONTEXT_NORMALIZATION_KEY",
    "LEGACY_DOMAIN_NORMALIZATION_KEY",
    "RootDomainIdentity",
    "build_root_domain_identity",
    "domain_normalization_key",
    "registrable_domain",
    "registrable_domain_resolver_metadata",
]
