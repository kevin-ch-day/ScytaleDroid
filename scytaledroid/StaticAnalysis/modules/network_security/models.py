"""Dataclasses describing network security configuration policies."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass


@dataclass(frozen=True)
class DomainPolicy:
    """Represents a domain configuration entry extracted from NSC."""

    domains: tuple[str, ...]
    include_subdomains: bool
    cleartext_permitted: bool | None
    user_certificates_allowed: bool
    pinned_certificates: tuple[Mapping[str, object], ...] = ()
    trust_anchors: tuple[str, ...] = ()
    source: str | None = None

    def to_dict(self) -> MutableMapping[str, object]:
        payload: MutableMapping[str, object] = {
            "domains": list(self.domains),
            "include_subdomains": self.include_subdomains,
            "cleartext_permitted": self.cleartext_permitted,
            "user_certificates_allowed": self.user_certificates_allowed,
        }
        if self.pinned_certificates:
            payload["pinned_certificates"] = [dict(pin) for pin in self.pinned_certificates]
        if self.trust_anchors:
            payload["trust_anchors"] = list(self.trust_anchors)
        if self.source:
            payload["source"] = self.source
        return payload


@dataclass(frozen=True)
class NetworkSecurityPolicy:
    """Resolved network security configuration information."""

    source_path: str | None
    base_cleartext: bool | None
    debug_overrides_cleartext: bool | None
    trust_user_certificates: bool
    base_trust_anchors: tuple[str, ...] = ()
    domain_policies: tuple[DomainPolicy, ...] = ()
    raw_xml_hash: str | None = None

    def to_dict(self) -> MutableMapping[str, object]:
        payload: MutableMapping[str, object] = {
            "source_path": self.source_path,
            "base_cleartext": self.base_cleartext,
            "debug_overrides_cleartext": self.debug_overrides_cleartext,
            "trust_user_certificates": self.trust_user_certificates,
            "domain_policies": [policy.to_dict() for policy in self.domain_policies],
        }
        if self.base_trust_anchors:
            payload["base_trust_anchors"] = list(self.base_trust_anchors)
        if self.raw_xml_hash:
            payload["raw_xml_hash"] = self.raw_xml_hash
        return payload

    @classmethod
    def empty(cls) -> NetworkSecurityPolicy:
        return cls(
            source_path=None,
            base_cleartext=None,
            debug_overrides_cleartext=None,
            trust_user_certificates=False,
            base_trust_anchors=tuple(),
            domain_policies=tuple(),
            raw_xml_hash=None,
        )


__all__ = ["DomainPolicy", "NetworkSecurityPolicy"]