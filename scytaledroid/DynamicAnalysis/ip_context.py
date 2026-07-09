"""IP destination context rules for dynamic network interpretation."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Any


@dataclass(frozen=True)
class IpRangeReference:
    package_name_scope: str
    cidr: str
    owner_class: str
    role_class: str
    confidence: str
    classification_basis: str
    source_label: str = "repo_seed"
    source_url: str | None = None
    notes: str | None = None


def _norm_text(value: object) -> str:
    return str(value or "").strip()


def default_ip_range_references() -> tuple[IpRangeReference, ...]:
    """Curated first-party IP ranges for apps that commonly use direct IP transport."""

    telegram_source = "https://core.telegram.org/resources/cidr.txt"
    telegram_notes = (
        "Telegram publishes these CIDR ranges for client/server transport. "
        "Android captures may show direct IP TCP/TLS or MTProto flows with little DNS/SNI."
    )
    return (
        IpRangeReference(
            "org.telegram.messenger",
            "91.108.56.0/22",
            "first_party",
            "telegram_datacenter_transport",
            "high",
            "curated_cidr",
            source_url=telegram_source,
            notes=telegram_notes,
        ),
        IpRangeReference(
            "org.telegram.messenger",
            "91.108.4.0/22",
            "first_party",
            "telegram_datacenter_transport",
            "high",
            "curated_cidr",
            source_url=telegram_source,
            notes=telegram_notes,
        ),
        IpRangeReference(
            "org.telegram.messenger",
            "91.108.8.0/22",
            "first_party",
            "telegram_datacenter_transport",
            "high",
            "curated_cidr",
            source_url=telegram_source,
            notes=telegram_notes,
        ),
        IpRangeReference(
            "org.telegram.messenger",
            "91.108.16.0/22",
            "first_party",
            "telegram_datacenter_transport",
            "high",
            "curated_cidr",
            source_url=telegram_source,
            notes=telegram_notes,
        ),
        IpRangeReference(
            "org.telegram.messenger",
            "91.108.12.0/22",
            "first_party",
            "telegram_datacenter_transport",
            "high",
            "curated_cidr",
            source_url=telegram_source,
            notes=telegram_notes,
        ),
        IpRangeReference(
            "org.telegram.messenger",
            "149.154.160.0/20",
            "first_party",
            "telegram_datacenter_transport",
            "high",
            "curated_cidr",
            source_url=telegram_source,
            notes=telegram_notes,
        ),
        IpRangeReference(
            "org.telegram.messenger",
            "91.105.192.0/23",
            "first_party",
            "telegram_datacenter_transport",
            "high",
            "curated_cidr",
            source_url=telegram_source,
            notes=telegram_notes,
        ),
        IpRangeReference(
            "org.telegram.messenger",
            "91.108.20.0/22",
            "first_party",
            "telegram_datacenter_transport",
            "high",
            "curated_cidr",
            source_url=telegram_source,
            notes=telegram_notes,
        ),
        IpRangeReference(
            "org.telegram.messenger",
            "185.76.151.0/24",
            "first_party",
            "telegram_datacenter_transport",
            "high",
            "curated_cidr",
            source_url=telegram_source,
            notes=telegram_notes,
        ),
    )


def normalize_ip(value: Any) -> str:
    text = _norm_text(value)
    if not text:
        return ""
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    elif ":" in text and text.count(":") == 1:
        host, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            text = host
    try:
        return str(ip_address(text))
    except ValueError:
        return ""


def classify_ip_destination(
    value: Any,
    *,
    package_name: str,
    references: tuple[IpRangeReference, ...] | None = None,
) -> dict[str, str | bool]:
    ip_text = normalize_ip(value)
    if not ip_text:
        return {
            "ip": "",
            "cidr": "",
            "owner_class": "unknown",
            "role_class": "unknown",
            "confidence": "low",
            "basis": "unclassified",
            "match_type": "",
            "package_name_scope": "",
            "first_party": False,
        }
    addr = ip_address(ip_text)
    package_key = _norm_text(package_name).lower()
    refs = references or default_ip_range_references()
    candidates: list[tuple[tuple[int, int], IpRangeReference]] = []
    for ref in refs:
        scope = _norm_text(ref.package_name_scope).lower()
        if scope and scope != package_key:
            continue
        try:
            network = ip_network(ref.cidr, strict=False)
        except ValueError:
            continue
        if addr.version != network.version or addr not in network:
            continue
        candidates.append(((0 if scope else 1, -int(network.prefixlen)), ref))
    candidates.sort(key=lambda item: item[0])
    if candidates:
        ref = candidates[0][1]
        return {
            "ip": ip_text,
            "cidr": ref.cidr,
            "owner_class": ref.owner_class,
            "role_class": ref.role_class,
            "confidence": ref.confidence,
            "basis": ref.classification_basis,
            "match_type": "CIDR",
            "package_name_scope": ref.package_name_scope,
            "first_party": ref.owner_class == "first_party",
        }
    return {
        "ip": ip_text,
        "cidr": "",
        "owner_class": "unknown",
        "role_class": "unknown",
        "confidence": "low",
        "basis": "unclassified",
        "match_type": "",
        "package_name_scope": "",
        "first_party": False,
    }


__all__ = [
    "IpRangeReference",
    "classify_ip_destination",
    "default_ip_range_references",
    "normalize_ip",
]
