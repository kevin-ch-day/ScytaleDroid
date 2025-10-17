"""Shared helpers for SNI detectors."""
from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from typing import MutableMapping
from urllib.parse import urlsplit

from ..extractor import IndexedString
from ..schema import EvidenceRef
from .patterns import AUTH_KEYWORDS, GRAPHQL_HINT, GRPC_HINT, INTERNAL_SUFFIXES, REDIRECTOR_HOSTS


@dataclass
class Fragment:
    """Normalized view of an extracted string with a stable offset base."""

    entry: IndexedString
    base_offset: int

    @property
    def src(self) -> str:
        return self.entry.origin

    @property
    def sha256(self) -> str:
        return self.entry.source_sha256 or self.entry.sha256


def collect_fragments(index: "StringIndex") -> dict[str, list[Fragment]]:
    """Bucket indexed strings by origin while keeping deterministic offsets."""

    from ..extractor import StringIndex  # circular import guard

    buckets: dict[str, list[Fragment]] = {}
    offsets: MutableMapping[str, int] = {}
    for entry in index.strings:
        if entry.origin not in buckets:
            buckets[entry.origin] = []
        if entry.byte_offset is not None:
            base = entry.byte_offset
        else:
            base = offsets.get(entry.origin, 0)
        buckets[entry.origin].append(Fragment(entry=entry, base_offset=base))
        encoded_len = len(entry.value.encode("utf-8", "ignore"))
        if entry.byte_offset is not None:
            offsets[entry.origin] = entry.byte_offset + encoded_len
        else:
            offsets[entry.origin] = base + encoded_len
    return buckets


def entropy(text: str) -> float:
    if not text:
        return 0.0
    frequency: MutableMapping[str, int] = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in frequency.values())


def context_window(value: str, start: int, end: int, *, radius: int = 20) -> str:
    head = max(start - radius, 0)
    tail = min(end + radius, len(value))
    snippet = value[head:tail]
    if head > 0:
        snippet = "…" + snippet
    if tail < len(value):
        snippet = snippet + "…"
    return snippet


def is_ip_literal(host: str | None) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def registrable_root(host: str | None) -> str | None:
    if not host:
        return None
    lowered = host.strip(".").lower()
    if not lowered:
        return None
    parts = lowered.split(".")
    if len(parts) <= 2:
        return lowered
    return ".".join(parts[-2:])


def tags_for_endpoint(url: str, *, value: str, start: int, host: str | None) -> list[str]:
    tags: list[str] = ["endpoint"]
    scheme = urlsplit(url).scheme.lower()
    if scheme in {"http", "ws"}:
        tags.append("cleartext")
    if scheme in {"ws", "wss"}:
        tags.append("websocket")
    if is_ip_literal(host):
        tags.append("ip-literal")
    elif host and not any(host.lower().endswith(f".{suffix}") or host.lower() == suffix for suffix in INTERNAL_SUFFIXES):
        tags.append("prod-domain")
    snippet = value[max(0, start - 48) : start + 48]
    if any(keyword in snippet.lower() for keyword in AUTH_KEYWORDS):
        tags.append("auth-adjacent")
    if GRAPHQL_HINT.search(url) or GRAPHQL_HINT.search(value):
        tags.append("graphql")
    if GRPC_HINT.search(value):
        tags.append("grpc")
    root = registrable_root(host)
    if root in REDIRECTOR_HOSTS or (host and host.lower() in REDIRECTOR_HOSTS):
        tags.append("redirector")
    return tags


def build_evidence(fragment: Fragment, start: int | None) -> EvidenceRef:
    base = fragment.entry.byte_offset if fragment.entry.byte_offset is not None else fragment.base_offset
    offset = None if start is None else base + start
    sha256 = fragment.entry.source_sha256 or fragment.entry.sha256
    return EvidenceRef(path=fragment.src, offset=offset, sha256=sha256)


def mask_secret(value: str) -> str:
    if len(value) <= 12:
        return value
    return f"{value[:6]}…{value[-4:]}"


__all__ = [
    "Fragment",
    "collect_fragments",
    "entropy",
    "context_window",
    "is_ip_literal",
    "registrable_root",
    "tags_for_endpoint",
    "build_evidence",
    "mask_secret",
]
