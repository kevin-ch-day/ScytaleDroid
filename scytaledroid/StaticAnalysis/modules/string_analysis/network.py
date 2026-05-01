"""Network-related helpers built on the string index."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from .constants import HTTP_URL_PATTERN
from .extractor import IndexedString, StringIndex
from .parsing.urlsafe import safe_urlsplit

_TRUST_MANAGER_KEYWORDS = (
    "x509trustmanager",
    "trustmanager",
    "checkservertrusted",
    "checkclienttrusted",
    "trustall",
    "trustmanagerfactory",
)

_HOSTNAME_VERIFIER_KEYWORDS = (
    "hostnameverifier",
    "allowallhostnameverifier",
    "verify(hostname",
    "sethostnameverifier",
)

_PINNING_KEYWORDS = (
    "certificatepinner",
    "pin-sha256",
    "pin-sha1",
    "trustkit",
    "okhttpclient",
    "certificateserializer",
)


@dataclass(frozen=True)
class EndpointMatch:
    """Represents an endpoint URL discovered in string resources."""

    url: str
    scheme: str
    host: str
    string_entry: IndexedString


def extract_endpoints(index: StringIndex) -> Sequence[EndpointMatch]:
    """Return HTTP(S) endpoints referenced in *index*."""

    matches: list[EndpointMatch] = []
    seen: set[tuple[str, str]] = set()

    for entry in index.strings:
        value = entry.value
        if not value or ("http" not in value and "HTTP" not in value):
            continue
        for match in HTTP_URL_PATTERN.finditer(value):
            candidate = match.group(0)
            parsed = safe_urlsplit(candidate)
            if parsed is None:
                continue
            if parsed.scheme not in {"http", "https"}:
                continue
            host = parsed.netloc.lower()
            if not host:
                continue
            dedupe_key = (parsed.scheme, entry.sha256)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            matches.append(
                EndpointMatch(
                    url=candidate,
                    scheme=parsed.scheme,
                    host=host,
                    string_entry=entry,
                )
            )

    return tuple(matches)


def detect_tls_keywords(index: StringIndex) -> Mapping[str, Sequence[IndexedString]]:
    """Return potential TLS customisation strings keyed by heuristic type."""

    results: MutableMapping[str, list[IndexedString]] = {
        "trust_manager": [],
        "hostname_verifier": [],
        "certificate_pinning": [],
    }

    seen: MutableMapping[str, set[str]] = {
        "trust_manager": set(),
        "hostname_verifier": set(),
        "certificate_pinning": set(),
    }

    for entry in index.strings:
        lowered = entry.value.lower()
        if not lowered:
            continue

        if _contains_keyword(lowered, _TRUST_MANAGER_KEYWORDS):
            if entry.sha256 not in seen["trust_manager"]:
                seen["trust_manager"].add(entry.sha256)
                results["trust_manager"].append(entry)

        if _contains_keyword(lowered, _HOSTNAME_VERIFIER_KEYWORDS):
            if entry.sha256 not in seen["hostname_verifier"]:
                seen["hostname_verifier"].add(entry.sha256)
                results["hostname_verifier"].append(entry)

        if _contains_keyword(lowered, _PINNING_KEYWORDS):
            if entry.sha256 not in seen["certificate_pinning"]:
                seen["certificate_pinning"].add(entry.sha256)
                results["certificate_pinning"].append(entry)

    return {
        key: tuple(entries) for key, entries in results.items()
    }


def _contains_keyword(value: str, keywords: Iterable[str]) -> bool:
    return any(keyword in value for keyword in keywords)


__all__ = ["EndpointMatch", "extract_endpoints", "detect_tls_keywords"]
