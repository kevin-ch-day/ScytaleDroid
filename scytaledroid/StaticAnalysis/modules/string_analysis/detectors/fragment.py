"""Per-fragment detectors that emit SNI observations."""
from __future__ import annotations

import base64
import binascii
from typing import Iterator
from urllib.parse import urlsplit

from ..schema import Observation
from .common import Fragment, build_evidence, context_window, entropy, mask_secret, tags_for_endpoint
from .patterns import (
    AUTH_HEADER_PATTERN,
    BASE64_CANDIDATE,
    BEARER_PATTERN,
    CLOUD_PATTERNS,
    ENDPOINT_PATTERN,
    FEATURE_KEYWORDS,
    JWT_PATTERN,
    KEYWORD_LOOKUP,
)


def iter_endpoint_observations(fragment: Fragment) -> Iterator[Observation]:
    value = fragment.entry.value
    for match in ENDPOINT_PATTERN.finditer(value):
        url = match.group("url")
        parsed = urlsplit(url)
        host = parsed.hostname
        tags = tuple(dict.fromkeys(tags_for_endpoint(url, value=value, start=match.start(), host=host)))
        context = context_window(value, match.start(), match.end())
        evidence = build_evidence(fragment, match.start())
        yield Observation(
            value=url,
            src=fragment.src,
            tags=tags,
            category="endpoint",
            confidence="high",
            evidence=evidence,
            context=context,
            sha_short=fragment.sha256[:8],
            host=host,
        )


def iter_auth_token_observations(fragment: Fragment) -> Iterator[Observation]:
    value = fragment.entry.value
    lowered = value.lower()
    if "auth" not in lowered and "bearer" not in lowered:
        return

    def _iter_tokens(pattern: "re.Pattern[str]") -> Iterator[tuple[str, "re.Match[str]"]]:
        import re

        for match in pattern.finditer(value):
            token = match.group("token")
            if not token or len(token) < 16:
                continue
            yield token, match

    seen_offsets: set[int] = set()
    for pattern in (AUTH_HEADER_PATTERN, BEARER_PATTERN, JWT_PATTERN):
        for token, match in _iter_tokens(pattern):
            start = match.start("token")
            if start in seen_offsets:
                continue
            seen_offsets.add(start)
            context = context_window(value, match.start(), match.end())
            context_lower = context.lower()
            tags = ["auth-token", "auth-adjacent"]
            confidence = "medium"
            if token.count(".") == 2:
                tags.append("jwt-format")
                confidence = "high"
            if "bearer" in context_lower:
                tags.append("bearer-context")
            if any(marker in context_lower for marker in ("test", "mock", "dummy")):
                tags.append("dev-marker")
            evidence = build_evidence(fragment, start)
            yield Observation(
                value=mask_secret(token),
                src=fragment.src,
                tags=tuple(tags),
                category="secret",
                confidence=confidence,
                evidence=evidence,
                context=context,
                sha_short=fragment.sha256[:8],
            )


def iter_cloud_observations(fragment: Fragment) -> Iterator[Observation]:
    value = fragment.entry.value
    for key, pattern in CLOUD_PATTERNS.items():
        for match in pattern.finditer(value):
            bucket = match.groupdict().get("bucket") or match.groupdict().get("project")
            if not bucket:
                continue
            context = context_window(value, match.start(), match.end())
            tags = ("cloud-bucket", key)
            yield Observation(
                value=bucket,
                src=fragment.src,
                tags=tags,
                category="cloud",
                confidence="medium",
                evidence=build_evidence(fragment, match.start()),
                context=context,
                sha_short=fragment.sha256[:8],
            )


def iter_base64_observations(fragment: Fragment) -> Iterator[Observation]:
    value = fragment.entry.value
    for match in BASE64_CANDIDATE.finditer(value):
        blob = match.group(0)
        if len(blob) % 4 != 0:
            continue
        try:
            decoded_bytes = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        if not decoded_bytes:
            continue
        try:
            decoded = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            decoded = ""
        meaningful = bool(decoded and (ENDPOINT_PATTERN.search(decoded) or KEYWORD_LOOKUP.search(decoded)))
        if not meaningful:
            continue
        context = context_window(value, match.start(), match.end())
        yield Observation(
            value=blob,
            src=fragment.src,
            tags=("encoded",),
            category="encoded",
            confidence="medium",
            evidence=build_evidence(fragment, match.start()),
            context=context,
            sha_short=fragment.sha256[:8],
            decoded=decoded if decoded else None,
        )


def iter_entropy_observations(fragment: Fragment) -> Iterator[Observation]:
    value = fragment.entry.value
    if len(value) < 16:
        return
    if not KEYWORD_LOOKUP.search(value):
        return
    score = entropy(value)
    if score < 4.8:
        return
    context = value[:40] + ("…" if len(value) > 40 else "")
    yield Observation(
        value=value,
        src=fragment.src,
        tags=("entropy-spike",),
        category="entropy",
        confidence="medium" if score < 5.4 else "high",
        evidence=build_evidence(fragment, 0),
        context=context,
        sha_short=fragment.sha256[:8],
    )


def iter_feature_flag_observations(fragment: Fragment) -> Iterator[Observation]:
    value = fragment.entry.value
    lowered = value.lower()
    if not any(keyword in lowered for keyword in FEATURE_KEYWORDS):
        return
    for match in ENDPOINT_PATTERN.finditer(value):
        url = match.group("url")
        snippet = context_window(value, match.start(), match.end())
        snippet_lower = snippet.lower()
        if not any(keyword in snippet_lower for keyword in FEATURE_KEYWORDS):
            continue
        parsed = urlsplit(url)
        host = parsed.hostname
        tags = ["feature-flag", "remote-control"]
        if parsed.scheme.lower() in {"http", "ws"}:
            tags.append("cleartext")
        evidence = build_evidence(fragment, match.start())
        yield Observation(
            value=url,
            src=fragment.src,
            tags=tuple(tags),
            category="remote",
            confidence="medium",
            evidence=evidence,
            context=snippet,
            sha_short=fragment.sha256[:8],
            host=host,
        )


_FRAGMENT_DETECTORS = (
    iter_endpoint_observations,
    iter_cloud_observations,
    iter_feature_flag_observations,
    iter_base64_observations,
    iter_entropy_observations,
    iter_auth_token_observations,
)


def iter_fragment_observations(fragment: Fragment) -> Iterator[Observation]:
    for detector in _FRAGMENT_DETECTORS:
        yield from detector(fragment)


__all__ = ["iter_fragment_observations"]
