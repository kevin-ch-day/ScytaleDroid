"""Tokenisation helpers for extracting URL and host candidates from strings."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from ..constants import ENDPOINT_PATTERN
from .punctuation import strip_wrap_punct
from .urlsafe import safe_urlsplit
from .validators import is_ip, is_placeholder, looks_like_domain

_TOKEN_PATTERN = re.compile(r"[^\s]+")
_SCHEME_ONLY_RE = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*):(?P<rest>.+)$")

_ALLOWED_SCHEMES = {"http", "https", "ws", "wss"}
_IGNORED_SCHEMES = {"file", "content", "about", "intent"}


@dataclass(frozen=True)
class Candidate:
    """Represents a token extracted from a string that may describe a host."""

    raw: str
    scheme: str | None
    host: str | None
    port: int | None
    path: str | None
    source_offset: int


def _candidate_from_url(raw: str, offset: int) -> Candidate | None:
    trimmed = strip_wrap_punct(raw)
    parsed = safe_urlsplit(trimmed)
    if parsed is None:
        return None
    scheme = parsed.scheme.lower() if parsed.scheme else None
    if scheme and scheme in _IGNORED_SCHEMES:
        return None
    if scheme and scheme not in _ALLOWED_SCHEMES:
        # Ignore schemes we do not reason about for network risk.
        return None
    host = parsed.hostname or (parsed.netloc or None)
    if host and not (
        looks_like_domain(host) or is_ip(host) or is_placeholder(host)
    ):
        host = None
    try:
        port = parsed.port
    except ValueError:
        port = None
    path = parsed.path or None
    return Candidate(
        raw=trimmed,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        source_offset=offset + raw.find(trimmed) if trimmed else offset,
    )


def _candidate_from_token(raw: str, offset: int) -> Candidate | None:
    trimmed = strip_wrap_punct(raw)
    if not trimmed:
        return None
    if "//" in trimmed:
        return _candidate_from_url(trimmed, offset)
    scheme_hint = None
    match = _SCHEME_ONLY_RE.match(trimmed)
    if match:
        scheme_hint = match.group("scheme").lower()
        remainder = match.group("rest")
        if scheme_hint in _IGNORED_SCHEMES:
            return None
        if scheme_hint in _ALLOWED_SCHEMES and remainder:
            canonical = f"{scheme_hint}://{remainder.lstrip('/')}"
            candidate = _candidate_from_url(canonical, offset)
            if candidate is None:
                return None
            return Candidate(
                raw=trimmed,
                scheme=candidate.scheme,
                host=candidate.host,
                port=candidate.port,
                path=candidate.path,
                source_offset=candidate.source_offset,
            )
    if scheme_hint and scheme_hint not in _ALLOWED_SCHEMES:
        return None
    guess = trimmed
    parsed = safe_urlsplit(f"//{trimmed}")
    if parsed is None:
        return None
    host = parsed.hostname
    if host and not (looks_like_domain(host) or is_ip(host) or is_placeholder(host)):
        host = None
    try:
        port = parsed.port
    except ValueError:
        port = None
    path = parsed.path or None
    if not host and (is_ip(guess) or looks_like_domain(guess) or is_placeholder(guess)):
        host = guess
    if not host and looks_like_domain(trimmed.split("/", 1)[0]):
        host = trimmed.split("/", 1)[0]
    if not host and not is_placeholder(trimmed):
        return None
    return Candidate(
        raw=trimmed,
        scheme=None,
        host=host,
        port=port,
        path=path,
        source_offset=offset + raw.find(trimmed) if trimmed else offset,
    )


def _iter_tokens(value: str) -> Iterable[re.Match[str]]:
    return _TOKEN_PATTERN.finditer(value)


def extract_candidates(value: str) -> list[Candidate]:
    """Return URL/host candidates discovered within *value*."""

    candidates: list[Candidate] = []
    seen_offsets: set[tuple[int, str]] = set()

    for match in ENDPOINT_PATTERN.finditer(value):
        raw = match.group("url")
        offset = match.start("url")
        candidate = _candidate_from_url(raw, offset)
        if candidate is None:
            continue
        if not candidate.host and not is_placeholder(candidate.raw):
            continue
        key = (candidate.source_offset, candidate.raw.lower())
        if key in seen_offsets:
            continue
        seen_offsets.add(key)
        candidates.append(candidate)

    for match in _iter_tokens(value):
        raw = match.group(0)
        offset = match.start()
        candidate = _candidate_from_token(raw, offset)
        if candidate is None:
            continue
        key = (candidate.source_offset, candidate.raw.lower())
        if key in seen_offsets:
            continue
        seen_offsets.add(key)
        candidates.append(candidate)

    return candidates


__all__ = ["Candidate", "extract_candidates"]
