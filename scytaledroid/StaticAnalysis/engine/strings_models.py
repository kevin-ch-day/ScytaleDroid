"""Lightweight models for string-analysis helpers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EndpointInfo:
    url: str
    scheme: str | None
    host: str | None
    root_domain: str | None
    risk_tag: str | None
    categories: tuple[str, ...]
    trimmed: bool = False


@dataclass(frozen=True)
class CloudReference:
    provider: str
    service: str | None
    resource: str | None
    region: str | None
    raw: str


@dataclass(frozen=True)
class TokenMatch:
    provider: str
    token_type: str
    value: str
    confidence: str


@dataclass(frozen=True)
class AnalyticsMatch:
    vendor: str
    identifier: str


__all__ = [
    "AnalyticsMatch",
    "CloudReference",
    "EndpointInfo",
    "TokenMatch",
]
