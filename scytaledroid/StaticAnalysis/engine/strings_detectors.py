"""Signal detectors used by string analysis."""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

from ..modules.string_analysis.constants import (
    ANALYTICS_PATTERNS,
    API_KEY_PATTERNS,
    AZURE_BLOB_PATTERN,
    CLOUDFRONT_HOST_PATTERN,
    ENDPOINT_PATTERN,
    FIREBASE_DB_PATTERN,
    FIREBASE_STORAGE_PATTERN,
    GCS_HOST_PATTERN,
    GCS_URI_PATTERN,
    S3_PATH_GLOBAL,
    S3_PATH_REGION,
    S3_URI_PATTERN,
    S3_VIRTUAL_HOST_GLOBAL,
    S3_VIRTUAL_HOST_REGION,
)
from ..modules.string_analysis.parsing.host_normalizer import registrable_domain
from ..modules.string_analysis.parsing.punctuation import strip_wrap_punct
from .strings_helpers import _entropy, _host_risk_tag, _ip_categories
from .strings_models import AnalyticsMatch, CloudReference, EndpointInfo, TokenMatch

_TRAILING_ENDPOINT_CHARS = ")]}>.,;:'\"’”"


def _sanitize_endpoint_value(value: str) -> tuple[str, bool]:
    if not value:
        return value, False
    stripped = strip_wrap_punct(value)
    sanitized = stripped.strip()
    if sanitized.endswith("]") and "[" in sanitized and sanitized.count("[") == sanitized.count("]"):
        return sanitized, sanitized != value
    trimmed = sanitized.rstrip(_TRAILING_ENDPOINT_CHARS).strip()
    if trimmed != sanitized:
        return trimmed, True
    return sanitized, sanitized != value


def _detect_endpoints(value: str) -> Iterable[EndpointInfo]:
    if "://" not in value:
        return
    for raw in ENDPOINT_PATTERN.findall(value):
        sanitized, trimmed = _sanitize_endpoint_value(raw)
        parsed = urlsplit(sanitized)
        scheme = (parsed.scheme or "").lower()
        host = parsed.hostname
        categories: list[str] = ["endpoints"]
        risk_tag = None
        ip_tags = list(_ip_categories(host))
        categories.extend(ip_tags)
        if scheme == "http" and "localhost" not in categories and not ip_tags:
            risk_tag = "http_cleartext"
            categories.append("http_cleartext")
        elif scheme == "https":
            categories.append("https")
        elif scheme == "ws":
            categories.append("ws")
        elif scheme == "wss":
            categories.append("wss")
        root_domain = registrable_domain(host)
        if risk_tag is None:
            risk_tag = _host_risk_tag(host)
        yield EndpointInfo(
            url=sanitized,
            scheme=scheme or None,
            host=host,
            root_domain=root_domain,
            risk_tag=risk_tag,
            categories=tuple(dict.fromkeys(categories)),
            trimmed=trimmed,
        )


def _detect_cloud_refs(value: str) -> Iterable[CloudReference]:
    lowered = value.lower()
    seen: set[tuple[str, str | None, str | None]] = set()

    def _emit(provider: str, service: str | None, resource: str | None, region: str | None) -> CloudReference | None:
        key = (provider, service, resource, region)
        if key in seen:
            return None
        seen.add(key)
        return CloudReference(
            provider=provider,
            service=service,
            resource=resource,
            region=region,
            raw=value,
        )

    for match in S3_VIRTUAL_HOST_REGION.finditer(lowered):
        ref = _emit(
            "aws",
            "s3",
            match.group("bucket"),
            match.group("region"),
        )
        if ref:
            yield ref

    for match in S3_VIRTUAL_HOST_GLOBAL.finditer(lowered):
        ref = _emit("aws", "s3", match.group("bucket"), None)
        if ref:
            yield ref

    for match in S3_PATH_REGION.finditer(lowered):
        ref = _emit(
            "aws",
            "s3",
            match.group("bucket"),
            match.group("region"),
        )
        if ref:
            yield ref

    for match in S3_PATH_GLOBAL.finditer(lowered):
        ref = _emit("aws", "s3", match.group("bucket"), None)
        if ref:
            yield ref

    for match in S3_URI_PATTERN.finditer(lowered):
        ref = _emit("aws", "s3", match.group("bucket"), None)
        if ref:
            yield ref

    for match in GCS_HOST_PATTERN.finditer(lowered):
        ref = _emit("gcp", "gcs", match.group("bucket"), None)
        if ref:
            yield ref

    for match in GCS_URI_PATTERN.finditer(lowered):
        ref = _emit("gcp", "gcs", match.group("bucket"), None)
        if ref:
            yield ref

    for match in AZURE_BLOB_PATTERN.finditer(lowered):
        account = match.group("account")
        container = match.group("container")
        resource = f"{account}/{container}" if account and container else account or container
        ref = _emit("azure", "blob", resource, None)
        if ref:
            yield ref

    for match in FIREBASE_DB_PATTERN.finditer(lowered):
        ref = _emit("firebase", None, match.group("project"), None)
        if ref:
            yield ref

    for match in FIREBASE_STORAGE_PATTERN.finditer(lowered):
        ref = _emit("firebase", "storage", match.group("bucket"), None)
        if ref:
            yield ref

    for match in CLOUDFRONT_HOST_PATTERN.finditer(lowered):
        ref = _emit("aws", "cloudfront", match.group("host"), None)
        if ref:
            yield ref


def _looks_dummy(text: str) -> bool:
    lowered = text.lower()
    if "test_" in lowered or "dummy" in lowered or "example" in lowered:
        return True
    if "xxxxx" in lowered or "yyyyy" in lowered or "00000" in lowered:
        return True
    unique_chars = set(lowered)
    return len(unique_chars) <= 3


def _classify_token(value: str) -> Iterable[TokenMatch]:
    for key, pattern in API_KEY_PATTERNS.items():
        for match in pattern.findall(value):
            if _looks_dummy(match):
                continue
            provider = "aws" if "aws" in key else key.split("_")[0]
            confidence = "high"
            if "test_" in match.lower():
                confidence = "low"
            if provider == "google":
                if len(set(match)) < 10:
                    continue
            if key == "aws_secret":
                score = _entropy(match)
                if score < 4.8:
                    continue
                confidence = "high" if score >= 5.4 else "medium"
            yield TokenMatch(provider=provider, token_type=key, value=match, confidence=confidence)


def _classify_analytics(value: str) -> Iterable[AnalyticsMatch]:
    for _, (vendor, pattern) in ANALYTICS_PATTERNS.items():
        for match in pattern.findall(value):
            if not match or _looks_dummy(match):
                continue
            yield AnalyticsMatch(vendor=vendor, identifier=match)


__all__ = [
    "_classify_analytics",
    "_classify_token",
    "_detect_cloud_refs",
    "_detect_endpoints",
]