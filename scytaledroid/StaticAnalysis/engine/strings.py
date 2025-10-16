"""File: scytaledroid/StaticAnalysis/engine/strings.py

Lightweight helpers for extracting and summarising string-analysis signals.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, MutableMapping
from urllib.parse import urlsplit

from scytaledroid.StaticAnalysis._androguard import APK

from ..modules.string_analysis import (
    BUCKET_ORDER,
    StringHit,
    build_bucket_overview,
    build_string_index,
)


_ENDPOINT_PATTERN = re.compile(r"(?:https?|wss?)://[^\s\"'<>]+", re.IGNORECASE)
_CONTENT_URI_PATTERN = re.compile(r"content://[^\s\"'<>]+", re.IGNORECASE)
_FILE_URI_PATTERN = re.compile(r"file://[^\s\"'<>]+", re.IGNORECASE)
_JWT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")

_S3_VIRTUAL_HOST_REGION = re.compile(
    r"(?P<bucket>[a-z0-9.-]+)\.s3[.-](?P<region>[a-z0-9-]+)\.amazonaws\.com"
)
_S3_VIRTUAL_HOST_GLOBAL = re.compile(r"(?P<bucket>[a-z0-9.-]+)\.s3\.amazonaws\.com")
_S3_PATH_REGION = re.compile(
    r"s3[.-](?P<region>[a-z0-9-]+)\.amazonaws\.com/(?P<bucket>[a-z0-9._-]+)/?"
)
_S3_PATH_GLOBAL = re.compile(r"s3\.amazonaws\.com/(?P<bucket>[a-z0-9._-]+)/?")
_S3_URI = re.compile(r"s3://(?P<bucket>[a-z0-9._-]+)/?")
_GCS_HOST = re.compile(r"storage.googleapis.com/(?P<bucket>[a-z0-9._-]+)/?")
_GCS_URI = re.compile(r"gs://(?P<bucket>[a-z0-9._-]+)/?")
_AZURE_BLOB = re.compile(
    r"(?P<account>[a-z0-9-]+)\.blob.core.windows.net/(?P<container>[a-z0-9-]+)/?"
)
_FIREBASE_DB = re.compile(r"(?P<project>[a-z0-9-]+)\.firebaseio.com")
_FIREBASE_STORAGE = re.compile(
    r"firebasestorage.googleapis.com/v0/b/(?P<bucket>[a-z0-9._-]+)/?"
)
_CLOUDFRONT_HOST = re.compile(r"(?P<host>[a-z0-9.-]+\.cloudfront\.net)")


@dataclass(frozen=True)
class EndpointInfo:
    url: str
    scheme: str | None
    host: str | None
    root_domain: str | None
    risk_tag: str | None
    categories: tuple[str, ...]


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


_SOURCE_TYPE_MAP = {
    "code": "dex",
    "resource": "resource",
    "raw": "resource",
    "asset": "asset",
    "native": "asset",
}

_INTERNAL_HOST_SUFFIXES = {
    "corp",
    "internal",
    "lan",
    "local",
    "intra",
}

_MULTI_LEVEL_SUFFIXES = {
    "co.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "com.br",
    "com.cn",
    "com.tr",
    "com.mx",
    "com.sg",
    "com.hk",
    "com.tw",
    "co.in",
    "co.jp",
    "ne.jp",
}

_ANALYTICS_PATTERNS: Mapping[str, tuple[str, re.Pattern[str]]] = {
    "ga": ("google_analytics", re.compile(r"UA-\d{4,}-\d+", re.IGNORECASE)),
    "gtag": ("gtag", re.compile(r"G-[A-Z0-9]{6,}", re.IGNORECASE)),
    "firebase": ("firebase", re.compile(r"1:[0-9]{8,}:[a-z0-9]{10,}", re.IGNORECASE)),
    "admob": ("admob", re.compile(r"ca-app-pub-[0-9]{16}/[0-9]{10}", re.IGNORECASE)),
    "adjust": ("adjust", re.compile(r"[0-9a-f]{8}[0-9a-z]{8}", re.IGNORECASE)),
    "appsflyer": ("appsflyer", re.compile(r"[0-9a-f]{32}af", re.IGNORECASE)),
    "segment": ("segment", re.compile(r"[A-Za-z0-9]{32}\.[A-Za-z0-9]{32}", re.IGNORECASE)),
    "mixpanel": ("mixpanel", re.compile(r"[0-9a-f]{24}", re.IGNORECASE)),
}

_API_KEY_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"A(?:KI|SI)A[0-9A-Z]{16}"),
    "aws_secret": re.compile(r"(?<![A-Z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "stripe": re.compile(r"s[kpr]_(?:live|test)_[0-9a-zA-Z]{16,}"),
    "slack": re.compile(r"xox(?:p|b|o|a|s|r)-[0-9A-Za-z-]{10,}"),
    "github": re.compile(r"gh[opsuhr]_[0-9A-Za-z]{36}"),
    "twilio": re.compile(r"(?:AC|SK)[0-9a-fA-F]{32}"),
}


def _short_hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    frequency: MutableMapping[str, int] = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in frequency.values())


def _mask_value(value: str) -> str:
    if len(value) <= 8:
        return value
    return f"{value[:4]}…{value[-4:]}"


def _normalise_src(origin: str, origin_type: str, sha256: str) -> str:
    origin_label = origin or origin_type or "string"
    return f"{origin_label}@{sha256[:8]}"


def _source_type_for(entry_origin_type: str) -> str | None:
    return _SOURCE_TYPE_MAP.get(entry_origin_type)


def _registrable_root(host: str | None) -> str | None:
    if not host:
        return None
    lowered = host.strip(".").lower()
    if not lowered:
        return None
    if lowered in {"localhost"}:
        return "localhost"
    parts = lowered.split(".")
    if len(parts) <= 2:
        return lowered
    suffix_two = ".".join(parts[-2:])
    suffix_three = ".".join(parts[-3:])
    if suffix_three in _MULTI_LEVEL_SUFFIXES:
        return suffix_three
    return suffix_two


def _host_risk_tag(host: str | None) -> str | None:
    if not host:
        return None
    lowered = host.lower()
    if lowered in {"localhost", "127.0.0.1", "::1"}:
        return "internal_domain"
    for suffix in _INTERNAL_HOST_SUFFIXES:
        if lowered.endswith(f".{suffix}") or lowered == suffix:
            return "internal_domain"
    return "prod_domain"


def _ip_categories(host: str | None) -> tuple[str, ...]:
    if not host:
        return tuple()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return tuple()
    if ip.is_loopback:
        return ("localhost",)
    if ip.is_private:
        return ("ip_private",)
    if ip.is_global:
        return ("ip_public",)
    return tuple()


def _detect_endpoints(value: str) -> Iterable[EndpointInfo]:
    for raw in _ENDPOINT_PATTERN.findall(value):
        parsed = urlsplit(raw)
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
        root_domain = _registrable_root(host)
        if risk_tag is None:
            risk_tag = _host_risk_tag(host)
        yield EndpointInfo(
            url=raw,
            scheme=scheme or None,
            host=host,
            root_domain=root_domain,
            risk_tag=risk_tag,
            categories=tuple(dict.fromkeys(categories)),
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

    for match in _S3_VIRTUAL_HOST_REGION.finditer(lowered):
        ref = _emit(
            "aws",
            "s3",
            match.group("bucket"),
            match.group("region"),
        )
        if ref:
            yield ref

    for match in _S3_VIRTUAL_HOST_GLOBAL.finditer(lowered):
        ref = _emit("aws", "s3", match.group("bucket"), None)
        if ref:
            yield ref

    for match in _S3_PATH_REGION.finditer(lowered):
        ref = _emit(
            "aws",
            "s3",
            match.group("bucket"),
            match.group("region"),
        )
        if ref:
            yield ref

    for match in _S3_PATH_GLOBAL.finditer(lowered):
        ref = _emit("aws", "s3", match.group("bucket"), None)
        if ref:
            yield ref

    for match in _S3_URI.finditer(lowered):
        ref = _emit("aws", "s3", match.group("bucket"), None)
        if ref:
            yield ref

    for match in _GCS_HOST.finditer(lowered):
        ref = _emit("gcp", "gcs", match.group("bucket"), None)
        if ref:
            yield ref

    for match in _GCS_URI.finditer(lowered):
        ref = _emit("gcp", "gcs", match.group("bucket"), None)
        if ref:
            yield ref

    for match in _AZURE_BLOB.finditer(lowered):
        account = match.group("account")
        container = match.group("container")
        resource = f"{account}/{container}" if account and container else account or container
        ref = _emit("azure", "blob", resource, None)
        if ref:
            yield ref

    for match in _FIREBASE_DB.finditer(lowered):
        ref = _emit("firebase", None, match.group("project"), None)
        if ref:
            yield ref

    for match in _FIREBASE_STORAGE.finditer(lowered):
        ref = _emit("firebase", "storage", match.group("bucket"), None)
        if ref:
            yield ref

    for match in _CLOUDFRONT_HOST.finditer(lowered):
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
    for key, pattern in _API_KEY_PATTERNS.items():
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
    for _, (vendor, pattern) in _ANALYTICS_PATTERNS.items():
        for match in pattern.findall(value):
            if not match or _looks_dummy(match):
                continue
            yield AnalyticsMatch(vendor=vendor, identifier=match)


def _entropy_bucket(value: str, *, minimum: float) -> tuple[str | None, float]:
    if len(value) < 16:
        return (None, 0.0)
    stripped = value.strip()
    if not stripped or stripped.isdigit():
        return (None, 0.0)
    if re.fullmatch(r"[0-9a-fA-F]{16,}", stripped):
        return (None, 0.0)
    entropy_score = _entropy(stripped)
    threshold = max(minimum, 4.0)
    if entropy_score < threshold:
        return (None, entropy_score)
    if 4.0 <= entropy_score < 4.8:
        return ("low", entropy_score)
    if 4.8 <= entropy_score <= 5.5:
        return ("med", entropy_score)
    return ("high", entropy_score)


def _detect_jwt(value: str) -> bool:
    return bool(_JWT_PATTERN.match(value.strip()))


def analyse_strings(
    apk_path: str,
    *,
    mode: str = "both",
    min_entropy: float = 4.8,
    max_samples: int | None = None,
    cleartext_only: bool = False,
) -> Mapping[str, object]:
    """Return baseline string buckets for the APK at *apk_path*."""

    try:
        apk = APK(apk_path)
    except Exception:
        return {"counts": {bucket: 0 for bucket in BUCKET_ORDER}, "samples": {}, "aggregates": {}}

    try:
        index = build_string_index(apk, include_resources=True)
    except Exception:
        return {"counts": {bucket: 0 for bucket in BUCKET_ORDER}, "samples": {}, "aggregates": {}}

    entries = sorted(
        index.strings,
        key=lambda entry: (
            0 if entry.origin_type == "code" else 1,
            entry.origin,
            entry.value,
        ),
    )

    if mode == "dex":
        entries = [entry for entry in entries if entry.origin_type == "code"]
    elif mode == "resources":
        entries = [
            entry
            for entry in entries
            if entry.origin_type in {"resource", "raw", "asset"}
        ]

    counts: Dict[str, int] = {bucket: 0 for bucket in BUCKET_ORDER}
    extra_counts: Counter[str] = Counter()
    samples: Dict[str, List[StringHit]] = defaultdict(list)

    endpoint_totals: Counter[str] = Counter()
    endpoint_by_root: MutableMapping[str, Counter[str]] = defaultdict(Counter)
    endpoint_cleartext: list[StringHit] = []
    analytics_vendor_ids: MutableMapping[str, MutableMapping[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    cloud_hits: list[tuple[StringHit, str | None]] = []
    api_key_hits: list[StringHit] = []
    entropy_high_samples: list[StringHit] = []

    for entry in entries:
        value = entry.value
        src = _normalise_src(entry.origin, entry.origin_type, entry.sha256)
        source_type = _source_type_for(entry.origin_type)

        for endpoint in _detect_endpoints(value):
            sample_hash = _short_hash(endpoint.url)
            hit = StringHit(
                bucket="endpoints",
                value=endpoint.url,
                src=src,
                tag=endpoint.scheme,
                sha256=entry.sha256,
                masked=None,
                finding_type="endpoint",
                provider=None,
                risk_tag=endpoint.risk_tag,
                confidence="high",
                scheme=endpoint.scheme,
                root_domain=endpoint.root_domain,
                resource_name=None,
                source_type=source_type,
                sample_hash=sample_hash,
            )
            samples["endpoints"].append(hit)
            counts["endpoints"] += 1
            endpoint_totals.update(endpoint.categories)
            if endpoint.root_domain:
                endpoint_by_root[endpoint.root_domain].update({endpoint.scheme or "other": 1})
            if "http_cleartext" in endpoint.categories and endpoint.risk_tag == "http_cleartext":
                clear_hit = StringHit(
                    bucket="http_cleartext",
                    value=endpoint.url,
                    src=src,
                    tag=endpoint.scheme,
                    sha256=entry.sha256,
                    masked=None,
                    finding_type="endpoint",
                    provider=None,
                    risk_tag=endpoint.risk_tag,
                    confidence="high",
                    scheme=endpoint.scheme,
                    root_domain=endpoint.root_domain,
                    resource_name=None,
                    source_type=source_type,
                    sample_hash=sample_hash,
                )
                samples["http_cleartext"].append(clear_hit)
                counts["http_cleartext"] += 1
                extra_counts["http_cleartext"] += 1
                endpoint_cleartext.append(hit)
            if endpoint.scheme == "https":
                extra_counts["https"] += 1
            if "ip_private" in endpoint.categories:
                extra_counts["ip_private"] += 1
            if "ip_public" in endpoint.categories:
                extra_counts["ip_public"] += 1
            if "localhost" in endpoint.categories:
                extra_counts["localhost"] += 1
            if endpoint.scheme in {"ws", "wss"}:
                extra_counts[endpoint.scheme] += 1

        if _CONTENT_URI_PATTERN.search(value) or _FILE_URI_PATTERN.search(value):
            tag = "content" if value.lower().startswith("content://") else "file"
            hit = StringHit(
                bucket="uris",
                value=value,
                src=src,
                tag=tag,
                sha256=entry.sha256,
                masked=None,
                finding_type="endpoint",
                provider=None,
                risk_tag=None,
                confidence="medium",
                scheme=tag,
                root_domain=None,
                resource_name=None,
                source_type=source_type,
                sample_hash=_short_hash(value),
            )
            samples["uris"].append(hit)
            counts["uris"] += 1
            extra_counts[tag] += 1

        for cloud in _detect_cloud_refs(value):
            hit = StringHit(
                bucket="cloud_refs",
                value=cloud.raw,
                src=src,
                tag=cloud.service or cloud.provider,
                sha256=entry.sha256,
                masked=None,
                finding_type="cloud_ref",
                provider=cloud.provider,
                risk_tag="prod_domain",
                confidence="medium",
                scheme=None,
                root_domain=None,
                resource_name=cloud.resource,
                source_type=source_type,
                sample_hash=_short_hash(cloud.raw),
            )
            samples["cloud_refs"].append(hit)
            counts["cloud_refs"] += 1
            cloud_hits.append((hit, cloud.region))

        for token in _classify_token(value):
            masked = _mask_value(token.value)
            hit = StringHit(
                bucket="api_keys",
                value=token.value,
                src=src,
                tag=token.token_type,
                sha256=entry.sha256,
                masked=masked,
                finding_type="api_key",
                provider=token.provider,
                risk_tag="token_candidate",
                confidence=token.confidence,
                scheme=None,
                root_domain=None,
                resource_name=None,
                source_type=source_type,
                sample_hash=_short_hash(token.value),
            )
            samples["api_keys"].append(hit)
            counts["api_keys"] += 1
            api_key_hits.append(hit)

        for analytic in _classify_analytics(value):
            hit = StringHit(
                bucket="analytics_ids",
                value=analytic.identifier,
                src=src,
                tag=analytic.vendor,
                sha256=entry.sha256,
                masked=None,
                finding_type="analytics_id",
                provider=analytic.vendor,
                risk_tag="prod_domain",
                confidence="medium",
                scheme=None,
                root_domain=None,
                resource_name=None,
                source_type=source_type,
                sample_hash=_short_hash(analytic.identifier),
            )
            samples["analytics_ids"].append(hit)
            counts["analytics_ids"] += 1
            analytics_vendor_ids[analytic.vendor][src].add(analytic.identifier)

        bucket, entropy_value = _entropy_bucket(value, minimum=min_entropy)
        if bucket:
            hit = StringHit(
                bucket="high_entropy",
                value=value,
                src=src,
                tag=f"entropy_{bucket}",
                sha256=entry.sha256,
                masked=_mask_value(value),
                finding_type="secret_entropy",
                provider=None,
                risk_tag="token_candidate",
                confidence="high" if bucket == "high" else "medium",
                scheme=None,
                root_domain=None,
                resource_name=None,
                source_type=source_type,
                sample_hash=_short_hash(value),
            )
            samples["high_entropy"].append(hit)
            counts["high_entropy"] += 1
            extra_counts[f"entropy_{bucket}"] += 1
            if bucket == "high":
                entropy_high_samples.append(hit)

        if _detect_jwt(value):
            hit = StringHit(
                bucket="api_keys",
                value=value,
                src=src,
                tag="jwt",
                sha256=entry.sha256,
                masked=_mask_value(value),
                finding_type="jwt_candidate",
                provider=None,
                risk_tag="token_candidate",
                confidence="medium",
                scheme=None,
                root_domain=None,
                resource_name=None,
                source_type=source_type,
                sample_hash=_short_hash(value),
            )
            samples["api_keys"].append(hit)
            counts["api_keys"] += 1
            extra_counts["jwt_candidate"] += 1

    raw_samples: Dict[str, List[StringHit]] = {
        bucket: list(samples.get(bucket, []))
        for bucket in BUCKET_ORDER
        if samples.get(bucket)
    }

    ordered_samples: Dict[str, List[Mapping[str, object]]] = {}
    for bucket in BUCKET_ORDER:
        hits = samples.get(bucket)
        if not hits:
            continue
        unique: MutableMapping[str, StringHit] = {}
        for hit in hits:
            key = f"{hit.value}|{hit.src}|{hit.tag}"
            unique.setdefault(key, hit)
        ordered = sorted(unique.values(), key=lambda item: (item.value, item.src, item.tag or ""))
        ordered_samples[bucket] = [
            {
                "value": hit.value,
                "value_masked": hit.masked,
                "src": hit.src,
                "tag": hit.tag,
                "sha256": hit.sha256,
                "finding_type": hit.finding_type,
                "provider": hit.provider,
                "risk_tag": hit.risk_tag,
                "confidence": hit.confidence,
                "scheme": hit.scheme,
                "root_domain": hit.root_domain,
                "resource_name": hit.resource_name,
                "source_type": hit.source_type,
                "sample_hash": hit.sample_hash,
            }
            for hit in ordered
        ]

    structured = build_bucket_overview(raw_samples, counts)

    endpoint_roots_payload = []
    for root, scheme_counts in endpoint_by_root.items():
        total = sum(scheme_counts.values())
        endpoint_roots_payload.append(
            {
                "root_domain": root,
                "total": total,
                "schemes": dict(sorted(scheme_counts.items())),
            }
        )
    endpoint_roots_payload.sort(key=lambda item: item["total"], reverse=True)

    cleartext_payload = []
    seen_clear: set[tuple[str, str]] = set()
    for hit in endpoint_cleartext:
        key = (hit.value, hit.src or "")
        if key in seen_clear:
            continue
        seen_clear.add(key)
        cleartext_payload.append(
            {
                "value": hit.value,
                "src": hit.src,
                "root_domain": hit.root_domain,
                "scheme": hit.scheme,
                "risk_tag": hit.risk_tag,
            }
        )

    api_keys_payload = [
        {
            "provider": hit.provider,
            "masked": hit.masked or _mask_value(hit.value),
            "src": hit.src,
            "confidence": hit.confidence,
            "finding_type": hit.finding_type,
            "token_type": hit.tag,
        }
        for hit in api_key_hits
        if hit.confidence != "low"
    ]

    cloud_payload = [
        {
            "provider": hit.provider,
            "service": hit.tag,
            "resource": hit.resource_name,
            "region": region,
            "src": hit.src,
        }
        for hit, region in cloud_hits
    ]

    analytics_payload: Dict[str, List[Mapping[str, object]]] = {}
    for vendor, src_map in analytics_vendor_ids.items():
        vendor_entries: List[Mapping[str, object]] = []
        for src_label, identifiers in src_map.items():
            vendor_entries.append(
                {
                    "src": src_label,
                    "ids": sorted(identifiers),
                    "count": len(identifiers),
                }
            )
        vendor_entries.sort(
            key=lambda item: (
                -int(item.get("count", 0) or 0),
                str(item.get("src") or ""),
            )
        )
        analytics_payload[vendor] = vendor_entries

    entropy_payload = [
        {
            "masked": hit.masked or _mask_value(hit.value),
            "src": hit.src,
        }
        for hit in entropy_high_samples[:10]
    ]

    aggregates = {
        "endpoint_totals": dict(endpoint_totals),
        "endpoint_roots": endpoint_roots_payload,
        "endpoint_cleartext": cleartext_payload,
        "api_keys_high": api_keys_payload,
        "cloud_refs": cloud_payload,
        "analytics_ids": analytics_payload,
        "entropy_high_samples": entropy_payload,
    }

    return {
        "counts": counts,
        "samples": ordered_samples,
        "extra_counts": dict(extra_counts),
        "aggregates": aggregates,
        "structured": structured,
        "options": {
            "max_samples": max_samples,
            "cleartext_only": cleartext_only,
            "min_entropy": min_entropy,
            "mode": mode,
        },
    }


__all__ = ["analyse_strings"]
