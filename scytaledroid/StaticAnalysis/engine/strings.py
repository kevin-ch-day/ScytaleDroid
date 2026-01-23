"""File: scytaledroid/StaticAnalysis/engine/strings.py

Lightweight helpers for extracting and summarising string-analysis signals.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from collections import Counter, defaultdict
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
import io
import os
import sys
import tempfile
from typing import Dict, Iterable, List, Mapping, MutableMapping
import os
from urllib.parse import urlsplit

from scytaledroid.StaticAnalysis._androguard import APK

from ..modules.string_analysis import (
    BUCKET_ORDER,
    StringHit,
    build_aggregates,
    build_bucket_overview,
    build_string_index,
)
from ..modules.string_analysis.constants import (
    ANALYTICS_PATTERNS,
    API_KEY_PATTERNS,
    AZURE_BLOB_PATTERN,
    CLOUDFRONT_HOST_PATTERN,
    CONTENT_URI_PATTERN,
    DOCUMENTARY_ROOTS,
    ENDPOINT_PATTERN,
    FILE_URI_PATTERN,
    FIREBASE_DB_PATTERN,
    FIREBASE_STORAGE_PATTERN,
    GCS_HOST_PATTERN,
    GCS_URI_PATTERN,
    INTERNAL_HOST_SUFFIXES,
    JWT_FULLMATCH_PATTERN,
    S3_PATH_GLOBAL,
    S3_PATH_REGION,
    S3_URI_PATTERN,
    S3_VIRTUAL_HOST_GLOBAL,
    S3_VIRTUAL_HOST_REGION,
)
from ..modules.string_analysis.parsing.host_normalizer import registrable_domain
from ..modules.string_analysis.parsing.punctuation import strip_wrap_punct
from scytaledroid.Utils.LoggingUtils import logging_engine, logging_utils as log


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


_SOURCE_TYPE_MAP = {
    "code": "dex",
    "resource": "resource",
    "raw": "resource",
    "asset": "asset",
    "native": "asset",
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


def _host_risk_tag(host: str | None) -> str | None:
    if not host:
        return None
    lowered = host.lower()
    if lowered in {"localhost", "127.0.0.1", "::1"}:
        return "internal_domain"
    for suffix in INTERNAL_HOST_SUFFIXES:
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
    return bool(JWT_FULLMATCH_PATTERN.match(value.strip()))


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip().lower()
    return value in {"1", "true", "yes", "on"}


def _extract_bounds_warnings(text: str) -> list[str]:
    """Extract resource parsing warnings emitted by third-party parsers."""

    if not text:
        return []
    lines: list[str] = []
    for raw in text.replace("\r", "\n").split("\n"):
        candidate = raw.strip()
        if not candidate:
            continue
        lowered = candidate.lower()
        if "out of bound" in lowered or "complex entry" in lowered:
            lines.append(candidate)
    return lines


def _summarize_bounds_warnings(lines: list[str]) -> dict[str, object]:
    counts: list[int] = []
    for line in lines:
        match = re.search(r"Count:\s*(\d+)", line)
        if match:
            try:
                counts.append(int(match.group(1)))
            except ValueError:
                continue
    return {
        "count_values": counts,
        "lines": lines,
    }


def _run_with_fd_capture(callable_obj):
    stdout_fd = os.dup(1)
    stderr_fd = os.dup(2)
    temp = tempfile.TemporaryFile(mode="w+b")
    try:
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(temp.fileno(), 1)
        os.dup2(temp.fileno(), 2)
        result = callable_obj()
        sys.stdout.flush()
        sys.stderr.flush()
    finally:
        os.dup2(stdout_fd, 1)
        os.dup2(stderr_fd, 2)
        os.close(stdout_fd)
        os.close(stderr_fd)
    temp.seek(0)
    raw = temp.read()
    temp.close()
    return result, raw.decode("utf-8", errors="replace")


def analyse_strings(
    apk_path: str,
    *,
    mode: str = "both",
    min_entropy: float = 4.8,
    max_samples: int | None = None,
    cleartext_only: bool = False,
    include_https_risk: bool | None = None,
) -> Mapping[str, object]:
    """Return baseline string buckets for the APK at *apk_path*."""

    try:
        apk = APK(apk_path)
    except Exception:
        return {"counts": {bucket: 0 for bucket in BUCKET_ORDER}, "samples": {}, "aggregates": {}}

    bounds_warnings: list[str] = []
    try:
        buffer = io.StringIO()
        with redirect_stdout(buffer), redirect_stderr(buffer):
            index, fd_output = _run_with_fd_capture(
                lambda: build_string_index(apk, include_resources=True)
            )
        captured = buffer.getvalue() + fd_output
        bounds_warnings = _extract_bounds_warnings(captured)
        if bounds_warnings:
            summary = _summarize_bounds_warnings(bounds_warnings)
            logging_engine.get_error_logger().warning(
                "Resource table parsing emitted bounds warnings",
                extra=logging_engine.ensure_trace(
                    {
                        "event": "strings.resource_bounds_warning",
                        "apk_path": apk_path,
                        "warning_lines": summary["lines"],
                        "count_values": summary["count_values"],
                    }
                ),
            )
    except Exception:
        return {
            "counts": {bucket: 0 for bucket in BUCKET_ORDER},
            "samples": {},
            "aggregates": {},
            "warnings": bounds_warnings,
        }

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

    if include_https_risk is None:
        include_https_risk = _env_flag(
            "SCYTALEDROID_STRINGS_INCLUDE_HTTPS_RISK", False
        )

    counts: Dict[str, int] = {bucket: 0 for bucket in BUCKET_ORDER}
    counts.setdefault("trailing_punct_trimmed", 0)
    extra_counts: Counter[str] = Counter()
    samples: Dict[str, List[StringHit]] = defaultdict(list)

    endpoint_totals: Counter[str] = Counter()
    endpoint_by_root: MutableMapping[str, Counter[str]] = defaultdict(Counter)
    endpoint_cleartext: list[StringHit] = []
    domain_sources: MutableMapping[str, set[str]] = defaultdict(set)
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
            if endpoint.root_domain:
                domain_sources[endpoint.root_domain].add(source_type or "unknown")
            if endpoint.trimmed:
                extra_counts["trailing_punct_trimmed"] += 1
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
                if (
                    endpoint.root_domain
                    and endpoint.root_domain.lower() in DOCUMENTARY_ROOTS
                ):
                    continue
                confidence = "high"
                if endpoint.root_domain:
                    sources = domain_sources.get(endpoint.root_domain, set())
                    if "dex" not in sources:
                        confidence = "low"
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
                    confidence=confidence,
                    scheme=endpoint.scheme,
                    root_domain=endpoint.root_domain,
                    resource_name=None,
                    source_type=source_type,
                    sample_hash=sample_hash,
                )
                samples["http_cleartext"].append(clear_hit)
                counts["http_cleartext"] += 1
                endpoint_cleartext.append(clear_hit)
                if confidence != "low":
                    extra_counts["http_cleartext"] += 1
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

        if CONTENT_URI_PATTERN.search(value) or FILE_URI_PATTERN.search(value):
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

    aggregates = build_aggregates(
        endpoint_totals=endpoint_totals,
        endpoint_by_root=endpoint_by_root,
        domain_sources=domain_sources,
        endpoint_cleartext=endpoint_cleartext,
        api_key_hits=api_key_hits,
        cloud_hits=cloud_hits,
        analytics_vendor_ids=analytics_vendor_ids,
        entropy_high_samples=entropy_high_samples,
    )

    counts["trailing_punct_trimmed"] = extra_counts.get("trailing_punct_trimmed", 0)

    return {
        "counts": counts,
        "samples": ordered_samples,
        "extra_counts": dict(extra_counts),
        "aggregates": aggregates,
        "structured": structured,
        "warnings": bounds_warnings,
        "options": {
            "max_samples": max_samples,
            "cleartext_only": cleartext_only,
            "min_entropy": min_entropy,
            "mode": mode,
            "https_in_risk": include_https_risk,
        },
    }


__all__ = ["analyse_strings"]
