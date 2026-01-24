"""File: scytaledroid/StaticAnalysis/engine/strings.py

Lightweight helpers for extracting and summarising string-analysis signals.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from contextlib import redirect_stderr, redirect_stdout
import io
from typing import Dict, Iterable, List, Mapping, MutableMapping

from scytaledroid.StaticAnalysis._androguard import APK

from ..modules.string_analysis import (
    BUCKET_ORDER,
    StringHit,
    build_aggregates,
    build_bucket_overview,
    build_string_index,
)
from ..modules.string_analysis.constants import (
    CONTENT_URI_PATTERN,
    DOCUMENTARY_ROOTS,
    FILE_URI_PATTERN,
)
from scytaledroid.Utils.LoggingUtils import logging_engine
from .strings_capture import _extract_bounds_warnings, _run_with_fd_capture, _summarize_bounds_warnings
from .strings_detectors import _classify_analytics, _classify_token, _detect_cloud_refs, _detect_endpoints
from .strings_helpers import (
    _detect_jwt,
    _env_flag,
    _entropy_bucket,
    _mask_value,
    _normalise_src,
    _short_hash,
    _source_type_for,
)


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
