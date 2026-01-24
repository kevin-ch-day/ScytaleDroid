"""Exploratory string summary renderers."""

from __future__ import annotations

from collections import Counter
from typing import Mapping

from scytaledroid.StaticAnalysis.modules.string_analysis import (
    CollectionSummary,
    NormalizedString,
)

_CONFIDENCE_PRIORITY = {"high": 2, "medium": 1, "low": 0}


def render_exploratory_summary(
    package_name: str,
    version: str | None,
    summary: CollectionSummary,
    *,
    sample_limit: int = 3,
) -> str:
    """Return a human-readable exploratory summary for collected strings."""

    metrics = summary.metrics
    version_text = version or "unknown"
    apk_hash = _first_apk_hash(summary)
    splits_count = len(metrics.splits_present) or 1
    source_parts = " ".join(
        f"{key}={value}" for key, value in sorted(metrics.strings_by_source.items())
    )
    decoded_ratio = _format_ratio(
        metrics.decoded_yield_rate, metrics.decoded_blobs_total, metrics.base64_candidates
    )
    lines = [
        f"Exploratory SNI  {package_name} {version_text}",
        (
            f"apk={apk_hash} splits={splits_count} "
            f"strings: total={metrics.strings_total} ({source_parts})"
        ),
        (
            f"doc_noise_ratio={metrics.doc_noise_ratio:.2f} "
            f"decoded_yield_rate={decoded_ratio} "
            f"obfuscation_hint={'true' if metrics.obfuscation_hint else 'false'}"
        ),
    ]

    lines.append(
        "Endpoints (non-doc): "
        f"effective_http={metrics.effective_http} "
        f"effective_https={metrics.effective_https} "
        f"placeholders_dropped={metrics.placeholders_dropped} "
        f"doc_suppressed={metrics.doc_suppressed} "
        f"doc_host_suppr={metrics.suppressed_doc_host} "
        f"doc_cdn_suppr={metrics.suppressed_doc_cdn} "
        f"doc_http_suppr={metrics.suppressed_doc_http} "
        f"downgraded_placeholder={metrics.downgraded_placeholder} "
        f"annotated_fragment={metrics.annotated_fragment} "
        f"ws_cleartext={metrics.ws_cleartext} "
        f"ws_seen={metrics.ws_seen} "
        f"wss_seen={metrics.wss_seen} "
        f"https_seen={metrics.https_seen} "
        f"ipv6_seen={metrics.ipv6_seen} "
        f"ip_literals_public={metrics.ip_literals_public} "
        f"graphql={metrics.graphql_markers} "
        f"grpc={metrics.grpc_markers}"
    )
    lines.append(
        "Secrets: "
        f"aws_pairs={metrics.aws_pairs} "
        f"jwt_near_auth={metrics.jwt_near_auth} "
        f"base64_candidates={metrics.base64_candidates} "
        f"hex_candidates={metrics.hex_candidates} "
        f"decoded={metrics.decoded_blobs_total} "
        f"decode_fail={metrics.base64_decode_failures + metrics.hex_decode_failures}"
    )
    lines.append(
        "Noise gate: "
        f"regex_skipped={metrics.regex_skipped} "
        + _format_counts(metrics.noise_counts, limit=6)
    )
    lines.append(
        "Cloud: "
        f"s3_buckets={metrics.s3_buckets} "
        f"firebase_projects={metrics.firebase_projects} "
        f"unknown_kind={metrics.unknown_kind_count} "
        f"unknown_ratio={metrics.unknown_kind_ratio:.2f}"
    )

    if metrics.strings_by_split and len(metrics.strings_by_split) > 1:
        lines.append(
            "Splits: "
            + _format_counts(metrics.strings_by_split, limit=6)
        )
    if metrics.strings_by_locale:
        lines.append(
            "Locales: " + _format_counts(metrics.strings_by_locale, limit=6)
        )

    top_tags = _top_tag_counts(summary)
    if top_tags:
        formatted_tags = ", ".join(f"{tag}={count}" for tag, count in top_tags)
        lines.append(f"Top tags: {formatted_tags}")

    issues = _exploratory_issues(summary)
    if issues:
        lines.append("Potential issues:")
        for issue in issues:
            lines.append(f"  - {issue}")

    samples = _select_exploratory_samples(summary, limit=sample_limit)
    if samples:
        lines.append("Samples (evidence):")
        for record in samples:
            pointer = (
                f"{record.source_path}@"
                f"{record.byte_offset if record.byte_offset is not None else 'na'}"
            )
            preview = record.value_preview
            lines.append(f"  {preview}  {pointer}")

    return "\n".join(lines)


def _first_apk_hash(summary: CollectionSummary) -> str:
    for record in summary.strings:
        if record.apk_sha256:
            return record.apk_sha256[:16]
    return "unknown"


def _format_ratio(ratio: float, numerator: int, denominator: int) -> str:
    if denominator:
        return f"{ratio:.2f} ({numerator}/{denominator})"
    return "0.00 (0/0)"


def _select_exploratory_samples(
    summary: CollectionSummary, *, limit: int = 3
) -> list[NormalizedString]:
    records = [record for record in summary.strings if not record.is_allowlisted]
    records.sort(
        key=lambda record: (
            len(record.tags),
            _CONFIDENCE_PRIORITY.get(record.confidence, 0),
            -1 if record.derived else 0,
        ),
        reverse=True,
    )
    return records[:limit]


def _format_counts(values: Mapping[str, int], *, limit: int = 5) -> str:
    ordered = sorted(values.items(), key=lambda item: (-item[1], item[0]))
    display = [f"{key}={value}" for key, value in ordered[:limit]]
    if len(ordered) > limit:
        remainder = sum(value for _, value in ordered[limit:])
        display.append(f"other={remainder}")
    return ", ".join(display)


def _top_tag_counts(summary: CollectionSummary, *, limit: int = 5) -> list[tuple[str, int]]:
    counter: Counter[str] = Counter()
    for record in summary.strings:
        if record.is_allowlisted:
            continue
        counter.update(record.tags)
    return counter.most_common(limit)


def _exploratory_issues(summary: CollectionSummary) -> list[str]:
    metrics = summary.metrics
    issues: list[str] = [
        f"[{issue.severity.upper()}] {issue.message}"
        for issue in metrics.issue_flags
    ]

    sensitive_splits = sorted(
        {record.split_id for record in summary.strings if not record.is_allowlisted and record.split_id != "base"}
    )
    if sensitive_splits:
        issues.append(
            "[INFO] Sensitive hits located in non-base splits: "
            + ", ".join(sensitive_splits)
        )

    locale_sensitive = sorted(
        {
            record.locale_qualifier
            for record in summary.strings
            if not record.is_allowlisted
            and record.locale_qualifier
        }
    )
    if locale_sensitive:
        issues.append(
            "[INFO] Sensitive hits constrained to locale qualifiers: "
            + ", ".join(locale_sensitive)
        )

    return issues


__all__ = ["render_exploratory_summary"]
