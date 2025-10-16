"""File: scytaledroid/StaticAnalysis/modules/string_analysis/bucket_meta.py

Bucket metadata definitions for the string-analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BucketMetadata:
    """Describes how a string-analysis bucket should appear in reports."""

    key: str
    label: str
    description: str | None = None
    highlight: bool = True
    priority: int = 0


_BUCKETS: tuple[BucketMetadata, ...] = (
    BucketMetadata(
        key="endpoints",
        label="Network endpoints",
        description="URLs, sockets, and remote hosts referenced by the app.",
        priority=100,
    ),
    BucketMetadata(
        key="http_cleartext",
        label="HTTP cleartext",
        description="Non-TLS endpoints and websocket hosts.",
        priority=95,
    ),
    BucketMetadata(
        key="api_keys",
        label="API keys & tokens",
        description="Credential-like values (API keys, JWTs, access tokens).",
        priority=90,
    ),
    BucketMetadata(
        key="high_entropy",
        label="High-entropy strings",
        description="Potential secrets detected via entropy thresholds.",
        priority=85,
    ),
    BucketMetadata(
        key="analytics_ids",
        label="Analytics identifiers",
        description="Tracking IDs and analytics SDK identifiers.",
        priority=80,
    ),
    BucketMetadata(
        key="cloud_refs",
        label="Cloud references",
        description="References to cloud buckets, CDN hosts, and storage endpoints.",
        priority=70,
    ),
    BucketMetadata(
        key="ipc",
        label="IPC channels",
        description="Binder/intent action strings and other IPC surfaces.",
        priority=60,
    ),
    BucketMetadata(
        key="uris",
        label="URIs & file paths",
        description="content:// and file:// style URIs exposed by the app.",
        priority=55,
    ),
    BucketMetadata(
        key="flags",
        label="Feature flags",
        description="Feature toggles, environment markers, and debug flags.",
        priority=45,
    ),
    BucketMetadata(
        key="certs",
        label="Certificates & pins",
        description="Public-key pinning and certificate references.",
        highlight=False,
        priority=40,
    ),
)


BUCKET_ORDER: tuple[str, ...] = tuple(metadata.key for metadata in _BUCKETS)
BUCKET_LABELS: dict[str, str] = {metadata.key: metadata.label for metadata in _BUCKETS}
BUCKET_METADATA: dict[str, BucketMetadata] = {
    metadata.key: metadata for metadata in _BUCKETS
}


__all__ = [
    "BucketMetadata",
    "BUCKET_ORDER",
    "BUCKET_LABELS",
    "BUCKET_METADATA",
]
