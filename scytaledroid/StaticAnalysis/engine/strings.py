"""Lightweight baseline string analysis helpers."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Dict, List, Mapping, MutableMapping, Sequence

from scytaledroid.StaticAnalysis._androguard import APK

from ..modules.string_analysis import build_string_index

_ENDPOINT_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_CONTENT_URI_PATTERN = re.compile(r"content://[^\s\"'<>]+", re.IGNORECASE)
_FILE_URI_PATTERN = re.compile(r"file://[^\s\"'<>]+", re.IGNORECASE)

_ANALYTICS_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "ga": re.compile(r"UA-\d{4,}-\d+", re.IGNORECASE),
    "gtag": re.compile(r"G-[A-Z0-9]{6,}", re.IGNORECASE),
    "firebase": re.compile(r"1:[0-9]{8,}:[a-z0-9]{10,}", re.IGNORECASE),
    "admob": re.compile(r"ca-app-pub-[0-9]{16}/[0-9]{10}", re.IGNORECASE),
}

_API_KEY_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "aws_access": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret": re.compile(r"(?<![A-Z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    "google_api": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "slack": re.compile(r"xox[pbar]-[0-9A-Za-z]{10,}"),
}

_CLOUD_HINTS: Mapping[str, str] = {
    "s3.amazonaws.com": "aws",
    "amazonaws.com": "aws",
    "firebaseio.com": "firebase",
    "storage.googleapis.com": "gcs",
    "blob.core.windows.net": "azure",
    "digitaloceanspaces.com": "do",
    "cloudfront.net": "cloudfront",
}

_IPC_HINTS: Mapping[str, str] = {
    "android.intent.action": "intent",
    "android.permission": "permission",
    "com.android.launcher": "component",
}

_FLAG_HINTS = (
    "ENABLE_",
    "DISABLE_",
    "FEATURE_",
    "FLAG_",
)


@dataclass(frozen=True)
class StringHit:
    """Represents a categorized string hit for baseline analysis."""

    bucket: str
    value: str
    src: str
    tag: str
    sha256: str
    masked: str | None = None


_BUCKET_ORDER: tuple[str, ...] = (
    "endpoints",
    "http_cleartext",
    "api_keys",
    "analytics_ids",
    "cloud_refs",
    "ipc",
    "uris",
    "flags",
    "certs",
    "high_entropy",
)


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


def _classify_value(value: str) -> Sequence[tuple[str, str, str | None, str]]:
    """Return iterable of ``(bucket, tag, masked, match_value)``."""

    matches: list[tuple[str, str, str | None, str]] = []

    for endpoint in _ENDPOINT_PATTERN.findall(value):
        tag = "https" if endpoint.lower().startswith("https://") else "http"
        matches.append(("endpoints", tag, None, endpoint))
        if tag == "http":
            matches.append(("http_cleartext", "http", None, endpoint))

    for name, pattern in _API_KEY_PATTERNS.items():
        for match in pattern.findall(value):
            masked = _mask_value(match)
            matches.append(("api_keys", name, masked, match))

    for name, pattern in _ANALYTICS_PATTERNS.items():
        for match in pattern.findall(value):
            matches.append(("analytics_ids", name, None, match))

    lowered = value.lower()
    for fragment, label in _CLOUD_HINTS.items():
        if fragment in lowered:
            matches.append(("cloud_refs", label, None, value))
            break

    for fragment, label in _IPC_HINTS.items():
        if fragment in value:
            matches.append(("ipc", label, None, value))
            break

    if _CONTENT_URI_PATTERN.search(value) or _FILE_URI_PATTERN.search(value):
        matches.append(("uris", "uri", None, value))

    if any(fragment in value for fragment in _FLAG_HINTS):
        matches.append(("flags", "flag", None, value))

    if "-----BEGIN CERTIFICATE" in value or "sha256/" in value:
        matches.append(("certs", "cert", None, value))

    if len(value) >= 16 and _entropy(value) >= 4.2:
        matches.append(("high_entropy", "entropy", _mask_value(value), value))

    return matches


def analyse_strings(apk_path: str) -> Mapping[str, object]:
    """Return baseline string buckets for the APK at *apk_path*."""

    try:
        apk = APK(apk_path)
    except Exception:
        return {"counts": {bucket: 0 for bucket in _BUCKET_ORDER}, "samples": {}}

    try:
        index = build_string_index(apk, include_resources=True)
    except Exception:
        return {"counts": {bucket: 0 for bucket in _BUCKET_ORDER}, "samples": {}}

    entries = sorted(
        index.strings,
        key=lambda entry: (
            0 if entry.origin_type == "code" else 1,
            entry.origin,
            entry.value,
        ),
    )

    counts: Dict[str, int] = {bucket: 0 for bucket in _BUCKET_ORDER}
    samples: Dict[str, List[StringHit]] = {}

    for entry in entries:
        hits = _classify_value(entry.value)
        if not hits:
            continue
        src = _normalise_src(entry.origin, entry.origin_type, entry.sha256)
        for bucket, tag, masked, match_value in hits:
            counts[bucket] = counts.get(bucket, 0) + 1
            display_value = masked or match_value
            record = StringHit(
                bucket=bucket,
                value=display_value,
                src=src,
                tag=tag,
                sha256=entry.sha256,
                masked=masked,
            )
            samples.setdefault(bucket, []).append(record)

    ordered_samples: Dict[str, List[Mapping[str, object]]] = {}
    for bucket in _BUCKET_ORDER:
        hits = samples.get(bucket)
        if not hits:
            continue
        unique: MutableMapping[str, StringHit] = {}
        for hit in hits:
            key = f"{hit.value}|{hit.src}|{hit.tag}"
            unique.setdefault(key, hit)
        ordered = sorted(unique.values(), key=lambda item: (item.value, item.src, item.tag))
        ordered_samples[bucket] = [
            {
                "value": hit.value,
                "value_masked": hit.masked,
                "src": hit.src,
                "tag": hit.tag,
                "sha256": hit.sha256,
            }
            for hit in ordered
        ]

    return {"counts": counts, "samples": ordered_samples}


__all__ = ["analyse_strings"]
