"""Bucket assignment helpers for string analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from ..parsing.host_normalizer import NormalizedHost
from ..parsing.url_tokenizer import Candidate
from ..parsing.validators import is_ip, is_localhost, is_placeholder, is_real_host
from ..parsing.validators import is_private_ip


@dataclass(frozen=True)
class BucketDecision:
    buckets: tuple[str, ...]
    tags: tuple[str, ...] = ()
    placeholder: bool = False


def classify(candidate: Candidate, normalized: NormalizedHost) -> BucketDecision:
    host = candidate.host or normalized.full_host
    if not host:
        return BucketDecision(buckets=())
    if is_placeholder(candidate.raw) or is_placeholder(host):
        return BucketDecision(buckets=(), tags=("placeholder",), placeholder=True)
    if not is_real_host(host):
        return BucketDecision(buckets=())

    buckets: list[str] = []
    tags: list[str] = []
    scheme = (candidate.scheme or "").lower()

    if scheme == "http":
        buckets.extend(["endpoints", "http_cleartext"])
    elif scheme == "ws":
        buckets.extend(["endpoints", "http_cleartext"])
    elif scheme in {"https", "wss"}:
        buckets.append("endpoints")

    if is_ip(host) and not is_private_ip(host):
        tags.append("ip-literal")
    elif not is_localhost(host):
        tags.append("prod-domain")

    return BucketDecision(buckets=tuple(dict.fromkeys(buckets)), tags=tuple(tags))


__all__ = ["BucketDecision", "classify"]
