"""Cross-fragment detectors that require correlated evidence."""
from __future__ import annotations

from typing import Iterator, Sequence, Tuple

from ..schema import Observation
from .common import Fragment, build_evidence, context_window, entropy
from .patterns import AWS_ACCESS_KEY, AWS_SECRET_KEY


def iter_aws_pair_observations(fragments: Sequence[Fragment]) -> Iterator[Observation]:
    access_hits: list[Tuple[Fragment, "re.Match[str]"]] = []
    secret_hits: list[Tuple[Fragment, "re.Match[str]"]] = []

    import re

    for fragment in fragments:
        value = fragment.entry.value
        for match in AWS_ACCESS_KEY.finditer(value):
            access_hits.append((fragment, match))
        for match in AWS_SECRET_KEY.finditer(value):
            secret_hits.append((fragment, match))

    for fragment, access_match in access_hits:
        access_offset = fragment.base_offset + access_match.start()
        for secret_fragment, secret_match in secret_hits:
            secret_offset = secret_fragment.base_offset + secret_match.start()
            if secret_fragment.entry.origin != fragment.entry.origin:
                continue
            if abs(secret_offset - access_offset) > 200:
                continue
            secret_value = secret_match.group(0)
            entropy_score = entropy(secret_value)
            if entropy_score < 4.8:
                continue
            context = context_window(secret_fragment.entry.value, secret_match.start(), secret_match.end())
            tags = ("aws-pair", "auth-adjacent")
            evidence = build_evidence(secret_fragment, secret_match.start())
            masked_secret = f"{secret_value[:4]}…{secret_value[-4:]}"
            value = f"{access_match.group(0)}::{masked_secret}"
            yield Observation(
                value=value,
                src=fragment.entry.origin,
                tags=tags,
                category="secret",
                confidence="high",
                evidence=evidence,
                context=context,
                sha_short=fragment.entry.sha256[:8],
            )
            break


__all__ = ["iter_aws_pair_observations"]
