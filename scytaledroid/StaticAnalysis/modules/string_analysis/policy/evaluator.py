"""Policy evaluation wrappers used by the refactored extractor."""

from __future__ import annotations

from dataclasses import dataclass

from ..allowlist import NoisePolicy, PolicyContext
from ..bucketing.classifier import BucketDecision
from ..parsing.host_normalizer import NormalizedHost


def _normalise_source_path(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("\\", "/").lower()


@dataclass(frozen=True)
class PolicyOutcome:
    action: str | None = None
    rule: str | None = None
    reason: str | None = None
    tag: str | None = None
    note: str | None = None
    severity: str | None = None

    @property
    def is_actionable(self) -> bool:
        return bool(self.action and self.action not in {"none"})


def evaluate(
    policy: NoisePolicy,
    bucket_decision: BucketDecision | None,
    normalized_host: NormalizedHost | None,
    *,
    source_path: str | None,
    value: str,
    scheme: str | None,
) -> PolicyOutcome:
    buckets = tuple(bucket_decision.buckets if bucket_decision else ())
    if not buckets:
        buckets = policy.default_buckets
    host_full = normalized_host.full_host if normalized_host else None
    host_registrable = normalized_host.etld_plus_one if normalized_host else None
    if host_full and host_full in policy.block_override_full:
        return PolicyOutcome()
    if host_registrable and host_registrable in policy.block_override_registrable:
        return PolicyOutcome()

    context = PolicyContext(
        value=value,
        source=_normalise_source_path(source_path),
        host=host_full,
        scheme=scheme.lower() if scheme else None,
        buckets=frozenset(buckets),
        host_variants=frozenset(
            variant
            for variant in (host_full, host_registrable)
            if variant
        ),
        host_full=host_full,
        host_registrable=host_registrable,
    )

    for rule in policy.rules:
        decision = rule.evaluate(context, policy)
        if not decision:
            continue
        if decision.tag == "guardrail_runtime" and context.buckets:
            disallowed = {"dynamic_endpoints", "runtime_contacts"}
            if context.buckets.isdisjoint(disallowed):
                continue
        return PolicyOutcome(
            action=decision.action,
            rule=decision.rule,
            reason=decision.reason,
            tag=decision.tag,
            note=decision.note,
            severity=decision.severity,
        )
    return PolicyOutcome(
        action=None,
    )


__all__ = ["PolicyOutcome", "evaluate"]
