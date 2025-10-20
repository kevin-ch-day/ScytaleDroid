"""Secrets & credentials detector leveraging string-index patterns."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from time import perf_counter
from typing import Callable, Dict, Mapping, MutableMapping, Sequence

from ..core.context import DetectorContext, SecretsSamplerConfig
from ..core.findings import (
    Badge,
    DetectorResult,
    EvidencePointer,
    Finding,
    MasvsCategory,
    SeverityLevel,
)
from ..core.pipeline import make_detector_result
from ..modules.string_analysis.matcher import (
    DEFAULT_SECRET_FILTERS,
    EvaluatedMatch,
    MatchBatch,
    MatchGroup,
    MatchRecord,
    StringMatcher,
)
from .base import BaseDetector, register_detector


def _string_pointer(
    match: MatchRecord,
    *,
    apk_path: Path,
) -> EvidencePointer:
    base_location = apk_path.resolve().as_posix()
    entry = match.string_entry
    pattern = match.pattern
    extra: Dict[str, object] = {
        "origin": entry.origin,
        "origin_type": entry.origin_type,
        "pattern": pattern.name,
    }
    return EvidencePointer(
        location=f"{base_location}!string[{entry.origin}]",
        hash_short=f"#h:{entry.sha256[:8]}",
        description=f"{entry.origin} #h:{entry.sha256[:12]}",
        extra=extra,
    )


def _collect_result_evidence(
    prepared: Mapping[str, Mapping[str, object]],
    *,
    apk_path: Path,
    limit: int = 2,
) -> Sequence[EvidencePointer]:
    pointers: list[EvidencePointer] = []
    for pattern_name in sorted(prepared.keys()):
        matches = prepared[pattern_name]["matches"]
        for evaluated in matches:
            pointers.append(_string_pointer(evaluated.record, apk_path=apk_path))
            if len(pointers) >= limit:
                return tuple(pointers)
    return tuple(pointers)


def _collect_filter_reasons(group: MatchGroup) -> Sequence[str]:
    reasons = {
        reason
        for match in group.filtered
        for reason in match.reasons
        if reason
    }
    return tuple(sorted(reasons))


def _decode_segment(segment: str) -> str:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8")


def _looks_like_jwt(fragment: str) -> bool:
    parts = fragment.split(".")
    if len(parts) != 3:
        return False
    try:
        header = json.loads(_decode_segment(parts[0]))
        payload = json.loads(_decode_segment(parts[1]))
    except Exception:
        return False
    return isinstance(header, dict) and isinstance(payload, dict)


def _looks_like_real_aws_key(fragment: str) -> bool:
    upper = fragment.upper()
    if upper.endswith("EXAMPLE") or "TEST" in upper:
        return False
    return upper.startswith("AKIA") or upper.startswith("ASIA")


def _looks_like_secret_value(fragment: str) -> bool:
    upper = fragment.upper()
    if "EXAMPLE" in upper or "TEST" in upper or "DEMO" in upper:
        return False
    return len(fragment.strip()) >= 32


_SECRET_VALIDATORS: Mapping[str, Callable[[str], bool]] = {
    "jwt_token": _looks_like_jwt,
    "aws_access_key": _looks_like_real_aws_key,
    "aws_secret_access_key": _looks_like_secret_value,
}

_VALIDATOR_LABELS: Mapping[str, str] = {
    "jwt_token": "jwt_shape",
    "aws_access_key": "aws_key_prefix",
    "aws_secret_access_key": "aws_secret_entropy",
}

_PLACEHOLDER_TOKENS = (
    "example",
    "sample",
    "changeme",
    "dummy",
    "test",
    "placeholder",
    "fake",
    "demo",
    "localhost",
)

_DEBUG_TOKENS = (
    "debug",
    "qa",
    "staging",
    "dev",
)


def _placeholder_reasons(match: MatchRecord) -> tuple[str, ...]:
    reasons: set[str] = set()
    fragment = match.fragment.lower()
    if any(token in fragment for token in _PLACEHOLDER_TOKENS):
        reasons.add("placeholder")

    entry = match.string_entry
    origin = (entry.origin or "").lower()
    context = (entry.context or "").lower()

    if any(token in origin for token in _DEBUG_TOKENS):
        reasons.add("debug_origin")
    if any(token in context for token in _DEBUG_TOKENS):
        reasons.add("debug_context")
    if any(token in origin for token in ("test", "sample")):
        reasons.add("test_namespace")
    return tuple(sorted(reasons))


def _evaluate_match(match: MatchRecord) -> tuple[bool, tuple[str, ...], tuple[str, ...]]:
    validator = _SECRET_VALIDATORS.get(match.pattern.name)
    hits: set[str] = set()
    reasons: list[str] = list(_placeholder_reasons(match))

    if validator is not None:
        try:
            if validator(match.fragment):
                hits.add(_VALIDATOR_LABELS.get(match.pattern.name, match.pattern.name))
            else:
                reasons.append("validator_failed")
        except Exception:
            reasons.append("validator_error")

    keep = not reasons
    return keep, tuple(sorted(hits)), tuple(sorted(set(reasons)))


def _is_usage_correlated(matches: Sequence[EvaluatedMatch]) -> bool:
    if len({m.record.string_entry.origin for m in matches}) > 1:
        return True
    for evaluated in matches:
        context = (evaluated.record.string_entry.context or "").lower()
        if any(token in context for token in ("auth", "token", "header", "secret")):
            return True
        if evaluated.record.string_entry.origin_type in {"network", "http", "request"}:
            return True
    return False


def _prepare_group_insights(
    groups: Mapping[str, MatchGroup]
) -> MutableMapping[str, Mapping[str, object]]:
    prepared: MutableMapping[str, Mapping[str, object]] = {}
    for pattern_name, group in groups.items():
        if not group.accepted:
            continue
        validated: list[EvaluatedMatch] = []
        validator_hits: set[str] = set()
        suppressed: list[str] = []
        for candidate in group.accepted:
            keep, hits, reasons = _evaluate_match(candidate.record)
            if keep:
                validated.append(candidate)
                validator_hits.update(hits)
            else:
                suppressed.extend(reasons)
        if not validated:
            continue
        info: Dict[str, object] = {
            "group": group,
            "matches": tuple(validated),
            "validator_dropped": group.accepted_count - len(validated),
            "usage_correlated": _is_usage_correlated(validated),
            "validator_hits": tuple(sorted(validator_hits)),
            "suppressed_reasons": tuple(sorted(set(suppressed))),
        }
        hits_present = bool(validator_hits)
        correlated = bool(info["usage_correlated"])
        confidence = "high" if hits_present and correlated else "medium" if hits_present or correlated else "low"
        info["confidence"] = confidence
        prepared[pattern_name] = info
    return prepared


def _build_findings(
    prepared: Mapping[str, Mapping[str, object]],
    *,
    apk_path: Path,
) -> Sequence[Finding]:
    findings: list[Finding] = []

    for pattern_name, info in sorted(prepared.items()):
        group = info["group"]
        matches: Sequence[EvaluatedMatch] = info["matches"]
        if not matches:
            continue

        pattern = group.pattern
        sample_record = matches[0].record
        count = len(matches)

        summary = (
            f"Detected {count} potential secret{'' if count == 1 else 's'} matching "
            f"{pattern.description.lower()}."
        )

        supporting_hashes = [
            match.record.string_entry.sha256 for match in matches[:10]
        ]
        pointer = _string_pointer(sample_record, apk_path=apk_path)

        origin_types = sorted(
            {
                match.record.string_entry.origin_type
                for match in matches
            }
        )

        filter_reasons = _collect_filter_reasons(group)

        validator_hits = info.get("validator_hits", ())
        suppressed_reasons = info.get("suppressed_reasons", ())
        confidence = info.get("confidence", "low")
        if confidence == "low":
            continue

        metrics_payload: Dict[str, object] = {
            "hashes": supporting_hashes,
            "filtered": group.filtered_count,
            "origin_types": origin_types,
            "pattern": pattern.name,
            "category": pattern.category,
        }

        if info.get("validator_dropped"):
            metrics_payload["validator_dropped"] = info["validator_dropped"]
        metrics_payload["usage_correlated"] = bool(info.get("usage_correlated"))
        metrics_payload["confidence"] = confidence
        if validator_hits:
            metrics_payload["validator_hits"] = validator_hits
        if suppressed_reasons:
            metrics_payload["suppressed_reasons"] = suppressed_reasons

        if filter_reasons:
            metrics_payload["filtered_reasons"] = filter_reasons

        if pattern.provider:
            metrics_payload["provider"] = pattern.provider
        if pattern.tags:
            metrics_payload["tags"] = pattern.tags

        status = Badge.WARN if confidence == "high" else Badge.INFO

        findings.append(
            Finding(
                finding_id=f"secret_{pattern_name}",
                title=pattern.description,
                severity_gate=SeverityLevel.P1,
                category_masvs=MasvsCategory.PRIVACY,
                status=status,
                because=summary,
                evidence=(pointer,),
                remediate="Rotate the credential and remove hardcoded secrets from the artifact.",
                metrics=metrics_payload,
                tags=("secret", pattern_name),
            )
        )

    return tuple(findings)


def _build_metrics(
    batch: MatchBatch,
    prepared: Mapping[str, Mapping[str, object]],
) -> Dict[str, object]:
    secret_types: Dict[str, Dict[str, object]] = {}
    validated_total = 0

    for pattern_name, group in sorted(batch.groups.items()):
        pattern = group.pattern
        info = prepared.get(pattern_name)
        accepted_after_validation = len(info["matches"]) if info else 0
        validated_total += accepted_after_validation
        validator_dropped = info.get("validator_dropped") if info else group.accepted_count
        filter_reasons = sorted(
            {
                reason
                for match in group.filtered
                for reason in match.reasons
                if reason
            }
        )

        entry_metrics: Dict[str, object] = {
            "found": group.accepted_count,
            "filtered": group.filtered_count,
            "accepted_after_validation": accepted_after_validation,
            "validator_dropped": int(validator_dropped or 0),
            "category": pattern.category,
        }

        if pattern.provider:
            entry_metrics["provider"] = pattern.provider
        if pattern.tags:
            entry_metrics["tags"] = pattern.tags
        if info is not None:
            entry_metrics["usage_correlated"] = bool(info.get("usage_correlated"))
            entry_metrics["confidence"] = info.get("confidence", "low")
            if info.get("validator_hits"):
                entry_metrics["validator_hits"] = info["validator_hits"]
            if info.get("suppressed_reasons"):
                entry_metrics["suppressed_reasons"] = info["suppressed_reasons"]
        if filter_reasons:
            entry_metrics["filtered_reasons"] = filter_reasons

        secret_types[pattern_name] = entry_metrics

    return {
        "secret_types": secret_types,
        "matched_strings": batch.matched_total,
        "real_strings": batch.accepted_total,
        "filtered_strings": batch.filtered_total,
        "validated_strings": validated_total,
    }


@register_detector
class SecretsDetector(BaseDetector):
    """Detector that surfaces potential hardcoded credentials."""

    detector_id = "secrets_credentials"
    name = "Secrets & Credentials detector"
    default_profiles = ("quick", "full")
    section_key = "secrets"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()
        index = context.string_index
        if index is None or index.is_empty():
            metrics = {
                "matched_strings": 0,
                "real_strings": 0,
                "filtered_strings": 0,
                "status": "ok",
            }
            return make_detector_result(
                detector_id=self.detector_id,
                section_key=self.section_key,
                status=Badge.OK,
                started_at=started,
                findings=tuple(),
                metrics={key: value for key, value in metrics.items() if key != "status"},
                evidence=tuple(),
            )

        sampler_config = context.config.secrets_sampler
        allowed_types: tuple[str, ...] | None = None
        hits_limit: int | None = None
        min_entropy: float | None = None
        evidence_limit = 2

        if isinstance(sampler_config, SecretsSamplerConfig):
            scope = (sampler_config.scope or "").lower()
            if scope == "dex-only":
                allowed_types = ("code",)
            elif scope == "resources-only":
                allowed_types = ("resource", "raw", "asset")
            hits_limit = sampler_config.hits_per_bucket if sampler_config.hits_per_bucket > 0 else None
            min_entropy = sampler_config.entropy_threshold if sampler_config.entropy_threshold > 0 else None
            evidence_limit = min(max(1, sampler_config.hits_per_bucket), 10)

        matcher = StringMatcher(index, filters=DEFAULT_SECRET_FILTERS)
        batch = matcher.match(
            allowed_origin_types=allowed_types,
            max_hits_per_pattern=hits_limit,
            min_entropy=min_entropy,
        )
        prepared = _prepare_group_insights(batch.groups)
        metrics = _build_metrics(batch, prepared)
        findings = _build_findings(prepared, apk_path=context.apk_path)
        evidence = _collect_result_evidence(
            prepared,
            apk_path=context.apk_path,
            limit=evidence_limit,
        )

        if findings:
            metrics_status = "warn"
        elif batch.filtered_total or (
            metrics.get("validated_strings", 0) == 0 and batch.accepted_total
        ):
            metrics_status = "filtered"
        else:
            metrics_status = "ok"

        metrics["status"] = metrics_status

        status_key = metrics_status
        badge = {
            "warn": Badge.WARN,
            "ok": Badge.OK,
            "filtered": Badge.INFO,
        }.get(status_key, Badge.INFO)

        metrics_payload = dict(metrics)
        metrics_payload.pop("status", None)

        return make_detector_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=badge,
            started_at=started,
            findings=findings,
            metrics=metrics_payload,
            evidence=evidence,
        )


__all__ = ["SecretsDetector"]
