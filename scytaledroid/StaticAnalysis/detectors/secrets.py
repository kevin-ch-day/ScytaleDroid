"""Secrets & credentials detector leveraging string-index patterns."""

from __future__ import annotations

from pathlib import Path
from time import perf_counter
from typing import Dict, Mapping, Sequence

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
    groups: Mapping[str, MatchGroup],
    *,
    apk_path: Path,
    limit: int = 2,
) -> Sequence[EvidencePointer]:
    pointers: list[EvidencePointer] = []
    for _, group in sorted(groups.items()):
        if not group.accepted:
            continue
        for evaluated in group.accepted:
            pointers.append(_string_pointer(evaluated.record, apk_path=apk_path))
            if len(pointers) >= limit:
                return tuple(pointers)
    return tuple(pointers)


def _build_findings(
    groups: Mapping[str, MatchGroup],
    *,
    apk_path: Path,
) -> Sequence[Finding]:
    findings: list[Finding] = []

    for pattern_name, group in sorted(groups.items()):
        if not group.accepted:
            continue

        pattern = group.pattern
        sample_record = group.accepted[0].record
        count = group.accepted_count

        summary = (
            f"Detected {count} potential secret{'' if count == 1 else 's'} matching "
            f"{pattern.description.lower()}."
        )

        supporting_hashes = [
            match.record.string_entry.sha256 for match in group.accepted[:10]
        ]
        pointer = _string_pointer(sample_record, apk_path=apk_path)

        origin_types = sorted(
            {
                match.record.string_entry.origin_type
                for match in group.accepted
            }
        )
        filter_reasons = sorted(
            {
                reason
                for match in group.filtered
                for reason in match.reasons
                if reason
            }
        )

        metrics_payload: Dict[str, object] = {
            "hashes": supporting_hashes,
            "filtered": group.filtered_count,
            "origin_types": origin_types,
            "pattern": pattern.name,
            "category": pattern.category,
        }

        if filter_reasons:
            metrics_payload["filtered_reasons"] = filter_reasons

        if pattern.provider:
            metrics_payload["provider"] = pattern.provider
        if pattern.tags:
            metrics_payload["tags"] = pattern.tags

        findings.append(
            Finding(
                finding_id=f"secret_{pattern_name}",
                title=pattern.description,
                severity_gate=SeverityLevel.P1,
                category_masvs=MasvsCategory.PRIVACY,
                status=Badge.WARN,
                because=summary,
                evidence=(pointer,),
                remediate="Rotate the credential and remove hardcoded secrets from the artifact.",
                metrics=metrics_payload,
                tags=("secret", pattern_name),
            )
        )

    return tuple(findings)


def _build_metrics(batch: MatchBatch) -> Dict[str, object]:
    secret_types: Dict[str, Dict[str, object]] = {}

    for pattern_name, group in sorted(batch.groups.items()):
        pattern = group.pattern
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
            "category": pattern.category,
        }

        if pattern.provider:
            entry_metrics["provider"] = pattern.provider
        if pattern.tags:
            entry_metrics["tags"] = pattern.tags
        if filter_reasons:
            entry_metrics["filtered_reasons"] = filter_reasons

        secret_types[pattern_name] = entry_metrics

    return {
        "secret_types": secret_types,
        "matched_strings": batch.matched_total,
        "real_strings": batch.accepted_total,
        "filtered_strings": batch.filtered_total,
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
        metrics = _build_metrics(batch)
        findings = _build_findings(batch.groups, apk_path=context.apk_path)
        evidence = _collect_result_evidence(
            batch.groups,
            apk_path=context.apk_path,
            limit=evidence_limit,
        )

        if findings:
            metrics_status = "warn"
        elif batch.filtered_total:
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
