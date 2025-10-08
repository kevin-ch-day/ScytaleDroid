"""Split APK correlation helpers."""

from __future__ import annotations

from typing import Dict, Mapping, Sequence

from ...core.context import DetectorContext
from ...core.findings import Badge, EvidencePointer, Finding, MasvsCategory, SeverityLevel
from ...persistence.reports import StoredReport, list_reports
from .models import NetworkSnapshot
from .network import previous_network_snapshot
from .utils import report_pointer


def _collect_related_reports(
    context: DetectorContext, split_id: str, current_sha: str | None
) -> list[StoredReport]:
    related_reports: list[StoredReport] = []
    for stored in list_reports():
        report = stored.report
        metadata = getattr(report, "metadata", {})
        if not isinstance(metadata, Mapping):
            continue
        if str(metadata.get("split_group_id")) != split_id:
            continue
        if report.hashes.get("sha256") == current_sha:
            continue
        related_reports.append(stored)
    return related_reports


def split_findings_and_metrics(
    context: DetectorContext, current_snapshot: NetworkSnapshot
) -> tuple[Sequence[Finding], Mapping[str, object]]:
    metadata = context.metadata or {}
    split_group_id = metadata.get("split_group_id")
    if split_group_id is None:
        return tuple(), {}

    split_id = str(split_group_id)
    current_sha = context.hashes.get("sha256")
    related_reports = _collect_related_reports(context, split_id, current_sha)

    metrics: Dict[str, object] = {
        "group_id": split_id,
        "members": [str(metadata.get("artifact") or context.apk_path.name)],
    }

    findings: list[Finding] = []
    if not related_reports:
        return tuple(findings), metrics

    metrics["members"].extend(
        str(
            stored.report.metadata.get("artifact")
            if isinstance(stored.report.metadata, Mapping)
            else stored.report.file_name
        )
        for stored in related_reports
    )

    component_union = {
        "activities": set(context.exported_components.activities),
        "services": set(context.exported_components.services),
        "receivers": set(context.exported_components.receivers),
        "providers": set(context.exported_components.providers),
    }

    for stored in related_reports:
        exported = stored.report.exported_components
        component_union["activities"].update(exported.activities)
        component_union["services"].update(exported.services)
        component_union["receivers"].update(exported.receivers)
        component_union["providers"].update(exported.providers)

    metrics["union_exported"] = {key: sorted(values) for key, values in component_union.items()}

    extra_components: Dict[str, tuple[str, ...]] = {}
    for key, values in component_union.items():
        current_values = set(getattr(context.exported_components, key))
        extras = tuple(sorted(values - current_values))
        if extras:
            extra_components[key] = extras

    if extra_components:
        evidence: list[EvidencePointer] = []
        for component_type, names in extra_components.items():
            for stored in related_reports:
                exported = getattr(stored.report.exported_components, component_type)
                intersection = sorted(set(exported) & set(names))
                if not intersection:
                    continue
                evidence.append(
                    EvidencePointer(
                        location=report_pointer(stored.path),
                        description=f"{component_type} in companion split",
                        extra={"component": component_type, "names": intersection},
                    )
                )
                if len(evidence) >= 3:
                    break
            if len(evidence) >= 3:
                break

        findings.append(
            Finding(
                finding_id="split_export_union",
                title="Split group exposes additional components",
                severity_gate=SeverityLevel.P1,
                category_masvs=MasvsCategory.PLATFORM,
                status=Badge.WARN,
                because="Other splits in the package export components not present in this artifact.",
                evidence=tuple(evidence),
                metrics={"extra_components": extra_components},
                remediate="Audit all split APK members together and gate exposed components with signature permissions.",
            )
        )

    http_union = set(current_snapshot.http_hosts)
    cleartext_union = set(current_snapshot.cleartext_domains)
    pinned_union = set(current_snapshot.pinned_domains)

    for stored in related_reports:
        snapshot = previous_network_snapshot(stored.report)
        http_union.update(snapshot.http_hosts)
        cleartext_union.update(snapshot.cleartext_domains)
        pinned_union.update(snapshot.pinned_domains)

    metrics["union_http_hosts"] = sorted(http_union)
    metrics["union_cleartext_domains"] = sorted(cleartext_union)
    metrics["union_pinned_domains"] = sorted(pinned_union)

    extra_http = sorted(http_union - set(current_snapshot.http_hosts))
    if extra_http:
        evidence = []
        for stored in related_reports:
            snapshot = previous_network_snapshot(stored.report)
            overlap = sorted(set(snapshot.http_hosts) & set(extra_http))
            if not overlap:
                continue
            evidence.append(
                EvidencePointer(
                    location=report_pointer(stored.path),
                    description="HTTP endpoints in companion split",
                    extra={"hosts": overlap},
                )
            )
            if len(evidence) >= 3:
                break

        findings.append(
            Finding(
                finding_id="split_http_union",
                title="Companion split introduces HTTP endpoints",
                severity_gate=SeverityLevel.P1,
                category_masvs=MasvsCategory.NETWORK,
                status=Badge.WARN,
                because="Other split members expose additional cleartext HTTP endpoints.",
                evidence=tuple(evidence),
                metrics={"http_hosts": extra_http},
                remediate="Consolidate split network posture and migrate HTTP endpoints to HTTPS.",
            )
        )

    return tuple(findings), metrics


__all__ = ["split_findings_and_metrics"]
