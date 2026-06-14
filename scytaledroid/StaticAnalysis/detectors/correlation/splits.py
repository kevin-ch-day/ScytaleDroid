"""Split APK correlation helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ...core.context import DetectorContext
from ...core.findings import Badge, EvidencePointer, Finding, MasvsCategory, SeverityLevel
from ...persistence.reports import StoredReport, reports_for_package
from .models import NetworkSnapshot
from .network import cached_previous_network_snapshot
from .runtime_state import cache_lookup, cache_store
from .utils import report_pointer


def _capture_id_from_metadata(metadata: Mapping[str, object] | None) -> str | None:
    if not isinstance(metadata, Mapping):
        return None
    for key in ("capture_id", "session_stamp"):
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _runtime_related_reports(
    context: DetectorContext,
    *,
    package_name: str | None,
    capture_id: str | None,
    split_id: str,
    current_sha: str | None,
) -> list[StoredReport]:
    runtime_state = getattr(context, "runtime_state", None)
    if not isinstance(runtime_state, Mapping) or not package_name or not capture_id:
        return []
    split_reports = runtime_state.get("saved_reports_by_split")
    if not isinstance(split_reports, Mapping):
        return []
    split_key = ((package_name or "").strip().lower(), capture_id, split_id)
    reports = split_reports.get(split_key)
    if not isinstance(reports, list):
        return []
    return [
        stored
        for stored in reports
        if isinstance(stored, StoredReport) and stored.report.hashes.get("sha256") != current_sha
    ]


def _split_cache_key(*, package_name: str | None, capture_id: str | None, split_id: str) -> tuple[str, str, str] | None:
    package_norm = (package_name or "").strip().lower()
    capture_norm = str(capture_id or "").strip()
    if not package_norm or not capture_norm:
        return None
    return (package_norm, capture_norm, split_id)


def _collect_related_reports(
    context: DetectorContext,
    split_id: str,
    current_sha: str | None,
    *,
    package_name: str | None,
    capture_id: str | None,
) -> list[StoredReport]:
    if not capture_id:
        # Strict default: no historical or cross-session joins without an active capture boundary.
        return []
    cache_key = _split_cache_key(package_name=package_name, capture_id=capture_id, split_id=split_id)
    runtime_state = getattr(context, "runtime_state", None)
    if cache_key is not None:
        found, cached = cache_lookup(
            runtime_state,
            "split_related_reports",
            cache_key,
            hit_counter="split_related_reports_cache_hits",
            miss_counter="split_related_reports_cache_misses",
        )
        if found and isinstance(cached, list):
            return [
                stored
                for stored in cached
                if isinstance(stored, StoredReport) and stored.report.hashes.get("sha256") != current_sha
            ]
    runtime_reports = _runtime_related_reports(
        context,
        package_name=package_name,
        capture_id=capture_id,
        split_id=split_id,
        current_sha=current_sha,
    )
    if runtime_reports:
        return runtime_reports
    related_reports: list[StoredReport] = []
    package_norm = (package_name or "").strip().lower()
    for stored in reports_for_package(package_norm):
        report = stored.report
        metadata = getattr(report, "metadata", {})
        if not isinstance(metadata, Mapping):
            continue
        report_capture_id = _capture_id_from_metadata(metadata)
        if report_capture_id != capture_id:
            continue
        if str(metadata.get("split_group_id")) != split_id:
            continue
        if report.hashes.get("sha256") == current_sha:
            continue
        related_reports.append(stored)
    if cache_key is not None:
        cache_store(runtime_state, "split_related_reports", cache_key, list(related_reports))
    return related_reports


def _build_related_group_cache(
    context: DetectorContext,
    *,
    package_name: str | None,
    capture_id: str | None,
    split_id: str,
    related_reports: Sequence[StoredReport],
) -> dict[str, object]:
    runtime_state = getattr(context, "runtime_state", None)
    cache_key = _split_cache_key(package_name=package_name, capture_id=capture_id, split_id=split_id)
    if cache_key is not None:
        found, cached = cache_lookup(
            runtime_state,
            "split_related_group_cache",
            cache_key,
            hit_counter="split_related_group_cache_hits",
            miss_counter="split_related_group_cache_misses",
        )
        if found and isinstance(cached, dict):
            return cached

    component_union = {
        "activities": set(),
        "services": set(),
        "receivers": set(),
        "providers": set(),
    }
    http_union: set[str] = set()
    cleartext_union: set[str] = set()
    pinned_union: set[str] = set()
    snapshot_by_report_path: dict[str, NetworkSnapshot] = {}

    for stored in related_reports:
        exported = stored.report.exported_components
        component_union["activities"].update(exported.activities)
        component_union["services"].update(exported.services)
        component_union["receivers"].update(exported.receivers)
        component_union["providers"].update(exported.providers)
        report_key = str(getattr(stored, "path", ""))
        snapshot = cached_previous_network_snapshot(
            getattr(context, "runtime_state", None),
            report_key=report_key,
            report=stored.report,
        )
        snapshot_by_report_path[report_key] = snapshot
        http_union.update(snapshot.http_hosts)
        cleartext_union.update(snapshot.cleartext_domains)
        pinned_union.update(snapshot.pinned_domains)

    payload = {
        "related_component_union": {key: tuple(sorted(values)) for key, values in component_union.items()},
        "related_http_hosts": tuple(sorted(http_union)),
        "related_cleartext_domains": tuple(sorted(cleartext_union)),
        "related_pinned_domains": tuple(sorted(pinned_union)),
        "snapshot_by_report_path": snapshot_by_report_path,
    }
    if cache_key is not None:
        cache_store(runtime_state, "split_related_group_cache", cache_key, payload)
    return payload


def split_findings_and_metrics(
    context: DetectorContext, current_snapshot: NetworkSnapshot
) -> tuple[Sequence[Finding], Mapping[str, object]]:
    metadata = context.metadata or {}
    split_group_id = metadata.get("split_group_id")
    if split_group_id is None:
        return tuple(), {}

    split_id = str(split_group_id)
    current_sha = context.hashes.get("sha256")
    current_capture_id = _capture_id_from_metadata(metadata)
    package_name = getattr(context.manifest_summary, "package_name", None)
    related_reports = _collect_related_reports(
        context,
        split_id,
        current_sha,
        package_name=package_name,
        capture_id=current_capture_id,
    )

    metrics: dict[str, object] = {
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

    group_cache = _build_related_group_cache(
        context,
        package_name=package_name,
        capture_id=current_capture_id,
        split_id=split_id,
        related_reports=related_reports,
    )
    related_component_union = {
        key: set(values)
        for key, values in (
            group_cache.get("related_component_union", {})
            if isinstance(group_cache.get("related_component_union"), Mapping)
            else {}
        ).items()
    }
    component_union = {
        "activities": set(context.exported_components.activities) | related_component_union.get("activities", set()),
        "services": set(context.exported_components.services) | related_component_union.get("services", set()),
        "receivers": set(context.exported_components.receivers) | related_component_union.get("receivers", set()),
        "providers": set(context.exported_components.providers) | related_component_union.get("providers", set()),
    }

    metrics["union_exported"] = {key: sorted(values) for key, values in component_union.items()}

    extra_components: dict[str, tuple[str, ...]] = {}
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
    related_http_hosts = group_cache.get("related_http_hosts", ())
    related_cleartext = group_cache.get("related_cleartext_domains", ())
    related_pinned = group_cache.get("related_pinned_domains", ())
    if isinstance(related_http_hosts, Sequence):
        http_union.update(str(item) for item in related_http_hosts)
    if isinstance(related_cleartext, Sequence):
        cleartext_union.update(str(item) for item in related_cleartext)
    if isinstance(related_pinned, Sequence):
        pinned_union.update(str(item) for item in related_pinned)

    metrics["union_http_hosts"] = sorted(http_union)
    metrics["union_cleartext_domains"] = sorted(cleartext_union)
    metrics["union_pinned_domains"] = sorted(pinned_union)

    extra_http = sorted(http_union - set(current_snapshot.http_hosts))
    if extra_http:
        snapshot_by_report_path = (
            group_cache.get("snapshot_by_report_path")
            if isinstance(group_cache.get("snapshot_by_report_path"), Mapping)
            else {}
        )
        evidence = []
        for stored in related_reports:
            snapshot = snapshot_by_report_path.get(str(getattr(stored, "path", "")))
            if not isinstance(snapshot, NetworkSnapshot):
                snapshot = cached_previous_network_snapshot(
                    getattr(context, "runtime_state", None),
                    report_key=str(getattr(stored, "path", "")),
                    report=stored.report,
                )
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
