"""Historical diff helpers for the correlation detector."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ...core.context import DetectorContext
from ...core.findings import Badge, EvidencePointer, Finding, MasvsCategory, SeverityLevel
from ...core.models import ComponentSummary
from ...persistence.reports import StoredReport, list_reports
from .models import DiffBundle, NetworkDiff
from .network import compare_network_snapshots, current_network_snapshot, previous_network_snapshot
from .utils import report_pointer


def load_previous_report(context: DetectorContext) -> StoredReport | None:
    package = context.manifest_summary.package_name or ""
    if not package:
        return None

    current_sha = context.hashes.get("sha256")
    target_version_name = context.manifest_summary.version_name or ""
    try:
        target_version_code = int(context.manifest_summary.version_code)
    except (TypeError, ValueError):
        target_version_code = None

    same_version: list[StoredReport] = []
    older_versions: list[tuple[int, StoredReport]] = []
    candidates: list[StoredReport] = []

    for stored in list_reports():
        report = stored.report
        if report.manifest.package_name != package:
            continue
        if report.hashes.get("sha256") == current_sha:
            continue

        stored_name = report.manifest.version_name or ""
        try:
            stored_code = int(report.manifest.version_code) if report.manifest.version_code else None
        except (TypeError, ValueError):
            stored_code = None

        if (
            stored_code is not None
            and target_version_code is not None
            and stored_code == target_version_code
            and stored_name == target_version_name
        ):
            same_version.append(stored)
            continue
        if (
            stored_code is not None
            and target_version_code is not None
            and stored_code < target_version_code
        ):
            older_versions.append((stored_code, stored))
            continue
        if stored_name and stored_name == target_version_name:
            same_version.append(stored)
            continue
        candidates.append(stored)

    if same_version:
        return same_version[0]
    if older_versions:
        older_versions.sort(key=lambda item: item[0], reverse=True)
        return older_versions[0][1]
    if candidates:
        return candidates[0]
    return None


def compare_components(
    current: ComponentSummary, previous: ComponentSummary
) -> Mapping[str, Sequence[str]]:
    diffs: dict[str, Sequence[str]] = {}
    for attr in ("activities", "services", "receivers", "providers"):
        current_set = set(getattr(current, attr, ()))
        previous_set = set(getattr(previous, attr, ()))
        added = sorted(current_set - previous_set)
        if added:
            diffs[attr] = tuple(added)
    return diffs


def compare_permissions(
    current_permissions: Sequence[str], previous_permissions: Sequence[str]
) -> Sequence[str]:
    current_set = set(current_permissions)
    previous_set = set(previous_permissions)
    return tuple(sorted(current_set - previous_set))


def compare_flags(
    current_flags: Mapping[str, object], previous_flags: Mapping[str, object]
) -> Mapping[str, tuple[object, object]]:
    deltas: dict[str, tuple[object, object]] = {}
    for key, current_value in current_flags.items():
        prev_value = previous_flags.get(key)
        if current_value != prev_value:
            deltas[key] = (prev_value, current_value)
    return deltas


def build_diff_bundle(context: DetectorContext) -> DiffBundle:
    stored = load_previous_report(context)
    if stored is None:
        return DiffBundle(
            previous=None,
            new_exported={},
            new_permissions=tuple(),
            flipped_flags={},
            network_diff=NetworkDiff(),
        )

    previous_report = stored.report
    new_exported = compare_components(
        context.exported_components, previous_report.exported_components
    )
    new_permissions = compare_permissions(
        context.permissions.dangerous,
        previous_report.permissions.dangerous,
    )
    flipped_flags = compare_flags(
        context.manifest_flags.to_dict(),
        previous_report.manifest_flags.to_dict(),
    )
    current_snapshot = current_network_snapshot(context)
    previous_snapshot = previous_network_snapshot(previous_report)
    network_diff = compare_network_snapshots(current_snapshot, previous_snapshot)

    return DiffBundle(
        previous=stored,
        new_exported=new_exported,
        new_permissions=new_permissions,
        flipped_flags=flipped_flags,
        network_diff=network_diff,
    )


def diff_findings(bundle: DiffBundle) -> Sequence[Finding]:
    findings: list[Finding] = []
    if bundle.previous is None:
        return tuple()

    base_location = report_pointer(bundle.previous.path)

    for component_type, names in bundle.new_exported.items():
        title = f"New exported {component_type}"
        finding = Finding(
            finding_id=f"diff_exported_{component_type}",
            title=title,
            severity_gate=SeverityLevel.P1,
            category_masvs=MasvsCategory.PLATFORM,
            status=Badge.WARN,
            because="New exported components were introduced compared to last scan.",
            evidence=(
                EvidencePointer(
                    location=base_location,
                    description=f"Previous export set ({component_type})",
                    extra={"added": names},
                ),
            ),
            metrics={"components": names},
            remediate="Review why additional components are exposed and gate them with signature permissions.",
        )
        findings.append(finding)

    if bundle.new_permissions:
        findings.append(
            Finding(
                finding_id="diff_new_permissions",
                title="Dangerous permissions added",
                severity_gate=SeverityLevel.P1,
                category_masvs=MasvsCategory.PRIVACY,
                status=Badge.WARN,
                because="New dangerous permissions detected compared to baseline.",
                evidence=(
                    EvidencePointer(
                        location=base_location,
                        description="Previous permission set",
                        extra={"new_permissions": bundle.new_permissions},
                    ),
                ),
                metrics={"permissions": bundle.new_permissions},
                remediate="Validate the new dangerous permissions and ensure user justification.",
            )
        )

    for key, (previous, current) in bundle.flipped_flags.items():
        findings.append(
            Finding(
                finding_id=f"diff_flag_{key}",
                title=f"Manifest flag changed — {key}",
                severity_gate=SeverityLevel.P2,
                category_masvs=MasvsCategory.PLATFORM,
                status=Badge.INFO,
                because=f"Manifest flag {key} changed from {previous} to {current}.",
                evidence=(
                    EvidencePointer(
                        location=base_location,
                        description="Previous manifest flags",
                        extra={"flag": key, "previous": previous, "current": current},
                    ),
                ),
                metrics={"flag": key, "previous": previous, "current": current},
                remediate="Confirm the flag change was intentional.",
            )
        )

    diff = bundle.network_diff
    if diff.cleartext_flip and diff.cleartext_flip[1] is True:
        findings.append(
            Finding(
                finding_id="diff_cleartext_enabled",
                title="Cleartext traffic newly permitted",
                severity_gate=SeverityLevel.P1,
                category_masvs=MasvsCategory.NETWORK,
                status=Badge.WARN,
                because="Base network security configuration now allows cleartext traffic.",
                evidence=(
                    EvidencePointer(
                        location=base_location,
                        description="Previous NSC baseline",
                        extra={
                            "previous": diff.cleartext_flip[0],
                            "current": diff.cleartext_flip[1],
                        },
                    ),
                ),
                metrics={
                    "previous": diff.cleartext_flip[0],
                    "current": diff.cleartext_flip[1],
                },
                remediate="Disable cleartextTrafficPermitted or scope it strictly to development domains.",
            )
        )

    if diff.cleartext_domains_added:
        findings.append(
            Finding(
                finding_id="diff_cleartext_domains",
                title="New domains permit cleartext",
                severity_gate=SeverityLevel.P1,
                category_masvs=MasvsCategory.NETWORK,
                status=Badge.WARN,
                because="Additional domain-config entries now permit cleartext transport.",
                evidence=(
                    EvidencePointer(
                        location=base_location,
                        description="Previous NSC domain set",
                        extra={"cleartext_domains": diff.cleartext_domains_added},
                    ),
                ),
                metrics={"domains": diff.cleartext_domains_added},
                remediate="Remove cleartext allowances or confine them to debug builds.",
            )
        )

    if diff.http_added:
        findings.append(
            Finding(
                finding_id="diff_http_endpoints",
                title="New HTTP endpoints discovered",
                severity_gate=SeverityLevel.P1,
                category_masvs=MasvsCategory.NETWORK,
                status=Badge.WARN,
                because="Cleartext HTTP endpoints were added compared to the previous analysis.",
                evidence=(
                    EvidencePointer(
                        location=base_location,
                        description="Baseline network surface",
                        extra={"http_added": diff.http_added},
                    ),
                ),
                metrics={"http_hosts": diff.http_added},
                remediate="Ensure these endpoints are protected by TLS or remove them from release builds.",
            )
        )

    if diff.pinning_removed:
        findings.append(
            Finding(
                finding_id="diff_pinning_removed",
                title="Certificate pinning removed",
                severity_gate=SeverityLevel.P1,
                category_masvs=MasvsCategory.NETWORK,
                status=Badge.WARN,
                because="Pinned certificate configuration disappeared for some domains.",
                evidence=(
                    EvidencePointer(
                        location=base_location,
                        description="Previous NSC pinning",
                        extra={"domains": diff.pinning_removed},
                    ),
                ),
                metrics={"domains": diff.pinning_removed},
                remediate="Restore certificate pinning for sensitive domains or document the risk.",
            )
        )

    if diff.user_certs_flip and diff.user_certs_flip[1] is True:
        findings.append(
            Finding(
                finding_id="diff_user_certs",
                title="Trust user-added certificates enabled",
                severity_gate=SeverityLevel.P2,
                category_masvs=MasvsCategory.NETWORK,
                status=Badge.INFO,
                because="Network Security Config now trusts user-added CAs.",
                evidence=(
                    EvidencePointer(
                        location=base_location,
                        description="Previous trust anchors",
                        extra={
                            "previous": diff.user_certs_flip[0],
                            "current": diff.user_certs_flip[1],
                        },
                    ),
                ),
                metrics={
                    "previous": diff.user_certs_flip[0],
                    "current": diff.user_certs_flip[1],
                },
                remediate="Avoid trusting user certificates for production builds to preserve pinning guarantees.",
            )
        )

    if diff.policy_hash_changed:
        findings.append(
            Finding(
                finding_id="diff_nsc_hash",
                title="Network security config changed",
                severity_gate=SeverityLevel.P2,
                category_masvs=MasvsCategory.NETWORK,
                status=Badge.INFO,
                because="NSC hash differs from the previous report; review policy drift.",
                evidence=(
                    EvidencePointer(
                        location=base_location,
                        description="Previous NSC hash",
                        extra={"policy_hash_changed": True},
                    ),
                ),
                metrics={"policy_hash_changed": True},
                remediate="Document intentional NSC changes and ensure they do not weaken transport security.",
            )
        )

    return tuple(findings)


__all__ = [
    "build_diff_bundle",
    "diff_findings",
    "compare_components",
    "compare_permissions",
    "compare_flags",
    "load_previous_report",
]