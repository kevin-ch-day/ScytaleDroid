"""Manifest-based App Links and domain-verification detector."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from time import perf_counter
from xml.etree import ElementTree

from ..core.context import DetectorContext
from ..core.findings import (
    Badge,
    DetectorResult,
    EvidencePointer,
    Finding,
    MasvsCategory,
    SeverityLevel,
)
from ..core.results_builder import make_detector_result
from .base import BaseDetector, register_detector

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_WEB_SCHEMES = {"http", "https"}


@dataclass(frozen=True)
class DomainIntentFilterRecord:
    """Normalized manifest view of a browsable/deep-link intent filter."""

    component_type: str
    component_name: str
    filter_index: int
    auto_verify: bool
    actions: tuple[str, ...]
    categories: tuple[str, ...]
    schemes: tuple[str, ...]
    hosts: tuple[str, ...]
    paths: tuple[str, ...]
    uppercase_schemes: tuple[str, ...]
    uppercase_hosts: tuple[str, ...]

    @property
    def has_view(self) -> bool:
        return "android.intent.action.VIEW" in self.actions

    @property
    def has_browsable(self) -> bool:
        return "android.intent.category.BROWSABLE" in self.categories

    @property
    def has_default(self) -> bool:
        return "android.intent.category.DEFAULT" in self.categories

    @property
    def web_schemes(self) -> tuple[str, ...]:
        lowered = {scheme.lower() for scheme in self.schemes if scheme}
        return tuple(sorted(lowered & _WEB_SCHEMES))

    @property
    def custom_schemes(self) -> tuple[str, ...]:
        lowered = {scheme.lower() for scheme in self.schemes if scheme}
        return tuple(sorted(lowered - _WEB_SCHEMES))

    @property
    def browsable_view(self) -> bool:
        return self.has_view and self.has_browsable

    @property
    def web_link_candidate(self) -> bool:
        return self.browsable_view and bool(self.web_schemes) and bool(self.hosts)

    @property
    def auto_verify_eligible(self) -> bool:
        return self.auto_verify and self.web_link_candidate and self.has_default and "https" in self.web_schemes


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _android_attr(element: ElementTree.Element, name: str) -> str | None:
    value = element.get(f"{_ANDROID_NS}{name}")
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _bool_android_attr(element: ElementTree.Element, name: str) -> bool:
    value = (_android_attr(element, name) or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _intent_filter_records(manifest_root: ElementTree.Element) -> tuple[DomainIntentFilterRecord, ...]:
    application = manifest_root.find("application")
    if application is None:
        return tuple()

    component_tags = {"activity", "activity-alias"}
    records: list[DomainIntentFilterRecord] = []

    for component in application:
        component_type = _local_name(component.tag)
        if component_type not in component_tags:
            continue
        component_name = _android_attr(component, "name")
        if not component_name:
            continue

        filter_index = 0
        for child in component:
            if _local_name(child.tag) != "intent-filter":
                continue
            filter_index += 1
            auto_verify = _bool_android_attr(child, "autoVerify")
            actions: set[str] = set()
            categories: set[str] = set()
            schemes: set[str] = set()
            hosts: set[str] = set()
            paths: set[str] = set()
            uppercase_schemes: set[str] = set()
            uppercase_hosts: set[str] = set()

            for entry in child:
                local = _local_name(entry.tag)
                if local == "action":
                    action_name = _android_attr(entry, "name")
                    if action_name:
                        actions.add(action_name)
                    continue
                if local == "category":
                    category_name = _android_attr(entry, "name")
                    if category_name:
                        categories.add(category_name)
                    continue
                if local != "data":
                    continue

                scheme = _android_attr(entry, "scheme")
                if scheme:
                    schemes.add(scheme)
                    if scheme != scheme.lower():
                        uppercase_schemes.add(scheme)

                host = _android_attr(entry, "host")
                if host:
                    hosts.add(host)
                    if host != host.lower():
                        uppercase_hosts.add(host)

                for path_attr in (
                    "path",
                    "pathPrefix",
                    "pathPattern",
                    "pathSuffix",
                    "pathAdvancedPattern",
                ):
                    path_value = _android_attr(entry, path_attr)
                    if path_value:
                        paths.add(f"{path_attr}={path_value}")

            records.append(
                DomainIntentFilterRecord(
                    component_type=component_type,
                    component_name=component_name,
                    filter_index=filter_index,
                    auto_verify=auto_verify,
                    actions=tuple(sorted(actions)),
                    categories=tuple(sorted(categories)),
                    schemes=tuple(sorted(schemes)),
                    hosts=tuple(sorted(hosts)),
                    paths=tuple(sorted(paths)),
                    uppercase_schemes=tuple(sorted(uppercase_schemes)),
                    uppercase_hosts=tuple(sorted(uppercase_hosts)),
                )
            )

    return tuple(records)


def _evidence_pointer(record: DomainIntentFilterRecord, *, apk_path) -> EvidencePointer:
    return EvidencePointer(
        location=(
            f"{apk_path.resolve().as_posix()}!AndroidManifest.xml::"
            f"{record.component_type}:{record.component_name}#intent-filter[{record.filter_index}]"
        ),
        description=f"{record.component_type} {record.component_name}",
        extra={
            "auto_verify": record.auto_verify,
            "actions": list(record.actions),
            "categories": list(record.categories),
            "schemes": list(record.schemes),
            "hosts": list(record.hosts),
            "paths": list(record.paths),
        },
    )


def _filter_label(record: DomainIntentFilterRecord) -> str:
    return f"{record.component_name}#{record.filter_index}"


def _finding_missing_autoverify(
    records: Sequence[DomainIntentFilterRecord],
    *,
    apk_path,
) -> Finding:
    hosts = sorted({host.lower() for record in records for host in record.hosts if host})
    evidence = tuple(_evidence_pointer(record, apk_path=apk_path) for record in records[:2])
    component_labels = sorted({_filter_label(record) for record in records})
    return Finding(
        finding_id="domain_verification_missing_autoverify",
        title="Browsable web link filters omit android:autoVerify",
        severity_gate=SeverityLevel.P2,
        category_masvs=MasvsCategory.PLATFORM,
        status=Badge.WARN,
        because=(
            f"{len(records)} web link filter(s) handle http/https hosts without android:autoVerify, "
            "so Android cannot verify domain ownership and may fall back to chooser-based routing."
        ),
        evidence=evidence,
        remediate=(
            "Add android:autoVerify=\"true\" to supported HTTPS host filters and publish matching "
            "Digital Asset Links statements at https://<host>/.well-known/assetlinks.json."
        ),
        metrics={
            "filters": len(records),
            "components": component_labels,
            "hosts": hosts,
        },
        tags=("app_links", "auto_verify", "deep_links"),
    )


def _finding_misconfigured_autoverify(
    records: Sequence[DomainIntentFilterRecord],
    *,
    apk_path,
) -> Finding:
    evidence = tuple(_evidence_pointer(record, apk_path=apk_path) for record in records[:2])
    misconfig_reasons: Counter[str] = Counter()
    for record in records:
        if not record.has_view:
            misconfig_reasons.update({"missing_VIEW": 1})
        if not record.has_browsable:
            misconfig_reasons.update({"missing_BROWSABLE": 1})
        if not record.has_default:
            misconfig_reasons.update({"missing_DEFAULT": 1})
        if not record.hosts:
            misconfig_reasons.update({"missing_host": 1})
        if "https" not in record.web_schemes:
            misconfig_reasons.update({"missing_https": 1})
        if not record.web_schemes:
            misconfig_reasons.update({"missing_web_scheme": 1})
    return Finding(
        finding_id="domain_verification_misconfigured_autoverify",
        title="android:autoVerify is declared on filters that are unlikely to verify",
        severity_gate=SeverityLevel.P1,
        category_masvs=MasvsCategory.PLATFORM,
        status=Badge.WARN,
        because=(
            f"{len(records)} autoVerify filter(s) do not match the expected App Links shape "
            "(VIEW + BROWSABLE + DEFAULT + HTTPS host), so verification may never succeed."
        ),
        evidence=evidence,
        remediate=(
            "Restrict android:autoVerify to real web-link handlers with VIEW, BROWSABLE, DEFAULT, "
            "and lowercase HTTPS host declarations."
        ),
        metrics={"filters": len(records), "reasons": dict(misconfig_reasons)},
        tags=("app_links", "auto_verify", "misconfiguration"),
    )


def _finding_uppercase_manifest_hosts(
    records: Sequence[DomainIntentFilterRecord],
    *,
    apk_path,
) -> Finding:
    evidence = tuple(_evidence_pointer(record, apk_path=apk_path) for record in records[:2])
    uppercase_hosts = sorted({host for record in records for host in record.uppercase_hosts})
    uppercase_schemes = sorted({scheme for record in records for scheme in record.uppercase_schemes})
    return Finding(
        finding_id="domain_verification_case_sensitive_manifest_values",
        title="App link scheme or host uses uppercase characters",
        severity_gate=SeverityLevel.P2,
        category_masvs=MasvsCategory.PLATFORM,
        status=Badge.INFO,
        because=(
            "Android scheme and host matching is case-sensitive. Uppercase manifest values can break "
            "deep-link matching and verification unexpectedly."
        ),
        evidence=evidence,
        remediate="Normalize app-link schemes and hosts to lowercase in AndroidManifest.xml.",
        metrics={
            "filters": len(records),
            "uppercase_hosts": uppercase_hosts,
            "uppercase_schemes": uppercase_schemes,
        },
        tags=("app_links", "case_sensitive", "manifest"),
    )


def _filter_subitems(records: Sequence[DomainIntentFilterRecord]) -> tuple[Mapping[str, object], ...]:
    rows: list[Mapping[str, object]] = []
    for record in records:
        rows.append(
            {
                "component": record.component_name,
                "component_type": record.component_type,
                "filter_index": record.filter_index,
                "auto_verify": record.auto_verify,
                "view": record.has_view,
                "browsable": record.has_browsable,
                "default": record.has_default,
                "web_link_candidate": record.web_link_candidate,
                "auto_verify_eligible": record.auto_verify_eligible,
                "schemes": list(record.schemes),
                "hosts": list(record.hosts),
                "paths": list(record.paths),
            }
        )
    return tuple(rows)


def _summary_metrics(records: Sequence[DomainIntentFilterRecord]) -> Mapping[str, object]:
    browsable_view = [record for record in records if record.browsable_view]
    web_links = [record for record in records if record.web_link_candidate]
    auto_verify = [record for record in records if record.auto_verify]
    eligible = [record for record in records if record.auto_verify_eligible]
    hosts = sorted({host.lower() for record in web_links for host in record.hosts if host})
    custom_schemes = sorted({scheme.lower() for record in records for scheme in record.custom_schemes if scheme})
    return {
        "Summary": (
            f"browsable_view={len(browsable_view)}  web_link_filters={len(web_links)}  "
            f"auto_verify_filters={len(auto_verify)}  eligible_verified_filters={len(eligible)}"
        ),
        "Hosts": hosts,
        "Custom schemes": custom_schemes,
        "Filter counts": {
            "total_intent_filters": len(records),
            "browsable_view_filters": len(browsable_view),
            "web_link_filters": len(web_links),
            "auto_verify_filters": len(auto_verify),
            "eligible_verified_filters": len(eligible),
        },
    }


@register_detector
class DomainVerificationDetector(BaseDetector):
    """Manifest-only App Links and deep-link verification detector."""

    detector_id = "domain_verification"
    name = "Domain verification detector"
    default_profiles = ("quick", "full")
    section_key = "domain_verification"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()
        manifest_root = getattr(context, "manifest_root", None)
        if manifest_root is None:
            return make_detector_result(
                detector_id=self.detector_id,
                section_key=self.section_key,
                status=Badge.SKIPPED,
                started_at=started,
                findings=tuple(),
                metrics={"skip_reason": "manifest unavailable"},
                evidence=tuple(),
            )

        records = _intent_filter_records(manifest_root)
        web_link_without_autoverify = [record for record in records if record.web_link_candidate and not record.auto_verify]
        misconfigured_autoverify = [record for record in records if record.auto_verify and not record.auto_verify_eligible]
        uppercase_manifest_values = [
            record for record in records if record.uppercase_hosts or record.uppercase_schemes
        ]

        findings: list[Finding] = []
        if web_link_without_autoverify:
            findings.append(_finding_missing_autoverify(web_link_without_autoverify, apk_path=context.apk_path))
        if misconfigured_autoverify:
            findings.append(_finding_misconfigured_autoverify(misconfigured_autoverify, apk_path=context.apk_path))
        if uppercase_manifest_values:
            findings.append(_finding_uppercase_manifest_hosts(uppercase_manifest_values, apk_path=context.apk_path))

        if any(finding.status is Badge.WARN for finding in findings):
            status = Badge.WARN
        elif findings or records:
            status = Badge.INFO
        else:
            status = Badge.OK

        notes: list[str] = []
        eligible_hosts = sorted({host.lower() for record in records if record.auto_verify_eligible for host in record.hosts if host})
        if eligible_hosts:
            notes.append(
                f"Verified app-link candidates declared for {len(eligible_hosts)} host(s); host verification still depends on HTTPS Digital Asset Links publication."
            )
        if any(record.uppercase_hosts or record.uppercase_schemes for record in records):
            notes.append("Android scheme and host matching is case-sensitive; lowercase manifest values are safer for deep links.")
        if any(len(record.hosts) > 1 or len(record.schemes) > 1 for record in records):
            notes.append("Multiple <data> elements were flattened into combined scheme/host sets for static review.")

        evidence = tuple(_evidence_pointer(record, apk_path=context.apk_path) for record in records[:4])
        metrics = dict(_summary_metrics(records))
        metrics["surface"] = {
            "eligible_verified_hosts": eligible_hosts,
            "filters": list(_filter_subitems(records)[:8]),
        }

        return make_detector_result(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=status,
            started_at=started,
            findings=tuple(findings),
            metrics=metrics,
            evidence=evidence,
            notes=tuple(notes),
            subitems=_filter_subitems(records),
        )


__all__ = ["DomainVerificationDetector"]
