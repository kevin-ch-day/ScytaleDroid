"""Network posture helpers for the correlation detector."""

from __future__ import annotations

from typing import Mapping, Optional, Sequence

from ...core.context import DetectorContext
from ...modules.network_security.models import DomainPolicy, NetworkSecurityPolicy
from .models import NetworkDiff, NetworkSnapshot


def policy_from_payload(payload: Mapping[str, object]) -> NetworkSecurityPolicy:
    """Rehydrate a :class:`NetworkSecurityPolicy` from persisted metrics."""

    try:
        domain_entries = payload.get("domain_policies", ())
        policies: list[DomainPolicy] = []
        if isinstance(domain_entries, Sequence):
            for entry in domain_entries:
                if not isinstance(entry, Mapping):
                    continue
                policies.append(
                    DomainPolicy(
                        domains=tuple(
                            str(domain)
                            for domain in entry.get("domains", ())
                            if isinstance(domain, str)
                        ),
                        include_subdomains=bool(entry.get("include_subdomains", False)),
                        cleartext_permitted=entry.get("cleartext_permitted"),
                        user_certificates_allowed=bool(
                            entry.get("user_certificates_allowed", False)
                        ),
                        pinned_certificates=tuple(
                            str(cert)
                            for cert in entry.get("pinned_certificates", ())
                            if isinstance(cert, str)
                        ),
                        source=entry.get("source"),
                    )
                )
        return NetworkSecurityPolicy(
            source_path=payload.get("source_path"),
            base_cleartext=payload.get("base_cleartext"),
            debug_overrides_cleartext=payload.get("debug_overrides_cleartext"),
            trust_user_certificates=bool(payload.get("trust_user_certificates", False)),
            domain_policies=tuple(policies),
            raw_xml_hash=payload.get("raw_xml_hash"),
        )
    except Exception:
        return NetworkSecurityPolicy.empty()


def network_snapshot_from_metrics(
    metrics: Mapping[str, object] | None,
    policy: Optional[NetworkSecurityPolicy],
) -> NetworkSnapshot:
    """Build a :class:`NetworkSnapshot` from detector metrics and NSC policy."""

    http_hosts: set[str] = set()
    https_hosts: set[str] = set()
    policy_hash: Optional[str] = None
    if isinstance(metrics, Mapping):
        surface = metrics.get("surface")
        if isinstance(surface, Mapping):
            hosts = surface.get("hosts")
            if isinstance(hosts, Mapping):
                http_hosts = {
                    str(host)
                    for host in hosts.get("http", ())
                    if isinstance(host, str)
                }
                https_hosts = {
                    str(host)
                    for host in hosts.get("https", ())
                    if isinstance(host, str)
                }
        nsc_metrics = metrics.get("NSC")
        if isinstance(nsc_metrics, Mapping):
            graph = nsc_metrics.get("graph")
            if isinstance(graph, Mapping):
                hash_value = graph.get("hash")
                if isinstance(hash_value, str):
                    policy_hash = hash_value
            if policy is None:
                policy = policy_from_payload(nsc_metrics)

    if policy is None:
        policy = NetworkSecurityPolicy.empty()

    cleartext_domains = {
        domain
        for policy_entry in policy.domain_policies
        for domain in policy_entry.domains
        if policy_entry.cleartext_permitted
    }
    pinned_domains = {
        domain
        for policy_entry in policy.domain_policies
        for domain in policy_entry.domains
        if policy_entry.pinned_certificates
    }

    if policy.raw_xml_hash and not policy_hash:
        policy_hash = str(policy.raw_xml_hash)

    return NetworkSnapshot(
        base_cleartext=policy.base_cleartext,
        debug_cleartext=policy.debug_overrides_cleartext,
        trust_user_certs=policy.trust_user_certificates,
        cleartext_domains=tuple(sorted(cleartext_domains)),
        pinned_domains=tuple(sorted(pinned_domains)),
        http_hosts=tuple(sorted(http_hosts)),
        https_hosts=tuple(sorted(https_hosts)),
        policy_hash=policy_hash,
    )


def compare_network_snapshots(
    current: NetworkSnapshot, previous: NetworkSnapshot
) -> NetworkDiff:
    """Generate a :class:`NetworkDiff` between two snapshots."""

    http_added = tuple(sorted(set(current.http_hosts) - set(previous.http_hosts)))
    https_added = tuple(sorted(set(current.https_hosts) - set(previous.https_hosts)))
    cleartext_flip = (
        (previous.base_cleartext, current.base_cleartext)
        if previous.base_cleartext != current.base_cleartext
        else None
    )
    debug_flip = (
        (previous.debug_cleartext, current.debug_cleartext)
        if previous.debug_cleartext != current.debug_cleartext
        else None
    )
    user_certs_flip = (
        (previous.trust_user_certs, current.trust_user_certs)
        if previous.trust_user_certs != current.trust_user_certs
        else None
    )
    cleartext_domains_added = tuple(
        sorted(set(current.cleartext_domains) - set(previous.cleartext_domains))
    )
    pinning_removed = tuple(
        sorted(set(previous.pinned_domains) - set(current.pinned_domains))
    )
    policy_hash_changed = (
        current.policy_hash is not None
        and previous.policy_hash is not None
        and current.policy_hash != previous.policy_hash
    )

    return NetworkDiff(
        http_added=http_added,
        https_added=https_added,
        cleartext_flip=cleartext_flip,
        debug_flip=debug_flip,
        user_certs_flip=user_certs_flip,
        cleartext_domains_added=cleartext_domains_added,
        pinning_removed=pinning_removed,
        policy_hash_changed=policy_hash_changed,
    )


def empty_network_snapshot() -> NetworkSnapshot:
    """Return an empty snapshot placeholder."""

    return NetworkSnapshot(
        base_cleartext=None,
        debug_cleartext=None,
        trust_user_certs=False,
        cleartext_domains=tuple(),
        pinned_domains=tuple(),
        http_hosts=tuple(),
        https_hosts=tuple(),
        policy_hash=None,
    )


def _current_metrics(
    context: DetectorContext, detector_id: str
) -> Mapping[str, object] | None:
    for result in context.intermediate_results:
        if result.detector_id == detector_id:
            return result.metrics
    return None


def current_network_snapshot(context: DetectorContext) -> NetworkSnapshot:
    """Snapshot the current network posture from detector state."""

    return network_snapshot_from_metrics(
        _current_metrics(context, "network_surface"),
        context.network_security_policy,
    )


def previous_network_snapshot(report) -> NetworkSnapshot:
    """Extract the network snapshot persisted with a stored report."""

    metrics_payload = None
    detector_metrics = getattr(report, "detector_metrics", {})
    if isinstance(detector_metrics, Mapping):
        metrics_payload = detector_metrics.get("network_surface")

    policy_payload: Optional[Mapping[str, object]] = None
    metadata = getattr(report, "metadata", {})
    if isinstance(metadata, Mapping):
        bundle = metadata.get("repro_bundle")
        if isinstance(bundle, Mapping):
            policy_candidate = bundle.get("network_security_config")
            if isinstance(policy_candidate, Mapping):
                policy_payload = policy_candidate

    policy = policy_from_payload(policy_payload or {}) if policy_payload else None
    return network_snapshot_from_metrics(metrics_payload, policy)


__all__ = [
    "policy_from_payload",
    "network_snapshot_from_metrics",
    "compare_network_snapshots",
    "empty_network_snapshot",
    "current_network_snapshot",
    "previous_network_snapshot",
]
