"""Parse Android network security configuration policies."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from xml.etree import ElementTree

from scytaledroid.StaticAnalysis._androguard import APK

from .models import DomainPolicy, NetworkSecurityPolicy

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def extract_network_security_policy(
    apk: APK,
    *,
    manifest_reference: str | None,
) -> NetworkSecurityPolicy:
    """Return the resolved network security configuration, if present."""

    resolved_path = _resolve_resource_path(manifest_reference)
    if not resolved_path:
        return NetworkSecurityPolicy.empty()

    try:
        raw_bytes = apk.get_file(resolved_path)
    except KeyError:
        # Some builds reference XML via tools:replace that may not exist.
        return NetworkSecurityPolicy(
            source_path=resolved_path,
            base_cleartext=None,
            debug_overrides_cleartext=None,
            trust_user_certificates=False,
            domain_policies=tuple(),
            raw_xml_hash=None,
        )

    if not raw_bytes:
        return NetworkSecurityPolicy(
            source_path=resolved_path,
            base_cleartext=None,
            debug_overrides_cleartext=None,
            trust_user_certificates=False,
            domain_policies=tuple(),
            raw_xml_hash=None,
        )

    try:
        root = ElementTree.fromstring(raw_bytes)
    except ElementTree.ParseError:
        return NetworkSecurityPolicy(
            source_path=resolved_path,
            base_cleartext=None,
            debug_overrides_cleartext=None,
            trust_user_certificates=False,
            domain_policies=tuple(),
            raw_xml_hash=hashlib.sha256(raw_bytes).hexdigest(),
        )

    base_cleartext = _coerce_bool(root.get(f"{_ANDROID_NS}cleartextTrafficPermitted"))
    trust_user_certificates = False
    base_trust_anchors: tuple[str, ...] = tuple()

    domain_configs: list[DomainPolicy] = []

    base_config = root.find("base-config")
    if base_config is not None:
        base_cleartext = _coerce_bool(
            base_config.get(f"{_ANDROID_NS}cleartextTrafficPermitted"),
            default=base_cleartext,
        )
        base_trust_anchors = _collect_trust_anchors(base_config)
        trust_user_certificates = _anchors_allow_user(base_trust_anchors)

    debug_overrides = root.find("debug-overrides")
    debug_cleartext = None
    if debug_overrides is not None:
        debug_cleartext = _coerce_bool(
            debug_overrides.get(f"{_ANDROID_NS}cleartextTrafficPermitted")
        )
        if debug_cleartext is None:
            debug_cleartext = base_cleartext
        debug_anchors = _collect_trust_anchors(debug_overrides)
        if _anchors_allow_user(debug_anchors):
            trust_user_certificates = True

    for element in root.findall("domain-config"):
        domain_configs.extend(
            _parse_domain_config(
                element,
                base_cleartext,
                base_trust_anchors,
            )
        )

    xml_hash = hashlib.sha256(raw_bytes).hexdigest()

    if not trust_user_certificates:
        trust_user_certificates = any(
            domain.user_certificates_allowed for domain in domain_configs
        )

    return NetworkSecurityPolicy(
        source_path=resolved_path,
        base_cleartext=base_cleartext,
        debug_overrides_cleartext=debug_cleartext,
        trust_user_certificates=trust_user_certificates,
        base_trust_anchors=base_trust_anchors,
        domain_policies=tuple(domain_configs),
        raw_xml_hash=xml_hash,
    )


def _resolve_resource_path(reference: str | None) -> str | None:
    if not reference:
        return None
    reference = reference.strip()
    if not reference:
        return None
    if reference.startswith("@xml/"):
        name = reference.split("/", 1)[1]
        return f"res/xml/{name}.xml"
    if reference.startswith("@raw/"):
        name = reference.split("/", 1)[1]
        return f"res/raw/{name}.xml"
    if reference.startswith("res/"):
        return reference
    if reference.endswith(".xml"):
        return reference
    return None


def _coerce_bool(value: str | None, *, default: bool | None = None) -> bool | None:
    if value is None:
        return default
    value = value.strip().lower()
    if not value:
        return default
    if value in {"true", "1", "yes"}:
        return True
    if value in {"false", "0", "no"}:
        return False
    return default


def _collect_trust_anchors(element: ElementTree.Element) -> tuple[str, ...]:
    anchors: list[str] = []
    for anchor in element.findall("trust-anchors"):
        for child in anchor:
            tag = child.tag.rsplit("}", 1)[-1] if "}" in child.tag else child.tag
            if tag == "certificates":
                src = (child.get(f"{_ANDROID_NS}src") or "").strip()
                if src:
                    anchors.append(src)
    return tuple(anchors)


def _anchors_allow_user(anchors: Sequence[str]) -> bool:
    for anchor in anchors:
        if anchor.endswith("user"):
            return True
    return False


def _parse_domain_config(
    element: ElementTree.Element,
    base_cleartext: bool | None,
    inherited_anchors: Sequence[str],
) -> list[DomainPolicy]:
    cleartext = _coerce_bool(
        element.get(f"{_ANDROID_NS}cleartextTrafficPermitted"),
        default=base_cleartext,
    )
    anchors = _collect_trust_anchors(element)
    if not anchors:
        anchors = tuple(inherited_anchors)
    user_certificates = _anchors_allow_user(anchors)
    pin_sets = _collect_pin_sets(element)

    domains: list[str] = []
    include_subdomains = False
    for domain in element.findall("domain"):
        name = (domain.text or "").strip()
        if not name:
            continue
        domains.append(name)
        include_subdomains = include_subdomains or _coerce_bool(
            domain.get(f"{_ANDROID_NS}includeSubdomains"), default=False
        )

    policies: list[DomainPolicy] = []
    if domains:
        policies.append(
            DomainPolicy(
                domains=tuple(domains),
                include_subdomains=include_subdomains,
                cleartext_permitted=cleartext,
                user_certificates_allowed=user_certificates,
                pinned_certificates=tuple(pin_sets),
                trust_anchors=tuple(anchors),
            )
        )

    for child in element.findall("domain-config"):
        policies.extend(_parse_domain_config(child, cleartext, anchors))

    return policies


def _collect_pin_sets(element: ElementTree.Element) -> list[Mapping[str, object]]:
    pin_sets: list[Mapping[str, object]] = []
    for pin_set in element.findall("pin-set"):
        entry: dict[str, object] = {}
        expiration = (pin_set.get(f"{_ANDROID_NS}expiration") or "").strip()
        if expiration:
            entry["expiration"] = expiration
        pins: list[Mapping[str, str]] = []
        for pin in pin_set.findall("pin"):
            digest = (pin.get(f"{_ANDROID_NS}digest") or "").strip()
            value = (pin.text or "").strip()
            if not digest or not value:
                continue
            pins.append({"digest": digest, "value": value})
        if pins:
            entry["pins"] = pins
        if entry:
            pin_sets.append(entry)
    return pin_sets


__all__ = ["extract_network_security_policy"]