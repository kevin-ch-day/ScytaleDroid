"""Parse Android network security configuration policies."""

from __future__ import annotations

import hashlib
from typing import List, Optional
from xml.etree import ElementTree

from androguard.core.apk import APK

from .models import DomainPolicy, NetworkSecurityPolicy

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def extract_network_security_policy(
    apk: APK,
    *,
    manifest_reference: Optional[str],
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

    domain_configs: List[DomainPolicy] = []

    base_config = root.find("base-config")
    if base_config is not None:
        base_cleartext = _coerce_bool(
            base_config.get(f"{_ANDROID_NS}cleartextTrafficPermitted"),
            default=base_cleartext,
        )
        trust_user_certificates = _has_user_certificates(base_config)

    debug_overrides = root.find("debug-overrides")
    debug_cleartext = None
    if debug_overrides is not None:
        debug_cleartext = _coerce_bool(
            debug_overrides.get(f"{_ANDROID_NS}cleartextTrafficPermitted")
        )
        if debug_cleartext is None:
            debug_cleartext = base_cleartext
        trust_user_certificates = trust_user_certificates or _has_user_certificates(
            debug_overrides
        )

    for element in root.findall("domain-config"):
        domain_configs.extend(_parse_domain_config(element, base_cleartext))

    xml_hash = hashlib.sha256(raw_bytes).hexdigest()

    return NetworkSecurityPolicy(
        source_path=resolved_path,
        base_cleartext=base_cleartext,
        debug_overrides_cleartext=debug_cleartext,
        trust_user_certificates=trust_user_certificates,
        domain_policies=tuple(domain_configs),
        raw_xml_hash=xml_hash,
    )


def _resolve_resource_path(reference: Optional[str]) -> Optional[str]:
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


def _coerce_bool(value: Optional[str], *, default: Optional[bool] = None) -> Optional[bool]:
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


def _has_user_certificates(element: ElementTree.Element) -> bool:
    for anchor in element.findall("trust-anchors"):
        for child in anchor:
            tag = child.tag.rsplit("}", 1)[-1] if "}" in child.tag else child.tag
            if tag == "certificates":
                src = child.get(f"{_ANDROID_NS}src") or ""
                if src.endswith("user"):
                    return True
    return False


def _parse_domain_config(
    element: ElementTree.Element,
    base_cleartext: Optional[bool],
) -> List[DomainPolicy]:
    cleartext = _coerce_bool(
        element.get(f"{_ANDROID_NS}cleartextTrafficPermitted"),
        default=base_cleartext,
    )
    user_certificates = _has_user_certificates(element)
    pin_sets: List[str] = []
    for pin_set in element.findall("pin-set"):
        set_name = pin_set.get(f"{_ANDROID_NS}expiration") or "pin"
        pin_sets.append(set_name)

    domains: List[str] = []
    include_subdomains = False
    for domain in element.findall("domain"):
        name = (domain.text or "").strip()
        if not name:
            continue
        domains.append(name)
        include_subdomains = include_subdomains or _coerce_bool(
            domain.get(f"{_ANDROID_NS}includeSubdomains"), default=False
        )

    policies: List[DomainPolicy] = []
    if domains:
        policies.append(
            DomainPolicy(
                domains=tuple(domains),
                include_subdomains=include_subdomains,
                cleartext_permitted=cleartext,
                user_certificates_allowed=user_certificates,
                pinned_certificates=tuple(pin_sets),
            )
        )

    for child in element.findall("domain-config"):
        policies.extend(_parse_domain_config(child, cleartext))

    return policies


__all__ = ["extract_network_security_policy"]
