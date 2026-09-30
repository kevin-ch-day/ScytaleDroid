"""Parse Android network security configuration policies."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from xml.etree import ElementTree

from androguard.core.axml import AXMLPrinter
from scytaledroid.StaticAnalysis._androguard import APK

from .models import DomainPolicy, NetworkSecurityPolicy

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _attribute(element: ElementTree.Element, name: str) -> str | None:
    """NSC uses unprefixed XML attributes; accept decoded prefixed variants too."""

    if name in element.attrib:
        return element.get(name)
    return element.get(f"{_ANDROID_NS}{name}")


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
            parse_valid=False,
        )

    if not raw_bytes:
        return NetworkSecurityPolicy(
            source_path=resolved_path,
            base_cleartext=None,
            debug_overrides_cleartext=None,
            trust_user_certificates=False,
            domain_policies=tuple(),
            raw_xml_hash=None,
            parse_valid=False,
        )

    root = _parse_xml_root(raw_bytes)
    if root is None or root.tag != "network-security-config":
        return NetworkSecurityPolicy(
            source_path=resolved_path,
            base_cleartext=None,
            debug_overrides_cleartext=None,
            trust_user_certificates=False,
            domain_policies=tuple(),
            raw_xml_hash=hashlib.sha256(raw_bytes).hexdigest(),
            parse_valid=False,
        )

    base_cleartext = _coerce_bool(_attribute(root, "cleartextTrafficPermitted"))
    trust_user_certificates = False
    base_trust_anchors: tuple[str, ...] = tuple()

    domain_configs: list[DomainPolicy] = []

    base_config = root.find("base-config")
    if base_config is not None:
        base_cleartext = _coerce_bool(
            _attribute(base_config, "cleartextTrafficPermitted"),
            default=base_cleartext,
        )
        base_trust_anchors = _collect_trust_anchors(base_config)
        trust_user_certificates = _anchors_allow_user(base_trust_anchors)

    debug_overrides = root.find("debug-overrides")
    debug_cleartext = None
    if debug_overrides is not None:
        debug_cleartext = _coerce_bool(
            _attribute(debug_overrides, "cleartextTrafficPermitted")
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
        parse_valid=True,
    )


def _parse_xml_root(raw_bytes: bytes) -> ElementTree.Element | None:
    try:
        return ElementTree.fromstring(raw_bytes)
    except ElementTree.ParseError:
        # APK resources are commonly Android binary XML rather than text XML.
        if not raw_bytes.startswith(b"\x03\x00\x08\x00"):
            return None
    try:
        printer = AXMLPrinter(raw_bytes)
        if printer.is_valid():
            return ElementTree.fromstring(printer.get_buff())
    except Exception:
        # Corrupt resources are evidence of uncertainty, not a scan failure.
        pass
    return None


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
                src = (_attribute(child, "src") or "").strip()
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
        _attribute(element, "cleartextTrafficPermitted"),
        default=base_cleartext,
    )
    anchors = _collect_trust_anchors(element)
    if not anchors:
        anchors = tuple(inherited_anchors)
    user_certificates = _anchors_allow_user(anchors)
    pin_sets = _collect_pin_sets(element)

    policies: list[DomainPolicy] = []
    for domain in element.findall("domain"):
        name = (domain.text or "").strip()
        if not name:
            continue
        policies.append(
            DomainPolicy(
                domains=(name,),
                include_subdomains=bool(
                    _coerce_bool(
                        _attribute(domain, "includeSubdomains"), default=False
                    )
                ),
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
        expiration = (_attribute(pin_set, "expiration") or "").strip()
        if expiration:
            entry["expiration"] = expiration
        pins: list[Mapping[str, str]] = []
        for pin in pin_set.findall("pin"):
            digest = (_attribute(pin, "digest") or "").strip()
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
