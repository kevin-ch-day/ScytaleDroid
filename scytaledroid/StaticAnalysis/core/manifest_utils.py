"""Helpers for parsing and inspecting Android manifests."""

from __future__ import annotations

from collections.abc import Mapping
from xml.etree import ElementTree

from scytaledroid.StaticAnalysis._androguard import APK

from .errors import StaticAnalysisError
from .models import ComponentSummary, ManifestFlags
from .utils import coerce_bool, coerce_optional_str

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def load_manifest_root(apk: APK) -> ElementTree.Element:
    """Return the parsed AndroidManifest root element."""

    try:
        manifest_xml = apk.get_android_manifest_xml()
    except Exception as exc:  # pragma: no cover - defensive, androguard handles parsing
        raise StaticAnalysisError(f"Unable to parse AndroidManifest.xml: {exc}") from exc

    if hasattr(manifest_xml, "tag"):
        # Androguard may return an lxml element when that dependency is available.
        try:
            manifest_xml = ElementTree.tostring(manifest_xml, encoding="utf-8")
        except Exception:
            manifest_xml = ElementTree.tostring(manifest_xml)

    if isinstance(manifest_xml, str):
        manifest_bytes = manifest_xml.encode("utf-8")
    else:
        manifest_bytes = manifest_xml

    try:
        return ElementTree.fromstring(manifest_bytes)
    except ElementTree.ParseError as exc:
        raise StaticAnalysisError(f"Malformed AndroidManifest.xml: {exc}") from exc


def build_manifest_flags(root: ElementTree.Element) -> ManifestFlags:
    """Extract notable booleans from the manifest tree."""

    application = root.find("application")
    if application is None:
        return ManifestFlags()

    return ManifestFlags(
        uses_cleartext_traffic=coerce_bool(application.get(f"{_ANDROID_NS}usesCleartextTraffic")),
        debuggable=coerce_bool(application.get(f"{_ANDROID_NS}debuggable")),
        allow_backup=coerce_bool(application.get(f"{_ANDROID_NS}allowBackup")),
        request_legacy_external_storage=coerce_bool(
            application.get(f"{_ANDROID_NS}requestLegacyExternalStorage")
        ),
        full_backup_content=coerce_optional_str(
            application.get(f"{_ANDROID_NS}fullBackupContent")
        ),
        network_security_config=coerce_optional_str(
            application.get(f"{_ANDROID_NS}networkSecurityConfig")
        ),
    )


def extract_compile_sdk(root: ElementTree.Element) -> str | None:
    """Best-effort extraction of compile SDK metadata from the manifest."""

    value = root.get(f"{_ANDROID_NS}compileSdkVersion") or root.get("platformBuildVersionCode")
    if value:
        return str(value)
    return None


def collect_exported_components(manifest_root: ElementTree.Element) -> ComponentSummary:
    """Derive exported component lists by inspecting manifest nodes."""

    def exported_names(tags: tuple[str, ...], *, default_exported: bool = False) -> tuple[str, ...]:
        names: set[str] = set()
        for tag in tags:
            for element in manifest_root.iter(tag):
                name = element.get(f"{_ANDROID_NS}name")
                if not name:
                    continue
                exported_attr = element.get(f"{_ANDROID_NS}exported")
                if exported_attr is not None:
                    is_exported = exported_attr.strip().lower() == "true"
                else:
                    is_exported = (
                        default_exported
                        if tag == "provider"
                        else _element_has_intent_filter(element)
                    )
                if is_exported:
                    names.add(name)
        return tuple(sorted(names))

    return ComponentSummary(
        activities=exported_names(("activity", "activity-alias")),
        services=exported_names(("service",)),
        receivers=exported_names(("receiver",)),
        providers=exported_names(("provider",), default_exported=False),
    )


def _element_has_intent_filter(element: ElementTree.Element) -> bool:
    """Return True if the manifest element declares an intent-filter child."""

    for child in element:
        tag = child.tag
        if "}" in tag:
            tag = tag.rsplit("}", 1)[-1]
        if tag == "intent-filter":
            return True
    return False


def collect_custom_permission_definitions(
    manifest_root: ElementTree.Element,
) -> Mapping[str, Mapping[str, object]]:
    """Return custom permission definitions declared in the manifest."""

    definitions: dict[str, dict[str, object]] = {}
    for element in manifest_root.findall("permission"):
        name = element.get(f"{_ANDROID_NS}name")
        if not name:
            continue
        raw_level = (element.get(f"{_ANDROID_NS}protectionLevel") or "").strip()
        level_parts = tuple(
            part.strip().lower()
            for part in raw_level.split("|")
            if part.strip()
        )
        description = element.get(f"{_ANDROID_NS}description")
        permission_group = element.get(f"{_ANDROID_NS}permissionGroup")
        definitions[name] = {
            "protection_levels": level_parts,
            "raw_protection_level": raw_level or None,
            "description": description or None,
            "group": permission_group or None,
        }

    # Normalise to immutable mapping for downstream consumers.
    return {key: dict(value) for key, value in definitions.items()}


__all__ = [
    "load_manifest_root",
    "build_manifest_flags",
    "extract_compile_sdk",
    "collect_exported_components",
    "collect_custom_permission_definitions",
]