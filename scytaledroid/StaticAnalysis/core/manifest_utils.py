"""Helpers for parsing and inspecting Android manifests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from xml.etree import ElementTree

from scytaledroid.StaticAnalysis._androguard import APK

from .errors import StaticAnalysisError
from .models import ComponentSummary, ManifestFlags
from .utils import coerce_bool, coerce_optional_str

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _android_attr(element: ElementTree.Element, name: str) -> str | None:
    value = (element.get(f"{_ANDROID_NS}{name}") or "").strip()
    return value or None


def application_default_permission(application: ElementTree.Element | None) -> str | None:
    """Return ``<application android:permission>`` when present."""

    if application is None:
        return None
    return _android_attr(application, "permission")


def effective_component_permission(
    element: ElementTree.Element,
    application_permission: str | None,
) -> str | None:
    """Return the component permission, inheriting the application default."""

    explicit = _android_attr(element, "permission")
    return explicit if explicit else application_permission


def effective_provider_permissions(
    element: ElementTree.Element,
    application_permission: str | None,
) -> tuple[str | None, str | None, str | None]:
    """Return ``(general, read, write)`` using Android provider defaults.

    ``android:permission`` (component, else application) is the default for both
    directions. Explicit ``readPermission`` / ``writePermission`` override one
    direction without implying the other is protected.
    """

    general = effective_component_permission(element, application_permission)
    read = _android_attr(element, "readPermission") or general
    write = _android_attr(element, "writePermission") or general
    return general, read, write
_PERMISSION_OCCURRENCE_RECORD_FORMAT = "android-permission-intel-permission-occurrence-evidence-v1"
_PERMISSION_OCCURRENCE_PRODUCT_FORMAT = "scytaledroid-permission-occurrence-extraction-product-v1"
_PERMISSION_ROLE_FAMILIES = (
    "PERMISSION_REQUEST",
    "PERMISSION_DEFINITION",
    "COMPONENT_GUARD",
    "PATH_PERMISSION_GUARD",
)
_PERMISSION_OCCURRENCE_PRODUCT_SCHEMA = {
    "format": _PERMISSION_OCCURRENCE_PRODUCT_FORMAT,
    "terminal_states": ["SUCCEEDED", "PARTIAL", "FAILED"],
    "artifact_scopes": ["BASE", "SPLIT", "OTHER", "UNKNOWN"],
    "role_families": list(_PERMISSION_ROLE_FAMILIES),
    "absence_rule": "only-succeeded-and-explicitly-complete-scope-may-refute",
    "install_set_rule": "artifact-completeness-does-not-imply-install-set-completeness",
}


class PermissionOccurrenceExtractionInterrupted(RuntimeError):
    """Signal an intentional interruption after already-emitted evidence."""


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
        full_backup_content=coerce_optional_str(application.get(f"{_ANDROID_NS}fullBackupContent")),
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

    target_sdk = _extract_target_sdk_int(manifest_root)
    application = manifest_root.find("application")
    application_enabled = (
        _manifest_bool(application.get(f"{_ANDROID_NS}enabled"), default=True)
        if application is not None
        else True
    )

    def exported_names(tags: tuple[str, ...]) -> tuple[str, ...]:
        names: set[str] = set()
        for tag in tags:
            for element in manifest_root.iter(tag):
                name = element.get(f"{_ANDROID_NS}name")
                if not name:
                    continue
                component_enabled = application_enabled and _manifest_bool(
                    element.get(f"{_ANDROID_NS}enabled"),
                    default=True,
                )
                if not component_enabled:
                    continue
                exported_attr = element.get(f"{_ANDROID_NS}exported")
                if exported_attr is not None:
                    is_exported = exported_attr.strip().lower() == "true"
                else:
                    has_intent_filter = _element_has_intent_filter(element)
                    if target_sdk is not None and target_sdk >= 31 and has_intent_filter:
                        is_exported = False
                    elif tag == "provider":
                        is_exported = _provider_default_exported(target_sdk)
                    else:
                        is_exported = has_intent_filter
                if is_exported:
                    names.add(name)
        return tuple(sorted(names))

    return ComponentSummary(
        activities=exported_names(("activity", "activity-alias")),
        services=exported_names(("service",)),
        receivers=exported_names(("receiver",)),
        providers=exported_names(("provider",)),
    )


def build_manifest_evidence(
    manifest_root: ElementTree.Element,
    *,
    source_manifest: str = "androguard",
    source_semantics: str = "androguard",
) -> list[dict[str, object]]:
    """Return explicit vs effective export evidence for manifest components."""

    application = manifest_root.find("application")
    if application is None:
        return []

    target_sdk = _extract_target_sdk_int(manifest_root)
    application_permission = application_default_permission(application)
    application_enabled = _manifest_bool(
        application.get(f"{_ANDROID_NS}enabled"),
        default=True,
    )

    records: list[dict[str, object]] = []
    component_tags = {
        "activity",
        "activity-alias",
        "service",
        "receiver",
        "provider",
    }

    for element in application:
        tag = element.tag.rsplit("}", 1)[-1] if "}" in element.tag else element.tag
        if tag not in component_tags:
            continue
        name = element.get(f"{_ANDROID_NS}name")
        if not name:
            continue

        enabled_explicit = coerce_bool(element.get(f"{_ANDROID_NS}enabled"))
        component_enabled = application_enabled and _manifest_bool(
            element.get(f"{_ANDROID_NS}enabled"),
            default=True,
        )
        exported_attr = element.get(f"{_ANDROID_NS}exported")
        exported_explicit: bool | None = None
        exported_state = "absent"
        export_reason = None
        if exported_attr is not None:
            exported_explicit = exported_attr.strip().lower() == "true"
            exported_state = "true" if exported_explicit else "false"
            exported_effective = exported_explicit
            export_reason = "explicit_flag"
        else:
            has_intent_filter = _element_has_intent_filter(element)
            if target_sdk is not None and target_sdk >= 31 and has_intent_filter:
                exported_effective = False
                export_reason = "sdk31_requires_explicit"
            elif tag == "provider":
                exported_effective = _provider_default_exported(target_sdk)
                export_reason = (
                    "provider_default_true_legacy_sdk"
                    if exported_effective
                    else "provider_default_false"
                )
            else:
                exported_effective = bool(has_intent_filter)
                export_reason = "intent_filter_present" if has_intent_filter else "default_false"

        if exported_effective and not component_enabled:
            exported_effective = False
            export_reason = (
                "application_disabled" if not application_enabled else "component_disabled"
            )

        record: dict[str, object] = {
            "component_type": tag,
            "name": name,
            "enabled": component_enabled,
            "enabled_explicit": enabled_explicit,
            "application_enabled": application_enabled,
            "exported_explicit": exported_explicit,
            "exported_explicit_state": exported_state,
            "exported_effective": exported_effective,
            "export_reason": export_reason,
            "source_manifest": source_manifest,
            "source_semantics": source_semantics,
            "permission": effective_component_permission(element, application_permission),
            "permission_explicit": _android_attr(element, "permission"),
            "application_permission": application_permission,
            "process": coerce_optional_str(element.get(f"{_ANDROID_NS}process")),
            "target_sdk": target_sdk,
        }

        if tag == "provider":
            authorities = element.get(f"{_ANDROID_NS}authorities") or ""
            authority_list = [token.strip() for token in authorities.split(",") if token.strip()]
            grant_uri = (
                element.get(f"{_ANDROID_NS}grantUriPermissions") or ""
            ).strip().lower() in {"true", "1"}
            general, read_perm, write_perm = effective_provider_permissions(
                element, application_permission
            )
            record.update(
                {
                    "authorities": authority_list,
                    "permission": general,
                    "read_permission": read_perm,
                    "write_permission": write_perm,
                    "grant_uri_permissions": grant_uri,
                }
            )

        records.append(record)

    records.sort(
        key=lambda item: (
            str(item.get("component_type") or ""),
            str(item.get("name") or ""),
        )
    )
    return records


def _element_has_intent_filter(element: ElementTree.Element) -> bool:
    """Return True if the manifest element declares an intent-filter child."""

    for child in element:
        tag = child.tag
        if "}" in tag:
            tag = tag.rsplit("}", 1)[-1]
        if tag == "intent-filter":
            return True
    return False


def _manifest_bool(value: str | None, *, default: bool) -> bool:
    parsed = coerce_bool(value)
    return default if parsed is None else parsed


def _provider_default_exported(target_sdk: int | None) -> bool:
    return target_sdk is None or target_sdk <= 16


def _extract_target_sdk_int(manifest_root: ElementTree.Element) -> int | None:
    uses_sdk = manifest_root.find("uses-sdk")
    if uses_sdk is None:
        return None
    raw_value = uses_sdk.get(f"{_ANDROID_NS}targetSdkVersion")
    if not raw_value:
        return None
    try:
        return int(str(raw_value).strip())
    except (TypeError, ValueError):
        return None


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
        level_parts = tuple(part.strip().lower() for part in raw_level.split("|") if part.strip())
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


def _semantic_sha256(value: Mapping[str, object]) -> str:
    encoded = (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _permission_occurrence_record(
    *,
    artifact_sha256: str,
    package_name: str | None,
    analysis_run_id: str,
    producer_version: str,
    observed_at_utc: str,
    raw_token: str,
    role: str,
    claim: str,
    evidence_locator: str,
    raw_protection: str | None = None,
) -> Mapping[str, object]:
    """Build one direct manifest fact without projecting its identity."""

    raw_token_digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    logical_identity = {
        "artifact_sha256": artifact_sha256,
        "occurrence_role": role,
        "raw_token_utf8_sha256": raw_token_digest,
        "extractor_surface": "scytaledroid.android_manifest",
        "evidence_locator": evidence_locator,
    }
    core: dict[str, object] = {
        "record_format": _PERMISSION_OCCURRENCE_RECORD_FORMAT,
        "occurrence_role": role,
        "evidence_layer": "DIRECT_MANIFEST",
        "semantic_claim": claim,
        "subject": {
            "artifact_sha256": artifact_sha256,
            "package_name": package_name,
            "producer_local_sample_ref": None,
        },
        "identity": {
            "raw_token": raw_token,
            "raw_token_utf8_sha256": raw_token_digest,
            "projected_pi_token": None,
            "projected_token_utf8_sha256": None,
            "projection_policy_version": "projection-deferred-to-permission-intel-v1",
            "compatibility_key": None,
            "compatibility_profile": "ascii-casefold-no-trim-v1",
            "transformation_steps": [],
            "supported_for_projection": False,
            "unsupported_reason": "PROJECTION_DEFERRED_TO_PERMISSION_INTEL",
        },
        "provenance": {
            "producer": "ScytaleDroid",
            "producer_version": producer_version,
            "analysis_run_id": analysis_run_id,
            "extractor_surface": "scytaledroid.android_manifest",
            "evidence_locator": evidence_locator,
            "source_artifact_sha256": artifact_sha256,
            "source_event_ref": None,
            "observed_at_utc": observed_at_utc,
        },
        "lineage": {
            "derivation_rule_id": None,
            "upstream_evidence_digests": [],
        },
        "protection_evidence": (
            {
                "source_kind": "MANIFEST_PROTECTION_LEVEL_ATTRIBUTE",
                "raw_value": raw_protection,
            }
            if raw_protection
            else None
        ),
        "authority": {
            "alias_authorized": False,
            "canonical_identity_authorized": False,
            "database_mutation_authorized": False,
        },
        "logical_occurrence_digest": _semantic_sha256(logical_identity),
    }
    return {**core, "occurrence_evidence_digest": _semantic_sha256(core)}


def _permission_occurrences_for_family(
    manifest_root: ElementTree.Element,
    *,
    role_family: str,
    artifact_sha256: str,
    package_name: str | None,
    analysis_run_id: str,
    producer_version: str,
    observed_at_utc: str,
) -> tuple[Mapping[str, object], ...]:
    """Extract one role family so completion can be stated precisely."""

    records: list[Mapping[str, object]] = []

    def attribute_value(
        element: ElementTree.Element,
        attribute: str,
    ) -> tuple[str | None, str]:
        namespaced = element.get(f"{_ANDROID_NS}{attribute}")
        if namespaced is not None:
            return namespaced, f"android:{attribute}"
        return element.get(attribute), attribute

    def append_record(
        *,
        element: ElementTree.Element,
        element_path: str,
        attribute: str,
        role: str,
        claim: str,
        include_protection: bool = False,
    ) -> None:
        raw_token, source_attribute = attribute_value(element, attribute)
        if not raw_token:
            return
        raw_protection = None
        if include_protection:
            raw_protection, _ = attribute_value(element, "protectionLevel")
        records.append(
            _permission_occurrence_record(
                artifact_sha256=artifact_sha256,
                package_name=package_name,
                analysis_run_id=analysis_run_id,
                producer_version=producer_version,
                observed_at_utc=observed_at_utc,
                raw_token=raw_token,
                role=role,
                claim=claim,
                evidence_locator=f"{element_path}/@{source_attribute}",
                raw_protection=raw_protection,
            )
        )

    def visit(element: ElementTree.Element, element_path: str) -> None:
        tag = element.tag.rsplit("}", 1)[-1]
        if role_family == "PERMISSION_REQUEST" and tag in {
            "uses-permission",
            "uses-permission-sdk-23",
        }:
            append_record(
                element=element,
                element_path=element_path,
                attribute="name",
                role=(
                    "MANIFEST_USES_PERMISSION_SDK_23"
                    if tag == "uses-permission-sdk-23"
                    else "MANIFEST_USES_PERMISSION"
                ),
                claim="PERMISSION_REQUEST",
            )
        elif role_family == "PERMISSION_DEFINITION" and tag == "permission":
            append_record(
                element=element,
                element_path=element_path,
                attribute="name",
                role="MANIFEST_PERMISSION_DEFINITION",
                claim="PERMISSION_DEFINITION",
                include_protection=True,
            )
        elif role_family == "COMPONENT_GUARD" and tag in {
            "application",
            "activity",
            "activity-alias",
            "service",
            "receiver",
            "provider",
        }:
            attributes = (
                ("permission", "readPermission", "writePermission")
                if tag == "provider"
                else ("permission",)
            )
            for attribute in attributes:
                append_record(
                    element=element,
                    element_path=element_path,
                    attribute=attribute,
                    role="MANIFEST_COMPONENT_GUARD",
                    claim="ACCESS_CONTROL_REFERENCE",
                )
        elif role_family == "PATH_PERMISSION_GUARD" and tag == "path-permission":
            for attribute in ("permission", "readPermission", "writePermission"):
                append_record(
                    element=element,
                    element_path=element_path,
                    attribute=attribute,
                    role="MANIFEST_PATH_PERMISSION_GUARD",
                    claim="ACCESS_CONTROL_REFERENCE",
                )

        child_ordinals: dict[str, int] = {}
        for child in element:
            child_tag = child.tag.rsplit("}", 1)[-1]
            child_ordinals[child_tag] = child_ordinals.get(child_tag, 0) + 1
            visit(child, f"{element_path}/{child_tag}[{child_ordinals[child_tag]}]")

    root_tag = manifest_root.tag.rsplit("}", 1)[-1]
    visit(manifest_root, f"/{root_tag}")
    return tuple(records)


def build_permission_occurrence_product(
    manifest_root: ElementTree.Element,
    *,
    artifact_sha256: str,
    artifact_scope: str,
    package_name: str | None,
    analysis_run_id: str,
    producer_version: str,
    observed_at_utc: str,
    role_families: Sequence[str] = _PERMISSION_ROLE_FAMILIES,
    family_observer: Callable[[str], None] | None = None,
    emission_observer: Callable[[Mapping[str, object], int], None] | None = None,
) -> Mapping[str, object]:
    """Return a digest-bound extraction product with explicit terminal scope.

    ``emission_observer`` is an optional streaming/checkpoint seam. Raising
    :class:`PermissionOccurrenceExtractionInterrupted` from it produces a
    PARTIAL terminal product while retaining every record already emitted.
    Other extraction failures produce FAILED before output or PARTIAL after it.
    """

    if artifact_scope not in {"BASE", "SPLIT", "OTHER", "UNKNOWN"}:
        raise ValueError("unsupported permission occurrence artifact scope")
    requested_families = tuple(dict.fromkeys(role_families))
    if not requested_families or any(
        family not in _PERMISSION_ROLE_FAMILIES for family in requested_families
    ):
        raise ValueError("unsupported permission occurrence role family")

    schema_digest = _semantic_sha256(_PERMISSION_OCCURRENCE_PRODUCT_SCHEMA)
    extraction_contract = {
        "product_schema_digest": schema_digest,
        "role_families": list(requested_families),
    }
    extractor_contract_digest = _semantic_sha256(extraction_contract)
    records: list[Mapping[str, object]] = []
    attempted: list[str] = []
    completed: list[str] = []
    terminal_state = "SUCCEEDED"
    reason: str | None = None
    try:
        for family in requested_families:
            attempted.append(family)
            if family_observer is not None:
                family_observer(family)
            for record in _permission_occurrences_for_family(
                manifest_root,
                role_family=family,
                artifact_sha256=artifact_sha256,
                package_name=package_name,
                analysis_run_id=analysis_run_id,
                producer_version=producer_version,
                observed_at_utc=observed_at_utc,
            ):
                records.append(record)
                if emission_observer is not None:
                    emission_observer(record, len(records))
            completed.append(family)
    except Exception as exc:
        terminal_state = "PARTIAL" if records else "FAILED"
        reason = f"{type(exc).__name__}: {exc}"

    occurrence_digests = sorted(str(record["logical_occurrence_digest"]) for record in records)
    output_set_digest = _semantic_sha256({"logical_occurrence_digests": occurrence_digests})
    decoded_tree_digest = hashlib.sha256(
        ElementTree.tostring(manifest_root, encoding="utf-8")
    ).hexdigest()
    core: dict[str, object] = {
        "product_format": _PERMISSION_OCCURRENCE_PRODUCT_FORMAT,
        "product_schema_digest": schema_digest,
        "subject": {
            "artifact_sha256": artifact_sha256,
            "artifact_scope": artifact_scope,
            "package_name": package_name,
            "captured_install_set": {
                "completeness": "NOT_ESTABLISHED",
                "set_digest": None,
                "member_artifact_sha256": [],
                "role_complete_member_artifact_sha256": [],
            },
        },
        "source_document": {
            "kind": "DECODED_ANDROID_MANIFEST_XML_TREE",
            "opened": True,
            "decoded": True,
            "decoded_tree_sha256": decoded_tree_digest,
        },
        "extractor": {
            "id": "scytaledroid.android_manifest.permission_occurrences",
            "version": producer_version,
            "contract_digest": extractor_contract_digest,
        },
        "scope": {
            "role_families_attempted": attempted,
            "role_families_completed": completed,
        },
        "terminal": {
            "state": terminal_state,
            "reason": reason,
            "emitted_occurrence_count": len(records),
            "output_set_digest": output_set_digest,
        },
        "occurrences": records,
    }
    return {**core, "product_digest": _semantic_sha256(core)}


def build_permission_occurrence_evidence(
    manifest_root: ElementTree.Element,
    *,
    artifact_sha256: str,
    package_name: str | None,
    analysis_run_id: str,
    producer_version: str,
    observed_at_utc: str,
) -> tuple[Mapping[str, object], ...]:
    """Build additive role-specific evidence without assigning PI authority.

    Projection stays explicitly deferred. This exporter preserves the exact
    manifest token and element role; a Permission Intel consumer can later
    apply its versioned projection policy without losing source identity.
    """

    product = build_permission_occurrence_product(
        manifest_root,
        artifact_sha256=artifact_sha256,
        artifact_scope="UNKNOWN",
        package_name=package_name,
        analysis_run_id=analysis_run_id,
        producer_version=producer_version,
        observed_at_utc=observed_at_utc,
    )
    if product["terminal"]["state"] != "SUCCEEDED":
        raise StaticAnalysisError("permission occurrence extraction did not complete")
    return tuple(product["occurrences"])


__all__ = [
    "load_manifest_root",
    "build_manifest_flags",
    "extract_compile_sdk",
    "application_default_permission",
    "effective_component_permission",
    "effective_provider_permissions",
    "collect_exported_components",
    "build_manifest_evidence",
    "collect_custom_permission_definitions",
    "build_permission_occurrence_evidence",
    "build_permission_occurrence_product",
    "PermissionOccurrenceExtractionInterrupted",
]
