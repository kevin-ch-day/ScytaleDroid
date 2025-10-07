"""Integrity & identity detector with APK topology awareness."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import Path
from time import perf_counter
from typing import Iterable, Optional, Sequence
from xml.etree import ElementTree
from zipfile import BadZipFile, ZipFile, ZipInfo

from androguard.core.apk import APK

from ..core.context import DetectorContext
from ..core.findings import Badge, DetectorResult, EvidencePointer
from .base import BaseDetector, register_detector

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_DIST_NS = "{http://schemas.android.com/apk/distribution}"
_EXECUTABLE_PAYLOAD_TYPES = {"dex", "jar", "so"}
_LARGE_PAYLOAD_THRESHOLD = 5 * 1024 * 1024  # 5 MiB


@dataclass(frozen=True)
class PayloadIndicator:
    """Describes an embedded payload detected within an APK."""

    location: str
    payload_type: str
    size_bytes: int
    hash_short: str


@dataclass(frozen=True)
class ModuleProfile:
    """Captured characteristics for a base or split module."""

    path: Path
    role: str
    split_name: Optional[str]
    config_for: Optional[str]
    config_category: Optional[str]
    install_mode: Optional[str]
    is_instant: bool
    required_split_types: Sequence[str]
    multi_dex_count: int
    signatures: Sequence[str]
    manifest_pointer: str
    manifest_hash: Optional[str]
    payloads: Sequence[PayloadIndicator]


def _looks_like_config_split(
    apk_path: Path,
    split_name: Optional[str],
    config_for: Optional[str],
) -> bool:
    if not split_name:
        return False

    if config_for:
        return True

    split_lower = split_name.lower()
    filename_lower = apk_path.name.lower()

    if split_lower.startswith("config."):
        return True

    if "split_config" in filename_lower or ".config." in filename_lower:
        return True

    return False


@register_detector
class IntegrityIdentityDetector(BaseDetector):
    """Summarises APK topology, signing lineage, and payload indicators."""

    detector_id = "integrity_identity"
    name = "Integrity & Identity detector"
    default_profiles = ("quick", "full")
    section_key = "integrity"

    def run(self, context: DetectorContext) -> DetectorResult:
        started = perf_counter()

        modules, notes = _collect_modules(context)
        module_lookup = {module.path.resolve(): module for module in modules}
        current_module = module_lookup.get(context.apk_path.resolve())
        if current_module is None and modules:
            current_module = modules[0]

        feature_modules = tuple(module for module in modules if module.role == "feature")
        config_modules = tuple(module for module in modules if module.role == "config")
        instant_modules = tuple(module for module in feature_modules if module.is_instant)

        required_types = set()
        if current_module is not None and current_module.role == "base":
            required_types.update(current_module.required_split_types)

        available_types = {
            f"{(module.config_for or 'base')}__{module.config_category or 'other'}"
            for module in config_modules
        }

        missing_required = sorted(required_types - available_types)
        required_summary, required_note = _summarise_required_types(
            current_module=current_module,
            required_types=sorted(required_types),
            missing_required=missing_required,
            config_modules=config_modules,
        )

        signatures_consistent = _signature_consistency(modules)
        debug_cert_state = _aggregate_debug_certificate_state(modules)

        multi_dex_total = sum(
            module.multi_dex_count
            for module in modules
            if module.role in {"base", "feature"}
        )

        payloads = tuple(
            payload
            for module in modules
            for payload in module.payloads
        )

        presentation = _build_presentation_payload(
            context=context,
            modules=modules,
            current_module=current_module,
            feature_modules=feature_modules,
            config_modules=config_modules,
            instant_modules=instant_modules,
            required_types=sorted(required_types),
            missing_required=missing_required,
            payloads=payloads,
            multi_dex_total=multi_dex_total,
            signatures_consistent=signatures_consistent,
            debug_cert_state=debug_cert_state,
        )

        metrics = {
            "presentation": presentation,
            "APK Topology": _build_topology_lines(
                context=context,
                current_module=current_module,
                feature_modules=feature_modules,
                config_modules=config_modules,
                instant_modules=instant_modules,
                required_summary=required_summary,
                multi_dex_total=multi_dex_total,
                payloads=payloads,
                signatures_consistent=signatures_consistent,
                debug_cert_state=debug_cert_state,
            ),
        }

        evidence = _select_evidence(modules, payloads)

        if required_note:
            notes.append(required_note)

        status = _determine_status(
            modules=modules,
            missing_required=missing_required,
            signatures_consistent=signatures_consistent,
        )

        duration = round(perf_counter() - started, 4)

        return DetectorResult(
            detector_id=self.detector_id,
            section_key=self.section_key,
            status=status,
            duration_sec=duration,
            metrics=metrics,
            evidence=evidence,
            notes=tuple(notes),
        )


def _collect_modules(context: DetectorContext) -> tuple[tuple[ModuleProfile, ...], list[str]]:
    """Return module profiles for the base APK and any discovered splits."""

    base_pkg = context.apk.get_package()
    base_dir = context.apk_path.resolve().parent
    candidates = sorted(
        path for path in base_dir.glob("*.apk") if path.is_file()
    )

    modules: list[ModuleProfile] = []
    notes: list[str] = []

    for candidate in candidates:
        try:
            if candidate.resolve() == context.apk_path.resolve():
                apk_obj = context.apk
                manifest_root = context.manifest_root
            else:
                apk_obj = APK(str(candidate))
                manifest_root = _parse_manifest(apk_obj)

            if apk_obj.get_package() != base_pkg:
                continue

            modules.append(
                _profile_module(
                    apk_path=candidate,
                    apk_obj=apk_obj,
                    manifest_root=manifest_root,
                )
            )
        except Exception as exc:  # pragma: no cover - defensive guard
            notes.append(f"Failed to profile split {candidate.name}: {exc}")

    modules.sort(key=lambda module: (module.path != context.apk_path.resolve(), module.path.name))
    return tuple(modules), notes


def _profile_module(
    *,
    apk_path: Path,
    apk_obj: APK,
    manifest_root: ElementTree.Element,
) -> ModuleProfile:
    split_name = _coerce_optional_str(manifest_root.get("split"))
    config_for_attr = _coerce_optional_str(manifest_root.get("configForSplit"))
    required_split_types = tuple(sorted(_extract_required_split_types(manifest_root)))

    install_mode, is_instant = _extract_delivery_info(manifest_root)

    is_config_split = _looks_like_config_split(
        apk_path,
        split_name,
        config_for_attr,
    )

    if is_config_split:
        role = "config"
        config_category = _infer_config_category(split_name)
    elif split_name:
        role = "feature"
        config_category = None
    else:
        role = "base"
        config_category = None

    signatures = tuple(sorted(_normalise_signature_names(apk_obj.get_signature_names())))

    manifest_pointer = _build_manifest_pointer(apk_path, split_name, config_for_attr)
    manifest_hash = _manifest_hash(manifest_root)

    multi_dex_count = _count_multidex(apk_path)
    payloads = _detect_payloads(apk_path)

    effective_config_for = config_for_attr or ("base" if is_config_split else None)

    return ModuleProfile(
        path=apk_path.resolve(),
        role=role,
        split_name=split_name,
        config_for=effective_config_for,
        config_category=config_category,
        install_mode=install_mode,
        is_instant=is_instant,
        required_split_types=required_split_types,
        multi_dex_count=multi_dex_count,
        signatures=signatures,
        manifest_pointer=manifest_pointer,
        manifest_hash=manifest_hash,
        payloads=payloads,
    )


def _build_topology_lines(
    *,
    context: DetectorContext,
    current_module: Optional[ModuleProfile],
    feature_modules: Sequence[ModuleProfile],
    config_modules: Sequence[ModuleProfile],
    instant_modules: Sequence[ModuleProfile],
    required_summary: str,
    multi_dex_total: int,
    payloads: Sequence[PayloadIndicator],
    signatures_consistent: Optional[bool],
    debug_cert_state: str,
) -> list[str]:
    role_label = _describe_role(current_module)

    feature_summary = _format_feature_summary(feature_modules)
    config_summary = _format_config_summary(config_modules)
    feature_line = f"Feature splits: {feature_summary}"
    config_line = f"Config splits: {config_summary}"

    required_text = required_summary or "—"

    if hasattr(context.apk, "is_signed_v4") and callable(getattr(context.apk, "is_signed_v4")):
        v4_signed = bool(context.apk.is_signed_v4())  # type: ignore[attr-defined]
    else:
        v4_signed = False

    signing_schemes = [
        name
        for name, present in (
            ("v2", bool(getattr(context.apk, "is_signed_v2", lambda: False)())),
            ("v3", bool(getattr(context.apk, "is_signed_v3", lambda: False)())),
            ("v4", v4_signed),
        )
        if present
    ]
    signing_text = ",".join(signing_schemes) + " present" if signing_schemes else "v2,v3 absent"

    signature_consistency_text = _describe_consistency(signatures_consistent)
    payload_text = _format_payload_summary(payloads, current_module)
    scan_scope_text = _format_scan_scope(
        current_module,
        feature_modules,
        config_modules,
        instant_modules,
    )
    multi_dex_text = _format_multidex_value(current_module, multi_dex_total)

    lines: list[str] = []
    delivery_summary = _build_delivery_summary(feature_modules, config_modules)
    if delivery_summary:
        lines.append(delivery_summary)
    lines.extend(
        [
            f"Role: {role_label}",
            f"{feature_line}   {config_line}",
            f"Required split types: {required_text}",
            f"Multi-dex: {multi_dex_text}",
            (
                "Signing: "
                f"{signing_text}  |  Debug cert: {debug_cert_state}  |  "
                f"Split signatures consistent: {signature_consistency_text}"
            ),
            f"Payloads: {payload_text}",
            f"Scan scope: {scan_scope_text}",
        ]
    )

    return lines


def _build_delivery_summary(
    feature_modules: Sequence[ModuleProfile],
    config_modules: Sequence[ModuleProfile],
) -> str:
    feature_count = len(feature_modules)
    config_count = len(config_modules)

    if not feature_count and not config_count:
        return "This package delivers a single base module."

    segments: list[str] = []
    if feature_count:
        segments.append(
            f"{feature_count} feature split{'s' if feature_count != 1 else ''}"
        )
    if config_count:
        category_labels = _describe_config_categories(config_modules)
        if category_labels:
            segments.append(
                f"{config_count} config split{'s' if config_count != 1 else ''} ({category_labels})"
            )
        else:
            segments.append(
                f"{config_count} config split{'s' if config_count != 1 else ''}"
            )

    return "This package uses Play Feature/Config Delivery: base + " + " + ".join(segments)


def _build_presentation_payload(
    *,
    context: DetectorContext,
    modules: Sequence[ModuleProfile],
    current_module: Optional[ModuleProfile],
    feature_modules: Sequence[ModuleProfile],
    config_modules: Sequence[ModuleProfile],
    instant_modules: Sequence[ModuleProfile],
    required_types: Sequence[str],
    missing_required: Sequence[str],
    payloads: Sequence[PayloadIndicator],
    multi_dex_total: int,
    signatures_consistent: Optional[bool],
    debug_cert_state: str,
) -> dict[str, object]:
    delivery_summary = _build_delivery_summary(feature_modules, config_modules)
    feature_counts = Counter(_normalise_mode(module.install_mode) for module in feature_modules)
    config_counts = Counter(module.config_category or "other" for module in config_modules)

    module_counts = {
        "features": {
            "count": len(feature_modules),
            "install_modes": {
                "install-time": feature_counts.get("install-time", 0),
                "on-demand": feature_counts.get("on-demand", 0),
                "unknown": feature_counts.get("unknown", 0),
            },
        },
        "configs": {
            "count": len(config_modules),
            "categories": {
                "abi": config_counts.get("abi", 0),
                "density": config_counts.get("density", 0),
                "language": config_counts.get("locale", 0),
                "other": config_counts.get("other", 0),
            },
        },
    }

    requirements = [
        {
            "label": requirement,
            "state": "present" if requirement not in missing_required else "missing",
        }
        for requirement in required_types
    ]

    signing_profile = _build_signing_profile(
        apk=context.apk,
        modules=modules,
        signatures_consistent=signatures_consistent,
        debug_cert_state=debug_cert_state,
    )

    payload_inventory = _summarise_payload_inventory(
        payloads=payloads,
        multi_dex_total=multi_dex_total,
    )

    scan_plan = _build_scan_plan_profile(
        current_module=current_module,
        feature_modules=feature_modules,
        config_modules=config_modules,
        instant_modules=instant_modules,
        missing_required=missing_required,
    )

    try:
        size_bytes = context.apk_path.stat().st_size
    except OSError:  # pragma: no cover - file may be missing in edge cases
        size_bytes = 0

    manifest = getattr(context, "manifest_summary", None)
    hashes = dict(context.hashes) if context.hashes else {}

    package_profile = {
        "delivery": delivery_summary,
        "module_counts": module_counts,
        "install_requirements": requirements,
        "signing": signing_profile,
        "payload_inventory": payload_inventory,
    }

    artifact_profile = {
        "role": _describe_role(current_module),
        "scan_plan": scan_plan,
    }

    integrity_card = {
        "size_bytes": size_bytes,
        "multi_dex_total": multi_dex_total,
        "role_label": _describe_role(current_module),
        "sdk": {
            "min": getattr(manifest, "min_sdk", None),
            "target": getattr(manifest, "target_sdk", None),
            "compile": getattr(manifest, "compile_sdk", None),
        },
        "hashes": {
            "md5": hashes.get("md5"),
            "sha1": hashes.get("sha1"),
            "sha256": hashes.get("sha256"),
        },
    }

    return {
        "package": package_profile,
        "artifact": artifact_profile,
        "integrity": integrity_card,
    }


def _summarise_required_types(
    *,
    current_module: Optional[ModuleProfile],
    required_types: Sequence[str],
    missing_required: Sequence[str],
    config_modules: Sequence[ModuleProfile],
) -> tuple[str, Optional[str]]:
    """Return display text and optional note for required split types."""

    if current_module is None or current_module.role != "base":
        return "—", None

    if not required_types:
        return "—", None

    summary = ", ".join(required_types)

    if missing_required:
        note = "Required split types missing from scan set: " + ", ".join(missing_required)
        return f"{summary} (not found in scan set)", note

    if config_modules:
        return f"{summary} (present)", None

    # Required types declared but no matching config splits were scanned.
    note = "Required split types missing from scan set: " + summary
    return f"{summary} (not found in scan set)", note


def _format_feature_summary(modules: Sequence[ModuleProfile]) -> str:
    if not modules:
        return "0"

    counts = Counter(_normalise_mode(module.install_mode) for module in modules)
    ordered_modes = ["install-time", "on-demand", "conditional", "unknown"]
    details = [
        f"{mode}: {counts[mode]}"
        for mode in ordered_modes
        if counts.get(mode)
    ]
    summary = str(len(modules))
    if details:
        summary += " (" + ", ".join(details) + ")"
    return summary


def _format_config_summary(modules: Sequence[ModuleProfile]) -> str:
    if not modules:
        return "0"

    counts = Counter(module.config_category or "other" for module in modules)
    ordered = ["abi", "density", "locale", "other"]
    details: list[str] = []
    for key in ordered:
        if not counts.get(key):
            continue
        label = "lang" if key == "locale" else key
        details.append(f"{label}: {counts[key]}")
    summary = str(len(modules))
    if details:
        summary += " (" + ", ".join(details) + ")"
    return summary


def _build_signing_profile(
    *,
    apk: APK,
    modules: Sequence[ModuleProfile],
    signatures_consistent: Optional[bool],
    debug_cert_state: str,
) -> dict[str, object]:
    v2_signed = bool(getattr(apk, "is_signed_v2", lambda: False)())  # type: ignore[attr-defined]
    v3_signed = bool(getattr(apk, "is_signed_v3", lambda: False)())  # type: ignore[attr-defined]
    if hasattr(apk, "is_signed_v4") and callable(getattr(apk, "is_signed_v4")):
        v4_signed = bool(apk.is_signed_v4())  # type: ignore[attr-defined]
    else:
        v4_signed = False

    signer_sets = _count_signer_sets(modules)

    return {
        "schemes": {"v2": v2_signed, "v3": v3_signed, "v4": v4_signed},
        "debug_cert": _debug_cert_to_bool(debug_cert_state),
        "consistency_state": signatures_consistent,
        "signer_sets": signer_sets,
        "artifact_total": len(modules),
    }


def _summarise_payload_inventory(
    *,
    payloads: Sequence[PayloadIndicator],
    multi_dex_total: int,
) -> dict[str, object]:
    native_count = sum(1 for payload in payloads if payload.payload_type == "so")
    resource_count = len(payloads)
    return {
        "dex": multi_dex_total,
        "native": native_count,
        "resources": resource_count,
        "notable": _detect_notable_payloads(payloads),
    }


def _detect_notable_payloads(payloads: Sequence[PayloadIndicator]) -> list[str]:
    notes: set[str] = set()
    for payload in payloads:
        location_lower = payload.location.lower()
        if "index.android.bundle" in location_lower:
            notes.add("react-native JS bundle")
        if "assetpack/" in location_lower or payload.payload_type == "assetpack":
            notes.add("Play Asset Delivery content")
    return sorted(notes)


def _build_scan_plan_profile(
    *,
    current_module: Optional[ModuleProfile],
    feature_modules: Sequence[ModuleProfile],
    config_modules: Sequence[ModuleProfile],
    instant_modules: Sequence[ModuleProfile],
    missing_required: Sequence[str],
) -> dict[str, str]:
    scope_text = _format_scan_scope(
        current_module,
        feature_modules,
        config_modules,
        instant_modules,
    )

    depth = "—"
    cross_refs = "—"
    if scope_text:
        for segment in scope_text.split("|"):
            if "=" not in segment:
                continue
            label, values = segment.split("=", 1)
            label = label.strip().lower()
            values = values.strip()
            if label == "deep":
                depth = "Deep"
                cross_refs = values
            elif label == "skim":
                if depth == "—" or (current_module and current_module.role == "config"):
                    depth = "Skim"
                    cross_refs = values

    if missing_required:
        coverage = "Missing required config splits reduce runtime parity."
    elif current_module and current_module.role == "config":
        coverage = "Config split skimmed; referencing base manifest."
    elif config_modules:
        coverage = "Config splits skimmed; deep code analysis on base/features."
    else:
        coverage = "Full deep coverage on scanned artifact."

    return {
        "depth": depth,
        "cross_refs": cross_refs,
        "coverage": coverage,
    }


def _count_signer_sets(modules: Sequence[ModuleProfile]) -> Optional[int]:
    signer_sets: set[frozenset[str]] = set()
    for module in modules:
        if not module.signatures:
            return None
        signer_sets.add(frozenset(module.signatures))
    if not signer_sets:
        return None
    return len(signer_sets)


def _debug_cert_to_bool(state: str) -> Optional[bool]:
    if not state:
        return None
    lowered = state.strip().lower()
    if lowered.startswith("y"):
        return True
    if lowered.startswith("n"):
        return False
    return None


def _describe_config_categories(modules: Sequence[ModuleProfile]) -> str:
    categories = sorted({module.config_category or "other" for module in modules})
    if not categories:
        return ""
    display: list[str] = []
    for category in categories:
        if category == "locale":
            display.append("lang")
        else:
            display.append(category)
    return ", ".join(display)


def _format_payload_summary(
    payloads: Sequence[PayloadIndicator],
    current_module: Optional[ModuleProfile],
) -> str:
    if current_module and current_module.role == "config":
        return "—"

    if not payloads:
        return "—"

    counts = Counter(payload.payload_type for payload in payloads)

    executable_types = sorted(t for t in _EXECUTABLE_PAYLOAD_TYPES if counts.get(t))
    parts: list[str] = []
    if executable_types:
        total_exec = sum(counts[t] for t in executable_types)
        parts.append(
            f"{total_exec} executable{'s' if total_exec != 1 else ''} in assets/ ("
            + ", ".join(executable_types)
            + ")"
        )

    if counts.get("assetpack"):
        total_packs = counts["assetpack"]
        parts.append(
            f"{total_packs} large pack{'s' if total_packs != 1 else ''} (assetpack)"
        )

    opaque_types = [ptype for ptype in sorted(counts) if ptype not in _EXECUTABLE_PAYLOAD_TYPES and ptype != "assetpack"]
    for payload_type in opaque_types:
        amount = counts[payload_type]
        parts.append(
            f"{amount} file{'s' if amount != 1 else ''} ({payload_type})"
        )

    return ", ".join(parts) if parts else "detected"


def _format_multidex_value(
    current_module: Optional[ModuleProfile],
    multi_dex_total: int,
) -> str:
    if current_module and current_module.role == "config":
        return "—"
    if multi_dex_total <= 0:
        return "—"
    return str(multi_dex_total)


def _format_scan_scope(
    current_module: Optional[ModuleProfile],
    feature_modules: Sequence[ModuleProfile],
    config_modules: Sequence[ModuleProfile],
    instant_modules: Sequence[ModuleProfile],
) -> str:
    deep_parts: list[str] = []
    if current_module:
        if current_module.role == "base":
            deep_parts.append("base")
        else:
            deep_parts.append(current_module.role)
    else:
        deep_parts.append("base")

    if feature_modules:
        deep_parts.append("+feature(s)")

    if instant_modules:
        deep_parts.append("+instant")

    deep_text = ",".join(deep_parts)

    config_categories = sorted({module.config_category or "other" for module in config_modules})
    if current_module and current_module.role == "config":
        skim_text = "config-only"
    else:
        skim_text = ",".join(config_categories) if config_categories else "none"

    return f"Deep = {deep_text} | Skim = {skim_text}"


def _determine_status(
    *,
    modules: Sequence[ModuleProfile],
    missing_required: Sequence[str],
    signatures_consistent: Optional[bool],
) -> Badge:
    if missing_required or signatures_consistent is False:
        return Badge.WARN
    if modules:
        return Badge.OK
    return Badge.INFO


def _select_evidence(
    modules: Sequence[ModuleProfile],
    payloads: Sequence[PayloadIndicator],
) -> tuple[EvidencePointer, ...]:
    pointers: list[EvidencePointer] = []

    for module in modules:
        if module.role != "base" and module.manifest_hash:
            pointers.append(
                EvidencePointer(
                    location=module.manifest_pointer,
                    hash_short=module.manifest_hash,
                )
            )
            break

    payload_candidates = sorted(payloads, key=lambda payload: payload.location)
    if payload_candidates:
        payload = payload_candidates[0]
        pointers.append(
            EvidencePointer(
                location=payload.location,
                hash_short=payload.hash_short,
            )
        )

    return tuple(pointers[:2])


def _signature_consistency(modules: Sequence[ModuleProfile]) -> Optional[bool]:
    reference: Optional[set[str]] = None
    for module in modules:
        if module.signatures:
            reference = set(module.signatures)
            break

    if reference is None:
        return None

    for module in modules:
        if not module.signatures:
            continue
        if set(module.signatures) != reference:
            return False

    if any(not module.signatures for module in modules):
        return None

    return True


def _aggregate_debug_certificate_state(modules: Sequence[ModuleProfile]) -> str:
    saw_signatures = False
    for module in modules:
        if not module.signatures:
            continue
        saw_signatures = True
        if any("android debug" in signature.lower() for signature in module.signatures):
            return "Yes"
    if saw_signatures:
        return "No"
    return "—"


def _describe_role(module: Optional[ModuleProfile]) -> str:
    if module is None:
        return "unknown"
    if module.role == "base":
        return "base"
    if module.role == "feature":
        return "feature split" + (" (instant)" if module.is_instant else "")
    if module.role == "config":
        detail = f" ({module.config_category})" if module.config_category else ""
        return f"config split{detail}"
    return module.role


def _describe_consistency(value: Optional[bool]) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "—"


def _normalise_mode(value: Optional[str]) -> str:
    if not value:
        return "unknown"
    value_normalised = value.strip().lower().replace("_", "-")
    if value_normalised in {"install", "installtime"}:
        return "install-time"
    if value_normalised in {"ondemand", "on-demand"}:
        return "on-demand"
    if value_normalised in {"conditional", "conditions"}:
        return "conditional"
    return value_normalised


def _detect_payloads(apk_path: Path) -> tuple[PayloadIndicator, ...]:
    try:
        archive = ZipFile(apk_path)
    except (OSError, BadZipFile):  # pragma: no cover - corrupted splits are rare
        return tuple()

    payloads: list[PayloadIndicator] = []
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            entry = info.filename
            lower_entry = entry.lower()

            payload_type: Optional[str] = None
            if lower_entry.startswith("assetpack/"):
                payload_type = "assetpack"
            elif lower_entry.startswith("assets/"):
                if lower_entry.endswith(".dex"):
                    payload_type = "dex"
                elif lower_entry.endswith(".jar"):
                    payload_type = "jar"
                elif lower_entry.endswith(".so"):
                    payload_type = "so"
                elif "assetpack" in lower_entry:
                    payload_type = "assetpack"
                elif info.file_size >= _LARGE_PAYLOAD_THRESHOLD:
                    payload_type = "opaque"
            elif info.file_size >= _LARGE_PAYLOAD_THRESHOLD:
                payload_type = "opaque"

            if not payload_type:
                continue

            hash_short = _hash_zip_entry(archive, info)
            location = f"{apk_path.resolve().as_posix()}!{entry}"
            payloads.append(
                PayloadIndicator(
                    location=location,
                    payload_type=payload_type,
                    size_bytes=info.file_size,
                    hash_short=hash_short,
                )
            )

    payloads.sort(key=lambda payload: payload.location)
    return tuple(payloads)


def _count_multidex(apk_path: Path) -> int:
    try:
        archive = ZipFile(apk_path)
    except (OSError, BadZipFile):  # pragma: no cover - corrupted splits are rare
        return 0

    count = 0
    with archive:
        for info in archive.infolist():
            name = info.filename
            if name.startswith("classes") and name.endswith(".dex"):
                count += 1
    return count


def _hash_zip_entry(archive: ZipFile, info: ZipInfo) -> str:
    digest = hashlib.sha256()
    with archive.open(info, "r") as handle:  # type: ignore[arg-type]
        for chunk in iter(lambda: handle.read(4096), b""):
            digest.update(chunk)
    return "#h:" + digest.hexdigest()[:8]


def _manifest_hash(root: ElementTree.Element) -> str:
    data = ElementTree.tostring(root, encoding="utf-8")
    digest = hashlib.sha256(data).hexdigest()[:8]
    return f"#h:{digest}"


def _build_manifest_pointer(
    apk_path: Path,
    split_name: Optional[str],
    config_for: Optional[str],
) -> str:
    attrs: list[str] = []
    if split_name:
        attrs.append(f"@split='{split_name}'")
    if config_for:
        attrs.append(f"@configForSplit='{config_for}'")
    suffix = ":/manifest"
    if attrs:
        suffix += "[" + " and ".join(attrs) + "]"
    return f"{apk_path.resolve().as_posix()}!AndroidManifest.xml{suffix}"


def _extract_delivery_info(root: ElementTree.Element) -> tuple[Optional[str], bool]:
    module = root.find(f".//{_DIST_NS}module")
    if module is None:
        return None, False

    instant = module.get(f"{_DIST_NS}instant")
    on_demand_attr = module.get(f"{_DIST_NS}onDemand")

    delivery = module.find(f"{_DIST_NS}delivery")
    mode: Optional[str] = None
    if delivery is not None:
        if delivery.find(f"{_DIST_NS}install-time") is not None:
            mode = "install-time"
        elif delivery.find(f"{_DIST_NS}on-demand") is not None:
            mode = "on-demand"
        elif delivery.find(f"{_DIST_NS}conditions") is not None:
            mode = "conditional"

    if mode is None and on_demand_attr:
        mode = "on-demand" if on_demand_attr.lower() == "true" else "install-time"

    return mode, (instant or "").lower() == "true"


def _infer_config_category(split_name: str) -> Optional[str]:
    label = split_name.split(".", 1)[-1].lower()
    tokens = {token.replace("-", "_") for token in label.split(".")}
    abi_tokens = {
        "armeabi",
        "armeabi_v7a",
        "arm64_v8a",
        "x86",
        "x86_64",
        "mips",
    }
    density_tokens = {
        "ldpi",
        "mdpi",
        "hdpi",
        "xhdpi",
        "xxhdpi",
        "xxxhdpi",
        "nodpi",
        "tvdpi",
    }

    if tokens & abi_tokens:
        return "abi"
    if tokens & density_tokens:
        return "density"
    if any(token.isalpha() and len(token) <= 3 for token in tokens):
        return "locale"
    if any("-r" in token for token in tokens):
        return "locale"
    return "other"


def _extract_required_split_types(root: ElementTree.Element) -> set[str]:
    values: set[str] = set()
    for element in (root, root.find("application")):
        if element is None:
            continue
        for attribute in ("requiredSplitTypes", f"{_ANDROID_NS}requiredSplitTypes"):
            raw = element.get(attribute)
            if raw:
                values.update(_split_attr_values(raw))
    return values


def _split_attr_values(value: str) -> Iterable[str]:
    delimiters = ",; "
    tokens: list[str] = []
    current = ""
    for char in value:
        if char in delimiters:
            if current:
                tokens.append(current)
            current = ""
        else:
            current += char
    if current:
        tokens.append(current)
    return (token.strip() for token in tokens if token.strip())


def _parse_manifest(apk_obj: APK) -> ElementTree.Element:
    manifest_xml = apk_obj.get_android_manifest_xml()
    if hasattr(manifest_xml, "tag"):
        try:
            manifest_bytes = ElementTree.tostring(manifest_xml, encoding="utf-8")
        except Exception:  # pragma: no cover - fallback path
            manifest_bytes = ElementTree.tostring(manifest_xml)
    else:
        manifest_bytes = manifest_xml.encode("utf-8") if isinstance(manifest_xml, str) else manifest_xml
    return ElementTree.fromstring(manifest_bytes)


def _normalise_signature_names(names: Iterable[str]) -> Iterable[str]:
    for name in names:
        if not isinstance(name, str):
            continue
        yield name.strip()


def _coerce_optional_str(value: object) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None
    return str(value)


__all__ = ["IntegrityIdentityDetector"]
