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

        signatures_consistent = _signature_consistency(modules)
        debug_cert_state = _debug_certificate_state(current_module)

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

        metrics = {
            "APK Topology": _build_topology_lines(
                context=context,
                current_module=current_module,
                feature_modules=feature_modules,
                config_modules=config_modules,
                instant_modules=instant_modules,
                required_types=sorted(required_types),
                missing_required=missing_required,
                multi_dex_total=multi_dex_total,
                payloads=payloads,
                signatures_consistent=signatures_consistent,
                debug_cert_state=debug_cert_state,
            )
        }

        evidence = _select_evidence(modules, payloads)

        if missing_required:
            notes.append(
                "Required split types missing: "
                + ", ".join(missing_required)
            )

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
    config_for = _coerce_optional_str(manifest_root.get("configForSplit"))
    required_split_types = tuple(sorted(_extract_required_split_types(manifest_root)))

    install_mode, is_instant = _extract_delivery_info(manifest_root)

    if split_name and config_for:
        role = "config"
        config_category = _infer_config_category(split_name)
    elif split_name:
        role = "feature"
        config_category = None
    else:
        role = "base"
        config_category = None

    signatures = tuple(sorted(_normalise_signature_names(apk_obj.get_signature_names())))

    manifest_pointer = _build_manifest_pointer(apk_path, split_name, config_for)
    manifest_hash = _manifest_hash(manifest_root)

    multi_dex_count = _count_multidex(apk_path)
    payloads = _detect_payloads(apk_path)

    return ModuleProfile(
        path=apk_path.resolve(),
        role=role,
        split_name=split_name,
        config_for=config_for,
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
    required_types: Sequence[str],
    missing_required: Sequence[str],
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

    required_text = ", ".join(required_types) if required_types else "—"

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

    payload_text = _format_payload_summary(payloads)

    scan_scope_text = _format_scan_scope(current_module, feature_modules, config_modules, instant_modules)

    lines = [
        f"Role: {role_label}",
        f"{feature_line}   {config_line}",
        f"Required split types: {required_text}",
        f"Multi-dex: {multi_dex_total}",
        "Signing: "
        f"{signing_text}  |  Debug cert: {debug_cert_state}  |  Split signatures consistent: {signature_consistency_text}",
        f"Payloads: {payload_text}",
        f"Scan scope: {scan_scope_text}",
    ]

    if missing_required:
        lines.append("Missing required types: " + ", ".join(missing_required))

    return lines


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
    details = [
        f"{key}: {counts[key]}"
        for key in ordered
        if counts.get(key)
    ]
    summary = str(len(modules))
    if details:
        summary += " (" + ", ".join(details) + ")"
    return summary


def _format_payload_summary(payloads: Sequence[PayloadIndicator]) -> str:
    if not payloads:
        return "none detected"

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
    if not modules:
        return None

    base_signatures = set(modules[0].signatures)
    if not base_signatures:
        return None

    for module in modules[1:]:
        if set(module.signatures) != base_signatures:
            return False
    return True


def _debug_certificate_state(module: Optional[ModuleProfile]) -> str:
    if module is None or not module.signatures:
        return "Unknown"
    for signature in module.signatures:
        if "android debug" in signature.lower():
            return "Yes"
    return "No"


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
    return "Unknown"


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
