"""Dynamic code-loading and reflection analysis module."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Mapping

from scytaledroid.Database.db_func.harvest import dynamic_loading as dyn_db
from scytaledroid.StaticAnalysis._androguard import APK, open_apk_safely, merge_bounds_warnings
from scytaledroid.Utils.LoggingUtils import logging_utils as log

from .module_api import AppModuleContext, ModuleResult, StaticModule
from .string_analysis.indexing.builder import build_string_index


_CLASSLOADER_TOKENS: tuple[str, ...] = (
    "DexClassLoader",
    "PathClassLoader",
    "BaseDexClassLoader",
    "InMemoryDexClassLoader",
)

_NATIVE_TOKENS: tuple[str, ...] = (
    "System.loadLibrary",
    "System.load",
    "Runtime.getRuntime().load",
    "Runtime.getRuntime().loadLibrary",
    "dlopen",
)

_REFLECTION_KEYWORDS: tuple[str, ...] = (
    "Class.forName",
    "java.lang.reflect",
    "getDeclaredMethod",
    "getMethod",
    "invoke",
)

_SENSITIVE_REFLECTION_TARGETS: tuple[str, ...] = (
    "android.hardware.Camera",
    "android.hardware.camera2.CameraManager",
    "android.media.AudioRecord",
    "android.media.MediaRecorder",
    "android.telephony.SmsManager",
    "android.telephony.TelephonyManager",
    "android.view.WindowManager",
    "android.provider.Settings$Secure",
    "android.provider.Settings$System",
    "android.app.NotificationManager",
    "android.app.ActivityManager",
)


@dataclass(frozen=True)
class _ReflectionCall:
    target_class: str
    target_method: str | None
    value: str
    origin: str
    sha256: str

    @property
    def evidence_hash(self) -> str:
        digest = hashlib.sha1()
        digest.update(self.target_class.encode("utf-8"))
        digest.update((self.target_method or "").encode("utf-8"))
        digest.update(self.sha256.encode("utf-8"))
        return digest.hexdigest()


class DynamicLoadModule(StaticModule):
    """Detects dynamic class loading, native bridges, and reflection hotspots."""

    name = "dynload"
    writes_to_db = True

    def run(self, context: AppModuleContext) -> ModuleResult:
        apk, warnings = open_apk_safely(str(context.apk_path))
        if warnings:
            merge_bounds_warnings(context.metadata, warnings)
            log.warning(
                "Resource table parsing emitted bounds warnings",
                category="static_analysis",
                extra={
                    "event": "dynload.resource_bounds_warning",
                    "apk_path": str(context.apk_path),
                    "package_name": context.package_name,
                    "warning_lines": warnings,
                },
            )
        index = build_string_index(apk)

        classloader_hits = [
            entry
            for entry in index.strings
            if entry.origin_type == "code"
            and any(token in entry.value for token in _CLASSLOADER_TOKENS)
        ]
        native_hits = [
            entry
            for entry in index.strings
            if entry.origin_type == "code"
            and any(token in entry.value for token in _NATIVE_TOKENS)
        ]

        reflection_possible = any(
            entry.origin_type == "code"
            and any(keyword in entry.value for keyword in _REFLECTION_KEYWORDS)
            for entry in index.strings
        )

        reflection_calls: list[_ReflectionCall] = []
        if reflection_possible:
            seen_hashes: set[str] = set()
            for entry in index.strings:
                if entry.origin_type != "code":
                    continue
                match = _match_sensitive_target(entry.value)
                if match is None:
                    continue
                call = _ReflectionCall(
                    target_class=match[0],
                    target_method=match[1],
                    value=entry.value,
                    origin=entry.origin,
                    sha256=entry.sha256,
                )
                evidence_hash = call.evidence_hash
                if evidence_hash in seen_hashes:
                    continue
                seen_hashes.add(evidence_hash)
                reflection_calls.append(call)

        events_payload = [
            {
                "class_ref": entry.value,
                "event_type": "classloader",
                "source": entry.origin,
                "origin_type": entry.origin_type,
                "sample_hash": entry.sha256,
                "severity": _classloader_severity(entry.value),
            }
            for entry in classloader_hits
        ]
        events_payload.extend(
            {
                "class_ref": entry.value,
                "event_type": "native",
                "source": entry.origin,
                "origin_type": entry.origin_type,
                "sample_hash": entry.sha256,
                "severity": "medium",
            }
            for entry in native_hits
        )

        reflection_payload = [
            {
                "target_class": call.target_class,
                "target_method": call.target_method,
                "evidence_hash": call.evidence_hash,
                "evidence": {
                    "value": call.value,
                    "origin": call.origin,
                    "sample_hash": call.sha256,
                },
            }
            for call in reflection_calls
        ]

        summary = {
            "classloader_events": len(classloader_hits),
            "native_loads": len(native_hits),
            "reflection_calls": len(reflection_calls),
        }

        data = {
            "context": {
                "package_name": context.package_name,
                "session_stamp": context.session_stamp,
                "scope_label": context.scope_label,
                "app_id": context.app_id,
                "apk_id": context.apk_id,
                "sha256": context.sha256,
            },
            "events": events_payload,
            "reflection_calls": reflection_payload,
        }

        return ModuleResult(module=self.name, data=data, summary=summary)

    def persist(self, result: ModuleResult) -> None:
        if not result.data:
            return
        try:
            dyn_db.ensure_tables()
            dyn_db.replace_events(result.data.get("context", {}), result.data.get("events", ()))
            dyn_db.replace_reflection_calls(
                result.data.get("context", {}), result.data.get("reflection_calls", ())
            )
        except Exception:
            return

    def summarize(self, result: ModuleResult) -> Mapping[str, int]:
        payload = result.summary or {}
        return {
            "classloaders": int(payload.get("classloader_events", 0)),
            "native": int(payload.get("native_loads", 0)),
            "reflection_calls": int(payload.get("reflection_calls", 0)),
        }


def _match_sensitive_target(value: str) -> tuple[str, str | None] | None:
    for candidate in _SENSITIVE_REFLECTION_TARGETS:
        if candidate in value:
            method_match = re.search(r"#([A-Za-z0-9_.$]+)$", value)
            method_name = method_match.group(1) if method_match else None
            return candidate, method_name
    return None


def _classloader_severity(value: str) -> str:
    lowered = value.lower()
    if "dexclassloader" in lowered:
        return "high"
    if "memory" in lowered or "pathclassloader" in lowered:
        return "medium"
    return "low"


__all__ = ["DynamicLoadModule"]
