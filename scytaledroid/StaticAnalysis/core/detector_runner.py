"""Detector pipeline orchestration helpers."""

from __future__ import annotations

from dataclasses import dataclass, replace
from time import perf_counter
from typing import Tuple, Type

from .findings import Badge, DetectorResult
from ..detectors.base import BaseDetector
from ..detectors.components import IpcExposureDetector
from ..detectors.correlation import CorrelationDetector
from ..detectors.crypto import CryptoHygieneDetector
from ..detectors.dfir import DfirHintsDetector
from ..detectors.domain_verification import DomainVerificationDetector
from ..detectors.dynamic import DynamicLoadingDetector
from ..detectors.fileio import FileIoSinksDetector
from ..detectors.integrity import IntegrityIdentityDetector
from ..detectors.interaction import UserInteractionRisksDetector
from ..detectors.manifest import ManifestBaselineDetector
from ..detectors.native import NativeHardeningDetector
from ..detectors.network import NetworkSurfaceDetector
from ..detectors.obfuscation import ObfuscationDetector
from ..detectors.permissions import PermissionsProfileDetector
from ..detectors.provider_acl import ProviderAclDetector
from ..detectors.sdks import SdkInventoryDetector
from ..detectors.secrets import SecretsDetector
from ..detectors.storage import StorageBackupDetector
from ..detectors.webview import WebViewDetector


@dataclass(frozen=True)
class PipelineStage:
    """Represents a detector invocation in the ordered pipeline."""

    detector_cls: Type[BaseDetector]
    section_key: str
    include_in_quick: bool = True

    def instantiate(self) -> BaseDetector:
        return self.detector_cls()


PIPELINE_STAGES: Tuple[PipelineStage, ...] = (
    PipelineStage(IntegrityIdentityDetector, "integrity"),
    PipelineStage(ManifestBaselineDetector, "manifest_hygiene"),
    PipelineStage(PermissionsProfileDetector, "permissions"),
    PipelineStage(IpcExposureDetector, "ipc_components"),
    PipelineStage(ProviderAclDetector, "provider_acl"),
    PipelineStage(NetworkSurfaceDetector, "network_surface"),
    PipelineStage(DomainVerificationDetector, "domain_verification"),
    PipelineStage(SecretsDetector, "secrets"),
    PipelineStage(StorageBackupDetector, "storage_backup"),
    PipelineStage(DfirHintsDetector, "dfir_hints"),
    PipelineStage(WebViewDetector, "webview", include_in_quick=False),
    PipelineStage(CryptoHygieneDetector, "crypto_hygiene", include_in_quick=False),
    PipelineStage(DynamicLoadingDetector, "dynamic_loading", include_in_quick=False),
    PipelineStage(FileIoSinksDetector, "file_io_sinks", include_in_quick=False),
    PipelineStage(UserInteractionRisksDetector, "interaction_risks", include_in_quick=False),
    PipelineStage(SdkInventoryDetector, "sdk_inventory", include_in_quick=False),
    PipelineStage(NativeHardeningDetector, "native_jni", include_in_quick=False),
    PipelineStage(ObfuscationDetector, "obfuscation", include_in_quick=False),
    PipelineStage(CorrelationDetector, "correlation_findings"),
)


def run_detector_pipeline(context) -> Tuple[DetectorResult, ...]:
    """Execute registered detectors in the fixed pipeline order."""

    results: list[DetectorResult] = []
    profile = (context.config.profile or "full").lower()
    enabled = {detector_id.lower() for detector_id in context.config.enabled_detectors or ()}

    for stage in PIPELINE_STAGES:
        context.intermediate_results = tuple(results)
        detector = stage.instantiate()

        if enabled and detector.detector_id.lower() not in enabled:
            reason = "disabled by custom selection"
            results.append(
                _build_skipped_result(detector, stage.section_key, reason)
            )
            continue

        if profile == "quick" and not stage.include_in_quick:
            reason = "skipped by quick profile"
            results.append(_build_skipped_result(detector, stage.section_key, reason))
            continue

        if not detector.applies_to_profile(context.config.profile):
            reason = f"disabled for profile {context.config.profile}"
            results.append(_build_skipped_result(detector, stage.section_key, reason))
            continue

        started = perf_counter()
        try:
            result = detector.run(context)
            duration = round(perf_counter() - started, 4)
        except Exception as exc:  # pragma: no cover - defensive guard
            duration = round(perf_counter() - started, 4)
            results.append(
                _build_error_result(
                    detector,
                    stage.section_key,
                    duration,
                    f"detector failed: {exc}",
                )
            )
            continue

        if not isinstance(result, DetectorResult):
            results.append(
                _build_error_result(
                    detector,
                    stage.section_key,
                    duration,
                    "detector returned invalid result",
                )
            )
            continue

        updates: dict[str, object] = {}
        if result.detector_id != detector.detector_id:
            updates["detector_id"] = detector.detector_id
        if result.section_key != stage.section_key:
            updates["section_key"] = stage.section_key
        if result.duration_sec <= 0 and duration > 0:
            updates["duration_sec"] = duration
        if updates:
            result = replace(result, **updates)

        results.append(result)

    context.intermediate_results = tuple(results)

    return tuple(results)


def _build_skipped_result(
    detector: BaseDetector,
    section_key: str,
    reason: str,
) -> DetectorResult:
    return DetectorResult(
        detector_id=detector.detector_id,
        section_key=section_key,
        status=Badge.SKIPPED,
        duration_sec=0.0,
        metrics={"skip_reason": reason},
        evidence=tuple(),
        notes=(reason,),
    )


def _build_error_result(
    detector: BaseDetector,
    section_key: str,
    duration: float,
    message: str,
) -> DetectorResult:
    return DetectorResult(
        detector_id=detector.detector_id,
        section_key=section_key,
        status=Badge.SKIPPED,
        duration_sec=max(duration, 0.0),
        metrics={"error": message},
        evidence=tuple(),
        notes=(message,),
    )


__all__ = ["PipelineStage", "PIPELINE_STAGES", "run_detector_pipeline"]
