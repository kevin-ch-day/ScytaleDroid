"""Base classes and registry helpers for static-analysis detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Iterable, List, Sequence, Tuple, Type, TypeVar

from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ..core import AnalysisConfig, DetectorContext, DetectorResult


class DetectorRegistrationError(RuntimeError):
    """Raised when a detector cannot be registered."""


class _DetectorRegistry:
    """Internal registry tracking available detector classes."""

    def __init__(self) -> None:
        self._registry: Dict[str, Type[BaseDetector]] = {}

    def register(self, detector_cls: Type["BaseDetector"]) -> Type["BaseDetector"]:
        detector_id = detector_cls.detector_id
        if not detector_id:
            raise DetectorRegistrationError("Detector must declare a detector_id")
        if detector_id in self._registry:
            raise DetectorRegistrationError(f"Detector {detector_id} already registered")
        self._registry[detector_id] = detector_cls
        log.debug(
            f"Registered static analysis detector {detector_id}",
            category="static_analysis",
        )
        return detector_cls

    def get_active_detectors(
        self, config: AnalysisConfig
    ) -> Tuple["BaseDetector", ...]:
        enabled = set(config.enabled_detectors or [])
        detectors: List[BaseDetector] = []
        for detector_cls in self._registry.values():
            if enabled and detector_cls.detector_id not in enabled:
                continue
            detector = detector_cls()
            if detector.applies_to_profile(config.profile):
                detectors.append(detector)
        detectors.sort(key=lambda detector: detector.detector_id)
        return tuple(detectors)


_REGISTRY = _DetectorRegistry()


class BaseDetector(ABC):
    """Abstract base class for static-analysis detectors."""

    detector_id: str = "base"
    name: str = "Base detector"
    default_profiles: Sequence[str] = ("quick", "full")

    def applies_to_profile(self, profile: str) -> bool:
        if not self.default_profiles:
            return True
        return profile in self.default_profiles

    @abstractmethod
    def run(self, context: DetectorContext) -> DetectorResult:
        """Execute the detector and return a result."""


DetectorType = TypeVar("DetectorType", bound=BaseDetector)


def register_detector(detector_cls: Type[DetectorType]) -> Type[DetectorType]:
    """Class decorator used to register detectors automatically."""

    return _REGISTRY.register(detector_cls)


def execute_detectors(context: DetectorContext) -> Tuple[DetectorResult, ...]:
    """Execute all detectors applicable to the provided context."""

    detectors = _REGISTRY.get_active_detectors(context.config)
    results: List[DetectorResult] = []

    for detector in detectors:
        try:
            result = detector.run(context)
        except Exception as exc:  # pragma: no cover - detectors should not crash pipeline
            log.error(
                f"Detector {detector.detector_id} failed: {exc}",
                category="static_analysis",
            )
            result = DetectorResult(
                detector_id=detector.detector_id,
                findings=tuple(),
                metrics={"error": str(exc)},
            )
        results.append(result)

    return tuple(results)


def registered_detector_ids() -> Iterable[str]:
    return tuple(_REGISTRY._registry.keys())


__all__ = [
    "BaseDetector",
    "DetectorRegistrationError",
    "register_detector",
    "execute_detectors",
    "registered_detector_ids",
]
