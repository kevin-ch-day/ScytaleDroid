"""Static-analysis detectors package."""

from .base import (
    BaseDetector,
    DetectorRegistrationError,
    execute_detectors,
    register_detector,
    registered_detector_ids,
)

__all__ = [
    "BaseDetector",
    "DetectorRegistrationError",
    "execute_detectors",
    "register_detector",
    "registered_detector_ids",
]

# Register built-in detectors
from . import manifest  # noqa: E402,F401
