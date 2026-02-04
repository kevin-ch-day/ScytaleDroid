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
from . import (
    components,  # noqa: E402,F401
    correlation,  # noqa: E402,F401
    crypto,  # noqa: E402,F401
    dfir,  # noqa: E402,F401
    domain_verification,  # noqa: E402,F401
    dynamic,  # noqa: E402,F401
    fileio,  # noqa: E402,F401
    integrity,  # noqa: E402,F401
    interaction,  # noqa: E402,F401
    manifest,  # noqa: E402,F401
    native,  # noqa: E402,F401
    network,  # noqa: E402,F401
    obfuscation,  # noqa: E402,F401
    permissions,  # noqa: E402,F401
    provider_acl,  # noqa: E402,F401
    sdks,  # noqa: E402,F401
    secrets,  # noqa: E402,F401
    storage,  # noqa: E402,F401
    webview,  # noqa: E402,F401
)
