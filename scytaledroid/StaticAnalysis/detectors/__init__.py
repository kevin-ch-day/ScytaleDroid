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
from . import correlation  # noqa: E402,F401
from . import crypto  # noqa: E402,F401
from . import dynamic  # noqa: E402,F401
from . import fileio  # noqa: E402,F401
from . import integrity  # noqa: E402,F401
from . import interaction  # noqa: E402,F401
from . import manifest  # noqa: E402,F401
from . import native  # noqa: E402,F401
from . import network  # noqa: E402,F401
from . import obfuscation  # noqa: E402,F401
from . import permissions  # noqa: E402,F401
from . import provider_acl  # noqa: E402,F401
from . import sdks  # noqa: E402,F401
from . import secrets  # noqa: E402,F401
from . import storage  # noqa: E402,F401
from . import components  # noqa: E402,F401
from . import domain_verification  # noqa: E402,F401
from . import webview  # noqa: E402,F401
