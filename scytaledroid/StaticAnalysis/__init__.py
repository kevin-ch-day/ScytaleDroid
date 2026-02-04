"""Static analysis package."""

from __future__ import annotations

import logging

from .core import (
    AnalysisConfig,
    DetectorContext,
    DetectorResult,
    EvidencePointer,
    Finding,
    MasvsCategory,
    SeverityLevel,
    StaticAnalysisError,
    StaticAnalysisReport,
    analyze_apk,
)

_ANDROGUARD_LOGGERS = (
    "androguard",
    "androguard.core",
    "androguard.core.axml",
    "androguard.core.apk",
    "androguard.core.bytecodes",
    "androguard.core.api_specific_resources",
)

for _logger_name in _ANDROGUARD_LOGGERS:
    _logger = logging.getLogger(_logger_name)
    # Drop any handlers androguard may have attached so we control verbosity.
    for handler in list(_logger.handlers):
        _logger.removeHandler(handler)
    _logger.addHandler(logging.NullHandler())
    _logger.setLevel(logging.CRITICAL)
    _logger.propagate = False

__all__ = [
    "AnalysisConfig",
    "DetectorContext",
    "analyze_apk",
    "StaticAnalysisReport",
    "StaticAnalysisError",
    "SeverityLevel",
    "MasvsCategory",
    "EvidencePointer",
    "Finding",
    "DetectorResult",
]
