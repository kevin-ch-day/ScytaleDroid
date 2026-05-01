"""Static analysis package."""

from __future__ import annotations

import logging
from importlib import import_module

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

_LAZY_EXPORTS = {
    "AnalysisConfig": (".core", "AnalysisConfig"),
    "DetectorContext": (".core", "DetectorContext"),
    "DetectorResult": (".core", "DetectorResult"),
    "EvidencePointer": (".core", "EvidencePointer"),
    "Finding": (".core", "Finding"),
    "MasvsCategory": (".core", "MasvsCategory"),
    "SeverityLevel": (".core", "SeverityLevel"),
    "StaticAnalysisError": (".core", "StaticAnalysisError"),
    "StaticAnalysisReport": (".core", "StaticAnalysisReport"),
    "analyze_apk": (".core", "analyze_apk"),
}


def __getattr__(name: str) -> object:
    if name not in _LAZY_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = _LAZY_EXPORTS[name]
    module = import_module(module_name, __name__)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value

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
