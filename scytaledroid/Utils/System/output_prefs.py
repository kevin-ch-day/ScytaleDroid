"""Process-local output preferences for menu-driven UI.

These preferences act as defaults for renderers and analysis modules. They are
in-memory for the current run; persistence can be added later if needed.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class OutputPrefs:
    verbose: bool = False
    analytics_detail: bool = False
    string_max_samples: int = 2
    cleartext_only: bool = False
    quiet: bool = False
    batch: bool = False
    run_mode: str = "interactive"
    noninteractive: bool = False
    show_splits: bool = False


_PREFS = OutputPrefs()
_RUN_CONTEXT = None


def get() -> OutputPrefs:
    return _PREFS


def snapshot() -> OutputPrefs:
    """Return a copy of the current preferences for later restoration."""
    return OutputPrefs(**_PREFS.__dict__)


def restore(prefs: OutputPrefs) -> None:
    """Restore preferences from a previous snapshot."""
    for key, value in prefs.__dict__.items():
        setattr(_PREFS, key, value)


def get_run_context():
    return _RUN_CONTEXT


def set_run_context(ctx) -> None:
    global _RUN_CONTEXT
    _RUN_CONTEXT = ctx


def _ctx_flag(name: str, fallback: bool) -> bool:
    ctx = _RUN_CONTEXT
    if ctx is not None and hasattr(ctx, name):
        try:
            return bool(getattr(ctx, name))
        except Exception:
            return bool(fallback)
    return bool(fallback)


def effective_quiet() -> bool:
    return _ctx_flag("quiet", _PREFS.quiet)


def effective_batch() -> bool:
    return _ctx_flag("batch", _PREFS.batch)


def effective_noninteractive() -> bool:
    return _ctx_flag("noninteractive", _PREFS.noninteractive)


def effective_show_splits() -> bool:
    return _ctx_flag("show_splits", _PREFS.show_splits)


def effective_run_mode() -> str:
    ctx = _RUN_CONTEXT
    if ctx is not None and hasattr(ctx, "run_mode"):
        try:
            value = ctx.run_mode
            return str(value or "interactive")
        except Exception:
            return _PREFS.run_mode or "interactive"
    return _PREFS.run_mode or "interactive"


def set_verbose(enabled: bool) -> None:
    _PREFS.verbose = bool(enabled)


def toggle_verbose() -> bool:
    _PREFS.verbose = not _PREFS.verbose
    return _PREFS.verbose


def set_analytics_detail(enabled: bool) -> None:
    _PREFS.analytics_detail = bool(enabled)


def toggle_analytics_detail() -> bool:
    _PREFS.analytics_detail = not _PREFS.analytics_detail
    return _PREFS.analytics_detail


def set_string_max_samples(value: int) -> int:
    try:
        v = int(value)
    except Exception:
        v = 2
    _PREFS.string_max_samples = max(1, min(20, v))
    return _PREFS.string_max_samples


def set_cleartext_only(enabled: bool) -> None:
    _PREFS.cleartext_only = bool(enabled)


def set_quiet(enabled: bool) -> None:
    _PREFS.quiet = bool(enabled)


def set_batch(enabled: bool) -> None:
    _PREFS.batch = bool(enabled)


def set_run_mode(mode: str) -> None:
    _PREFS.run_mode = mode or "interactive"


def set_noninteractive(enabled: bool) -> None:
    _PREFS.noninteractive = bool(enabled)


def set_show_splits(enabled: bool) -> None:
    _PREFS.show_splits = bool(enabled)


def is_compact_mode() -> bool:
    return not _PREFS.verbose


def toggle_cleartext_only() -> bool:
    _PREFS.cleartext_only = not _PREFS.cleartext_only
    return _PREFS.cleartext_only


__all__ = [
    "get",
    "snapshot",
    "restore",
    "effective_quiet",
    "effective_batch",
    "effective_run_mode",
    "effective_noninteractive",
    "effective_show_splits",
    "set_verbose",
    "toggle_verbose",
    "set_analytics_detail",
    "toggle_analytics_detail",
    "set_string_max_samples",
    "set_cleartext_only",
    "toggle_cleartext_only",
    "set_quiet",
    "set_batch",
    "set_run_mode",
    "set_noninteractive",
    "set_show_splits",
    "is_compact_mode",
    "get_run_context",
    "set_run_context",
]
