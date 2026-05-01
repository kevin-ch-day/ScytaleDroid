"""Shared PEP 562 ``__getattr__`` helpers for lightweight package facades."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from importlib import import_module


def lazy_getattr(
    package_qualname: str,
    exports: Mapping[str, tuple[str, str]],
    module_globals: MutableMapping[str, object],
    name: str,
) -> object:
    """Resolve ``name`` from a relative submodule and cache it on ``module_globals``."""

    if name not in exports:
        raise AttributeError(f"module {package_qualname!r} has no attribute {name!r}")
    mod_rel, attr = exports[name]
    module = import_module(mod_rel, package_qualname)
    value = getattr(module, attr)
    module_globals[name] = value
    return value
