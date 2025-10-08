#!/usr/bin/env python3
"""
Runtime sanity check for StaticAnalysis imports.

- The canonical shim is scytaledroid.StaticAnalysis._androguard
- There must NOT be a shim module under scytaledroid.StaticAnalysis.core
"""
from __future__ import annotations
import sys
import pathlib
import importlib.util as u

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

def main() -> int:
    # 1) Canonical shim path must resolve
    top_spec = u.find_spec("scytaledroid.StaticAnalysis._androguard")
    if top_spec is None:
        print("[ERROR] Could not resolve scytaledroid.StaticAnalysis._androguard")
        return 1

    # 2) No ghost shim under core/
    core_spec = u.find_spec("scytaledroid.StaticAnalysis.core._androguard")
    if core_spec is not None:
        print("[ERROR] Found unexpected module at core/_androguard:", core_spec.origin)
        return 2

    # 3) Import shim symbols and pipeline together
    try:
        from scytaledroid.StaticAnalysis._androguard import APK  # type: ignore
    except Exception as e:  # pragma: no cover - diagnostics only
        print("[ERROR] Failed importing APK from shim:", repr(e))
        return 3

    try:
        import scytaledroid.StaticAnalysis.core.pipeline as pipeline  # type: ignore  # noqa: F401
    except Exception as e:  # pragma: no cover - diagnostics only
        print("[ERROR] Failed importing pipeline:", repr(e))
        return 4

    # 4) Light touch: ensure symbol exists and is a class/type-like
    if not hasattr(APK, "__name__"):
        print("[ERROR] APK symbol does not look like a class:", type(APK))
        return 5

    print("[OK] Shim & pipeline imports look good.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
