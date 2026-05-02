"""Dynamic analysis package.

Keep package import lightweight.

Dynamic analysis has optional heavy dependencies (sklearn/scipy). Importing them at
package import time causes failures in environments where those deps are missing
or broken, even if the user is only using evidence-pack tools or menus.

We therefore provide lazy attribute access for the primary TUI entrypoints.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "DynamicAnalysisEngine",
    "DynamicEngineResult",
    "dynamic_analysis_menu",
    "run_dynamic_analysis",
    "run_dynamic_engine",
]


def __getattr__(name: str) -> Any:  # pragma: no cover - import-time shim
    if name == "dynamic_analysis_menu":
        from .menu import dynamic_analysis_menu as fn

        return fn
    if name == "run_dynamic_analysis":
        from .run_dynamic_analysis import run_dynamic_analysis as fn

        return fn
    if name in {"DynamicAnalysisEngine", "DynamicEngineResult", "run_dynamic_engine"}:
        from .engine import DynamicAnalysisEngine, DynamicEngineResult, run_dynamic_engine

        return {
            "DynamicAnalysisEngine": DynamicAnalysisEngine,
            "DynamicEngineResult": DynamicEngineResult,
            "run_dynamic_engine": run_dynamic_engine,
        }[name]
    raise AttributeError(name)

