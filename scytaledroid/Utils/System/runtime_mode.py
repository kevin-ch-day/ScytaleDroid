"""Global runtime mode resolution for ScytaleDroid."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _clean(value: str | None, *, default: str = "") -> str:
    cleaned = str(value or "").strip()
    return cleaned or default


def _env_bool(value: str | None, default: bool = False) -> bool:
    raw = str(value or "").strip().lower()
    if not raw:
        return bool(default)
    return raw in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class RuntimeMode:
    debug_mode: bool
    sys_test: bool
    execution_mode: str
    sys_env: str
    preset: str

    @property
    def show_runtime_identity(self) -> bool:
        return bool(self.debug_mode or self.execution_mode == "DEV")


_PRESET_DEFAULTS: dict[str, dict[str, object]] = {
    "physical": {
        "debug_mode": False,
        "sys_test": False,
        "execution_mode": "PROD",
        "sys_env": "PHYSICAL",
    },
    "virtual": {
        "debug_mode": True,
        "sys_test": False,
        "execution_mode": "DEV",
        "sys_env": "VIRTUAL",
    },
    "validation": {
        "debug_mode": True,
        "sys_test": True,
        "execution_mode": "DEV",
        "sys_env": "VIRTUAL",
    },
}


def resolve_runtime_mode() -> RuntimeMode:
    preset = _clean(os.getenv("SCYTALEDROID_RUNTIME_PRESET", "physical"), default="physical").lower()
    defaults = _PRESET_DEFAULTS.get(preset, _PRESET_DEFAULTS["physical"])

    debug_mode = _env_bool(
        os.getenv("SCYTALEDROID_DEBUG_MODE"),
        bool(defaults["debug_mode"]),
    )
    sys_test = _env_bool(
        os.getenv("SCYTALEDROID_SYS_TEST"),
        bool(defaults["sys_test"]),
    )

    execution_mode = _clean(
        os.getenv("SCYTALEDROID_EXECUTION_MODE", str(defaults["execution_mode"])),
        default=str(defaults["execution_mode"]),
    ).upper()
    if execution_mode not in {"DEV", "PROD"}:
        execution_mode = str(defaults["execution_mode"])

    sys_env = _clean(
        os.getenv("SCYTALEDROID_SYS_ENV", str(defaults["sys_env"])),
        default=str(defaults["sys_env"]),
    ).upper()
    if sys_env not in {"PHYSICAL", "VIRTUAL"}:
        sys_env = str(defaults["sys_env"])

    return RuntimeMode(
        debug_mode=debug_mode,
        sys_test=sys_test,
        execution_mode=execution_mode,
        sys_env=sys_env,
        preset=preset,
    )


__all__ = ["RuntimeMode", "resolve_runtime_mode"]
