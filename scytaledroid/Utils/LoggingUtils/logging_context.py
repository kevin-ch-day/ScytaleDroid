"""Shared logging context helpers to enforce consistent structured logs."""

from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass

from . import logging_engine


@dataclass(frozen=True)
class RunContext:
    subsystem: str  # inventory | harvest | static | db
    device_serial: str | None
    device_model: str | None
    run_id: str
    scope: str | None = None
    profile: str | None = None

    def to_extra(self) -> MutableMapping[str, object]:
        return {
            "subsystem": self.subsystem,
            "device_serial": self.device_serial,
            "device_model": self.device_model,
            "run_id": self.run_id,
            "scope": self.scope,
            "profile": self.profile,
        }


def get_run_logger(category: str, ctx: RunContext) -> logging_engine.ContextAdapter:
    """Return a logger adapter for ``category`` bound to the run context."""

    base = logging_engine.get_logger(category)
    extra = logging_engine.ensure_trace(ctx.to_extra())
    return logging_engine.ContextAdapter(base, extra)

