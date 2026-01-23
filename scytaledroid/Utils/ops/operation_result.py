"""Lightweight operation result contract for critical workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, MutableMapping, Optional


@dataclass(slots=True)
class OperationResult:
    ok: bool
    status: str
    user_message: str = ""
    log_hint: str = ""
    error_code: str = ""
    context: MutableMapping[str, object] = field(default_factory=dict)

    @classmethod
    def success(
        cls,
        *,
        status: str = "OK",
        user_message: str = "",
        context: Optional[Mapping[str, object]] = None,
    ) -> "OperationResult":
        return cls(
            ok=True,
            status=status,
            user_message=user_message,
            context=dict(context or {}),
        )

    @classmethod
    def failure(
        cls,
        *,
        status: str = "FAILED",
        user_message: str,
        log_hint: str = "See logs for traceback.",
        error_code: str = "",
        context: Optional[Mapping[str, object]] = None,
    ) -> "OperationResult":
        return cls(
            ok=False,
            status=status,
            user_message=user_message,
            log_hint=log_hint,
            error_code=error_code,
            context=dict(context or {}),
        )

    @classmethod
    def partial(
        cls,
        *,
        user_message: str,
        log_hint: str = "See logs for traceback.",
        error_code: str = "",
        context: Optional[Mapping[str, object]] = None,
    ) -> "OperationResult":
        return cls.failure(
            status="PARTIAL",
            user_message=user_message,
            log_hint=log_hint,
            error_code=error_code,
            context=context,
        )


__all__ = ["OperationResult"]
