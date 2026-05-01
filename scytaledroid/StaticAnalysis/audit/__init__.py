"""Static analysis audit helpers (log tail scan, persistence JSON summary)."""

from __future__ import annotations

from .run_log_audit import emit_static_audit_report

__all__ = ["emit_static_audit_report"]
