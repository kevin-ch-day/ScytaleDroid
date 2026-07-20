#!/usr/bin/env python3
"""Wrapper for Profile v3 capture-status reporting."""

from __future__ import annotations

from _service_wrapper import run_service_wrapper

if __name__ == "__main__":
    raise SystemExit(
        run_service_wrapper(
            __file__,
            service_module="scytaledroid.DynamicAnalysis.services.profile_v3_capture_status_service",
            help_summary="Generate Profile v3 capture-status reporting.",
        )
    )
