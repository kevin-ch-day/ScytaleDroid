#!/usr/bin/env python3
"""Wrapper for Profile v3 integrity gates."""

from __future__ import annotations

from _service_wrapper import run_service_wrapper


if __name__ == "__main__":
    raise SystemExit(
        run_service_wrapper(
            __file__,
            service_module="scytaledroid.Reporting.services.profile_v3_integrity_gates_service",
            help_summary="Run Profile v3 integrity gates.",
        )
    )
