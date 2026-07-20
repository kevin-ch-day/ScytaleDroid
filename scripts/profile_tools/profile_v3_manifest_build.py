#!/usr/bin/env python3
"""Wrapper for Profile v3 manifest build."""

from __future__ import annotations

from _service_wrapper import run_service_wrapper

if __name__ == "__main__":
    raise SystemExit(
        run_service_wrapper(
            __file__,
            service_module="scytaledroid.DynamicAnalysis.services.profile_v3_manifest_build_service",
            help_summary="Build a Profile v3 manifest.",
        )
    )
