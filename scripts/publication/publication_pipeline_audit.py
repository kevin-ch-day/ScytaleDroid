#!/usr/bin/env python3
"""Thin wrapper for frozen-archive pipeline audits."""

from __future__ import annotations

from _service_wrapper import run_service_wrapper


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(
        run_service_wrapper(
            __file__,
            service_module="scytaledroid.Reporting.services.publication_pipeline_audit_service",
            help_summary="Generate frozen-archive publication pipeline audit.",
        )
    )
