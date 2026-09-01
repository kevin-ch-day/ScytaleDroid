"""Lightweight argument parser for the headless static-analysis command."""

from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    """Build the headless-run parser without importing the analysis runtime."""

    parser = argparse.ArgumentParser(description="Headless static analysis runner")
    parser.add_argument("--apk", help="Path to APK file")
    parser.add_argument("--apk-id", help="android_apk_repository.apk_id for exact-hash static analysis")
    parser.add_argument(
        "--base-apk-sha256",
        "--exact-hash",
        dest="base_apk_sha256",
        help="Exact base APK SHA-256 to analyze",
    )
    parser.add_argument(
        "--include-splits",
        default="auto",
        choices=["auto", "base-only", "require"],
        help="Exact target split handling: auto uses receipt-backed group; base-only must be explicit.",
    )
    parser.add_argument(
        "--research-cohort-key",
        help="Run a deterministic DB-backed research cohort headlessly.",
    )
    parser.add_argument("--session", help="Session stamp (defaults to generated)")
    parser.add_argument("--scope-label", help="Scope label (defaults to package name)")
    parser.add_argument(
        "--profile",
        default="full",
        choices=["full", "permissions", "metadata", "lightweight", "split"],
        help="Static analysis profile",
    )
    parser.add_argument("--dry-run", action="store_true", help="Run analysis without database persistence")
    parser.add_argument(
        "--allow-session-reuse",
        action="store_true",
        help="Permit reusing an existing session stamp",
    )
    return parser
