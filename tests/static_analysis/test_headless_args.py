"""Contracts for the dependency-light headless static parser."""

from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.flows.headless_args import build_parser


def test_headless_parser_preserves_single_apk_defaults() -> None:
    args = build_parser().parse_args(["--apk", "/tmp/example.apk"])

    assert args.apk == "/tmp/example.apk"
    assert args.profile == "full"
    assert args.include_splits == "auto"
    assert args.dry_run is False
    assert args.allow_session_reuse is False


def test_headless_parser_preserves_exact_hash_alias() -> None:
    args = build_parser().parse_args(["--exact-hash", "a" * 64])

    assert args.base_apk_sha256 == "a" * 64
