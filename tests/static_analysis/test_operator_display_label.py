from __future__ import annotations

from types import SimpleNamespace

from scytaledroid.StaticAnalysis.cli.execution.operator_display_label import (
    build_operator_label_metadata_from_report,
    resolve_operator_app_label,
)


def test_build_operator_label_metadata_report_metadata_wins_over_manifest_for_app_label() -> None:
    report = SimpleNamespace(
        manifest=SimpleNamespace(app_label="From Manifest"),
        metadata={"app_label": "From Meta", "display_name": "Display X"},
    )
    meta = build_operator_label_metadata_from_report(report)
    assert meta["app_label"] == "From Meta"
    assert meta["display_name"] == "Display X"


def test_build_operator_label_metadata_from_report_manifest_when_no_metadata_keys() -> None:
    report = SimpleNamespace(
        manifest=SimpleNamespace(app_label="Manifest Only"),
        metadata={},
    )
    meta = build_operator_label_metadata_from_report(report)
    assert meta["app_label"] == "Manifest Only"


def test_resolve_operator_app_label_v3_over_metadata_and_db() -> None:
    pkg = "com.example.app"
    meta = {"app_label": "Harvest"}
    v3 = {pkg.lower(): "Catalog Title"}
    db = {pkg.lower(): "DB Name"}
    assert resolve_operator_app_label(pkg, meta, v3, db) == "Catalog Title"

    assert resolve_operator_app_label(pkg, meta, {}, db) == "Harvest"
    assert resolve_operator_app_label(pkg, {}, {}, db) == "DB Name"


def test_resolve_operator_app_label_curated_db_beats_package_shaped_harvest() -> None:
    """When harvest ``app_label`` is only the package id, ``apps.display_name`` wins."""

    pkg = "com.example.app"
    meta = {"app_label": pkg}
    db = {pkg.lower(): "Curated Store Title"}
    assert resolve_operator_app_label(pkg, meta, {}, db) == "Curated Store Title"
