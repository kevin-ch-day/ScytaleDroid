from __future__ import annotations

from scytaledroid.StaticAnalysis.core.pipeline import (
    _build_parser_provenance,
    _resolve_toolchain_versions,
)


def test_resolve_toolchain_versions_returns_independent_dicts() -> None:
    a = _resolve_toolchain_versions()
    b = _resolve_toolchain_versions()
    assert isinstance(a, dict)
    assert a == b
    assert a is not b
    a["androguard"] = "mutated"
    assert b["androguard"] != "mutated"


def test_build_parser_provenance_tracks_fallback_sources() -> None:
    provenance = _build_parser_provenance(  # noqa: SLF001 - targeted contract test
        {
            "manifest_source": "androguard",
            "manifest_semantics_source": "androguard",
            "label_fallback": "aapt2",
            "resource_fallback": {
                "fallback_used": True,
                "fallback_reason": "androguard_open_failed",
                "aapt2_available": True,
                "warning_count": 2,
            },
            "resource_bounds_warnings": ["w1", "w2"],
            "string_index_error": "index unavailable",
        }
    )

    assert provenance["manifest_source"] == "androguard"
    assert provenance["resource_open_source"] == "aapt2_metadata_fallback"
    assert provenance["resource_fallback_used"] is True
    assert provenance["resource_fallback_reason"] == "androguard_open_failed"
    assert provenance["resource_bounds_warning_count"] == 2
    assert provenance["resource_bounds_warning_severity"] == "warn"
    assert provenance["resource_bounds_warning_kind"] == "mixed_or_large"
    assert provenance["resource_parse_state"] == "partial"
    assert provenance["resource_parse_partial"] is True
    assert provenance["resource_reparse_candidate"] is True
    assert provenance["label_source"] == "aapt2"
    assert provenance["string_index_source"] == "string_index_unavailable"
    assert provenance["aapt2_available"] is True


def test_build_parser_provenance_marks_minor_complex_entry_bounds_note() -> None:
    provenance = _build_parser_provenance(  # noqa: SLF001 - targeted contract test
        {
            "resource_bounds_warnings": ["We are out of bound with this complex entry. Count: 262"],
        }
    )

    assert provenance["resource_bounds_warning_count"] == 1
    assert provenance["resource_bounds_warning_severity"] == "minor"
    assert provenance["resource_bounds_warning_kind"] == "complex_entry_minor"
    assert provenance["resource_parse_state"] == "minor"
    assert provenance["resource_parse_partial"] is False
    assert provenance["resource_reparse_candidate"] is False
