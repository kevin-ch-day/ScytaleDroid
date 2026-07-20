from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def _load_script_module():
    path = Path("scripts/reporting/generate_static_exposure_privacy_report.py").resolve()
    spec = importlib.util.spec_from_file_location("generate_static_exposure_privacy_report_cli", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_report_cli_help_uses_report_mode_not_output_contract(capsys) -> None:
    module = _load_script_module()
    parser = module._parser()

    with capsys.disabled():
        help_text = parser.format_help()

    assert "--report-mode" in help_text
    assert "--include-tex" in help_text
    assert "--output-contract" not in help_text
    assert "research_dataset" in help_text
    assert "all_apps" in help_text
    assert "saved_custom_scope" not in help_text
    assert "--saved-scope" not in help_text
    assert "static_social_media_2025" not in help_text
    assert "selected_manifest" in help_text
    assert "selected_publication_manifest" not in help_text
    assert "publication_candidate" not in help_text
    assert "frozen" not in help_text


def test_report_mode_maps_to_internal_compatibility_contract() -> None:
    module = _load_script_module()
    parser = module._parser()

    assert module._output_contract_for_args(parser.parse_args(["--scope-type", "single_app", "--package", "example.app", "--evidence-basis-type", "latest_valid_as_of", "--evidence-basis-key", "latest"])) == "publication_candidate"
    assert module._output_contract_for_args(parser.parse_args(["--scope-type", "single_app", "--package", "example.app", "--evidence-basis-type", "latest_valid_as_of", "--evidence-basis-key", "latest", "--report-mode", "exploratory"])) == "exploratory"
    assert module._output_contract_for_args(parser.parse_args(["--scope-type", "single_app", "--package", "example.app", "--evidence-basis-type", "latest_valid_as_of", "--evidence-basis-key", "latest", "--report-mode", "archive"])) == "frozen"


def test_evidence_basis_aliases_keep_legacy_values_compatible() -> None:
    module = _load_script_module()

    assert module._normalize_evidence_basis_type("exact_manifest") == "exact_historical_freeze"
    assert module._normalize_evidence_basis_type("selected_manifest") == "selected_publication_manifest"
    assert module._normalize_evidence_basis_type("selected_publication_manifest") == "selected_publication_manifest"


def test_scope_type_aliases_keep_legacy_values_compatible() -> None:
    module = _load_script_module()

    assert module._normalize_scope_type("research_dataset") == "research_cohort"
    assert module._normalize_scope_type("category") == "application_category"
    assert module._normalize_scope_type("all_apps") == "all_eligible_apps"
    assert module._normalize_scope_type("saved_custom_scope") == "saved_custom_scope"


def test_fixed_recent_window_defaults_to_last_30_days(monkeypatch) -> None:
    module = _load_script_module()
    monkeypatch.setattr(module, "default_as_of_now", lambda: "2026-07-11T03:00:00+00:00")
    parser = module._parser()

    request = module._build_request(
        parser.parse_args(
            [
                "--scope-type",
                "single_app",
                "--package",
                "example.app",
                "--evidence-basis-type",
                "fixed_recent_window",
                "--evidence-basis-key",
                "current_static_evidence_30d",
            ]
        )
    )

    assert request.window_start_utc == "2026-06-11T03:00:00+00:00"
    assert request.window_end_utc == "2026-07-11T03:00:00+00:00"


def test_single_app_cli_resolves_display_name(monkeypatch) -> None:
    module = _load_script_module()
    monkeypatch.setattr(module, "default_as_of_now", lambda: "2026-07-11T03:00:00+00:00")
    monkeypatch.setattr(
        module,
        "find_static_application_matches",
        lambda query, limit=5: [
            {
                "package_name": "com.pinterest",
                "display_name": "Pinterest",
                "app_category": "Social",
            }
        ],
    )
    parser = module._parser()

    request = module._build_request(
        parser.parse_args(
            [
                "--scope-type",
                "single_app",
                "--package",
                "Pinterest",
                "--evidence-basis-type",
                "fixed_recent_window",
                "--evidence-basis-key",
                "current_static_evidence_30d",
            ]
        )
    )

    assert request.scope_key == "com.pinterest"
    assert request.scope_label == "Pinterest"
    assert request.package_names == ["com.pinterest"]


def test_single_app_cli_blocks_unknown_display_name(monkeypatch) -> None:
    module = _load_script_module()
    monkeypatch.setattr(module, "find_static_application_matches", lambda query, limit=5: [])
    parser = module._parser()

    with pytest.raises(SystemExit, match="No app named"):
        module._build_request(
            parser.parse_args(
                [
                    "--scope-type",
                    "single_app",
                    "--package",
                    "Not A Package",
                    "--evidence-basis-type",
                    "fixed_recent_window",
                    "--evidence-basis-key",
                    "current_static_evidence_30d",
                ]
            )
        )
