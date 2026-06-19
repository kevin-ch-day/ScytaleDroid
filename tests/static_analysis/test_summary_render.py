from scytaledroid.StaticAnalysis.cli.views.renderers.summary_render import render_app_result
from scytaledroid.StaticAnalysis.core.models import (
    ManifestFlags,
    ManifestSummary,
    StaticAnalysisReport,
)


def test_render_app_result_orders_known_hashes_without_name_error() -> None:
    report = StaticAnalysisReport(
        file_path="/tmp/app.apk",
        relative_path=None,
        file_name="app.apk",
        file_size=123,
        hashes={
            "sha256": "c" * 64,
            "md5": "a" * 32,
            "sha1": "b" * 40,
        },
        manifest=ManifestSummary(
            package_name="com.example.app",
            version_name="1.0",
            version_code="1",
            min_sdk="23",
            target_sdk="35",
        ),
    )

    lines, payload, finding_totals = render_app_result(
        report,
        signer=None,
        split_count=1,
        string_data={"counts": {}},
        duration_seconds=0.1,
    )

    assert "  MD5     : " + "a" * 32 in lines
    assert "  SHA-1   : " + "b" * 40 in lines
    assert "  SHA-256 : " + "c" * 64 in lines
    assert list(payload["app"]["hashes"]) == ["md5", "sha1", "sha256"]
    assert not finding_totals


def test_render_app_result_orders_baseline_findings_by_severity() -> None:
    report = StaticAnalysisReport(
        file_path="/tmp/app.apk",
        relative_path=None,
        file_name="app.apk",
        file_size=123,
        hashes={},
        manifest=ManifestSummary(
            package_name="com.example.app",
            version_name="1.0",
            version_code="1",
            min_sdk="23",
            target_sdk="35",
        ),
        manifest_flags=ManifestFlags(
            debuggable=True,
            allow_backup=True,
        ),
    )

    lines, _payload, finding_totals = render_app_result(
        report,
        signer=None,
        split_count=1,
        string_data={"counts": {}},
        duration_seconds=0.1,
    )

    medium_index = lines.index("  M BASE-001  android:debuggable enabled")
    low_index = lines.index("  L BASE-001  allowBackup is enabled")
    assert medium_index < low_index
    assert finding_totals["Medium"] == 1
    assert finding_totals["Low"] == 1


def test_render_app_result_preserves_string_enrichment_metadata_in_payload() -> None:
    report = StaticAnalysisReport(
        file_path="/tmp/app.apk",
        relative_path=None,
        file_name="app.apk",
        file_size=123,
        hashes={},
        manifest=ManifestSummary(
            package_name="com.example.app",
            version_name="1.0",
            version_code="1",
            min_sdk="23",
            target_sdk="35",
        ),
    )

    string_data = {
        "counts": {"api_keys": 1},
        "samples": {
            "api_keys": [
                {
                    "value": "AIzaSyExampleSecretValue",
                    "value_masked": "AIzaSyEx…",
                    "src": "classes.dex",
                    "root_domain": "example.com",
                    "source_type": "dex",
                    "api_context": "auth_flow",
                    "posture": "actionable",
                    "ownership_class": "third_party",
                    "pair_group": "google:token_endpoint_family",
                    "verification_status": "supported_opt_in",
                    "xref_context": "SecretKeySpec init",
                    "dynamic_corroboration": "unknown",
                }
            ]
        },
        "selected_samples": {},
    }

    _lines, payload, _finding_totals = render_app_result(
        report,
        signer=None,
        split_count=1,
        string_data=string_data,
        duration_seconds=0.1,
    )

    sample = payload["baseline"]["string_analysis"]["samples"]["api_keys"][0]

    assert sample["api_context"] == "auth_flow"
    assert sample["posture"] == "actionable"
    assert sample["ownership_class"] == "third_party"
    assert sample["pair_group"] == "google:token_endpoint_family"
    assert sample["verification_status"] == "supported_opt_in"
    assert sample["xref_context"] == "SecretKeySpec init"
    assert sample["dynamic_corroboration"] == "unknown"
