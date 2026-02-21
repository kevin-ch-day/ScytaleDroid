from __future__ import annotations

import re

import pytest

import main as app_main
from scytaledroid.Database.db_core import db_queries as core_q
from scytaledroid.Database.db_core import db_config
from scytaledroid.Database.db_utils import diagnostics
from scytaledroid.StaticAnalysis.cli.persistence.static_handoff import build_static_handoff
from scytaledroid.StaticAnalysis.core import (
    ManifestFlags,
    ManifestSummary,
    PermissionSummary,
    StaticAnalysisReport,
)
from scytaledroid.Database.db_queries import schema_manifest
from scytaledroid.Database.db_func.static_analysis import string_analysis
from scytaledroid.StaticAnalysis.cli.flows import headless_run
from scytaledroid.StaticAnalysis.cli.menus import actions
from scytaledroid.StaticAnalysis.cli.persistence import run_writers


def _require_db_or_skip() -> None:
    if not diagnostics.check_connection():
        pytest.skip("DB not reachable for integration gate check")


def _db_engine() -> str:
    return str(db_config.DB_CONFIG.get("engine", "sqlite")).strip().lower()


def _require_mysql_or_skip() -> None:
    if _db_engine() != "mysql":
        pytest.skip("Static contract schema/view gate is defined for canonical MySQL backend")


def _sample_report() -> StaticAnalysisReport:
    return StaticAnalysisReport(
        file_path="/tmp/app.apk",
        relative_path=None,
        file_name="app.apk",
        file_size=1,
        hashes={"sha256": "b" * 64},
        manifest=ManifestSummary(package_name="com.example.app", version_code="123"),
        manifest_flags=ManifestFlags(
            uses_cleartext_traffic=True,
            allow_backup=True,
            request_legacy_external_storage=False,
            network_security_config="@xml/network_security_config",
        ),
        permissions=PermissionSummary(
            declared=(
                "android.permission.INTERNET",
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION",
            ),
            dangerous=(
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION",
            ),
        ),
        detector_metrics={
            "ipc_components": {"exported_without_permission": 3},
            "provider_acl": {"without_permissions": 2},
            "storage_surface": {"fileproviders": 1},
            "network_surface": {"cleartext_permitted": True, "cleartext_domain_count": 2},
        },
        analysis_matrices={"severity_by_category": {"NETWORK": {"High": 1}}},
    )


def test_reset_default_session_scoped(monkeypatch):
    captured: dict[str, object] = {}

    def _choice(valid, default="1", prompt="Choice: "):
        captured["valid"] = list(valid)
        return "1"

    monkeypatch.setattr(actions.prompt_utils, "get_choice", _choice)
    assert actions.confirm_reset() == "session"
    assert captured["valid"] == ["1", "0"]


def test_truncate_not_accessible_in_normal_menu_or_requires_token():
    with pytest.raises(SystemExit):
        app_main.main(["db", "--truncate-static"])


def test_schema_has_static_contract_columns():
    _require_db_or_skip()
    _require_mysql_or_skip()
    columns = set(diagnostics.get_table_columns("static_analysis_runs") or [])
    required = {
        "identity_mode",
        "identity_conflict_flag",
        "static_handoff_hash",
        "static_handoff_json_path",
        "masvs_mapping_hash",
        "run_class",
        "non_canonical_reasons",
    }
    missing = sorted(required - columns)
    assert not missing, f"Missing static contract columns: {missing}"


def test_view_v_static_handoff_v1_exists():
    _require_db_or_skip()
    _require_mysql_or_skip()
    row = core_q.run_sql(
        """
        SELECT COUNT(*)
        FROM information_schema.views
        WHERE table_schema=DATABASE()
          AND table_name='v_static_handoff_v1'
        """,
        fetch="one",
    )
    assert row and int(row[0] or 0) == 1


def test_schema_manifest_contains_handoff_view():
    statements = schema_manifest.ordered_schema_statements()
    assert any("CREATE OR REPLACE VIEW v_static_handoff_v1" in stmt for stmt in statements)


def test_identity_conflict_blocks_canonical(monkeypatch):
    captured: dict[str, object] = {}
    monkeypatch.setattr(run_writers, "_ensure_app_version", lambda **_k: 1)
    monkeypatch.setattr(run_writers, "_identity_mode", lambda **_k: "full_hash")
    monkeypatch.setattr(run_writers, "_detect_identity_conflict", lambda **_k: True)
    monkeypatch.setattr(run_writers, "_update_static_run_metadata", lambda **_k: None)
    monkeypatch.setattr(run_writers.core_q, "run_sql", lambda *_a, **_k: None)
    monkeypatch.setattr(
        run_writers,
        "_maybe_set_canonical_static_run",
        lambda **_k: (_ for _ in ()).throw(AssertionError("must not set canonical")),
    )

    def _capture(**kwargs):
        captured.update(kwargs)
        return 7

    monkeypatch.setattr(run_writers, "_create_static_run", _capture)
    run_writers.create_static_run_ledger(
        package_name="com.example.app",
        display_name="Example",
        version_name="1.0",
        version_code=1,
        min_sdk=24,
        target_sdk=34,
        session_stamp="s1",
        session_label="s1",
        scope_label="scope",
        category="cat",
        profile="full",
        profile_key="full",
        scenario_id="static_default",
        device_serial=None,
        tool_semver="2.0.1",
        tool_git_commit="deadbeef",
        schema_version="0.2.6",
        findings_total=0,
        run_started_utc="2026-02-20 00:00:00",
        status="STARTED",
        is_canonical=True,
        canonical_set_at_utc="2026-02-20 00:00:00",
        canonical_reason="replace",
        base_apk_sha256="a" * 64,
    )
    assert captured["is_canonical"] is False
    assert captured["identity_conflict_flag"] is True


def test_masvs_mapping_hash_non_null_and_stable():
    payload_1 = build_static_handoff(
        report=_sample_report(),
        string_data={},
        package_name="com.example.app",
        version_code=123,
        base_apk_sha256="a" * 64,
        artifact_set_hash="c" * 64,
        static_run_id=9,
        session_label="20260220",
        tool_semver="2.0.1",
        tool_git_commit="deadbeef",
        schema_version="0.2.6",
    )
    payload_2 = build_static_handoff(
        report=_sample_report(),
        string_data={},
        package_name="com.example.app",
        version_code=123,
        base_apk_sha256="a" * 64,
        artifact_set_hash="c" * 64,
        static_run_id=9,
        session_label="20260220",
        tool_semver="2.0.1",
        tool_git_commit="deadbeef",
        schema_version="0.2.6",
    )
    h1 = payload_1["masvs"]["masvs_mapping_hash"]
    h2 = payload_2["masvs"]["masvs_mapping_hash"]
    assert h1
    assert h1 == h2


def test_secret_buckets_mask_raw_values():
    masked, digest = string_analysis._safe_masked_value_and_hash("api_keys", {"value": "AKIA_TEST_SECRET"})
    assert masked == "[REDACTED]"
    assert digest


def test_secret_redaction_no_raw_secret_leak_db_scan():
    _require_db_or_skip()
    candidates: list[tuple[str, str]] = [
        ("static_string_samples", "value_masked"),
        ("static_string_selected_samples", "value_masked"),
        ("static_findings", "evidence"),
        ("doc_hosts", "host"),
    ]
    jwt_like = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
    aws_key_like = re.compile(r"AKIA[0-9A-Z]{16}")
    bad_tokens: list[str] = []

    for table, column in candidates:
        cols = diagnostics.get_table_columns(table) or []
        if column not in cols:
            continue
        rows = core_q.run_sql(
            f"SELECT `{column}` FROM `{table}` WHERE `{column}` IS NOT NULL LIMIT 5000",
            fetch="all",
        ) or []
        for row in rows:
            value = str(row[0] or "")
            if not value:
                continue
            if aws_key_like.search(value) or jwt_like.search(value):
                bad_tokens.append(f"{table}.{column}")
                break

    assert not bad_tokens, f"Raw secret-like tokens found in DB fields: {sorted(set(bad_tokens))}"


def test_headless_dataset_mode_requires_session():
    with pytest.raises(SystemExit):
        headless_run.main(["--profile-key", "research_dataset_alpha"])
