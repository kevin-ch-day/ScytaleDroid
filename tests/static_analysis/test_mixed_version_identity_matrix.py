from __future__ import annotations

from scytaledroid.Database.db_func.harvest import install_sets
from scytaledroid.DynamicAnalysis.plans.db_lookup import fetch_static_run_row
from scytaledroid.DynamicAnalysis.plans.payload import extract_plan_identity
from scytaledroid.StaticAnalysis.cli.views.renderers.dynamic_plan import build_dynamic_plan
from scytaledroid.StaticAnalysis.core import (
    ComponentSummary,
    ManifestFlags,
    ManifestSummary,
    PermissionSummary,
    StaticAnalysisReport,
)
from scytaledroid.Utils.install_set_identity import V1, V2, compute_artifact_set_hash


def _members():
    return [
        {"role": "base", "split_name": None, "sha256": "a" * 64},
        {"role": "config", "split_name": "config.en", "sha256": "b" * 64},
    ]


def _report(*, version: str, digest: str, apk_set_id: int = 44) -> StaticAnalysisReport:
    return StaticAnalysisReport(
        file_path="/tmp/example.apk",
        relative_path="example.apk",
        file_name="example.apk",
        file_size=123,
        hashes={"sha256": "f" * 64},
        manifest=ManifestSummary(
            package_name="com.example.app", version_name="1.0", version_code="123"
        ),
        manifest_flags=ManifestFlags(),
        permissions=PermissionSummary(),
        components=ComponentSummary(),
        exported_components=ComponentSummary(),
        signatures=("aa" * 32,),
        metadata={
            "package": "com.example.app",
            "version_name": "1.0",
            "version_code": "123",
            "base_apk_sha256": "a" * 64,
            "artifact_set_hash": digest,
            "artifact_set_hash_version": version,
            "apk_set_id": apk_set_id,
            "run_signature": "c" * 64,
            "run_signature_version": "v1",
            "static_handoff_hash": "d" * 64,
            "identity_valid": True,
            "identity_error_reason": None,
        },
    )


def test_lookup_prefers_stored_v1_over_parallel_v2_digest(monkeypatch) -> None:
    members = _members()
    stored_v1 = compute_artifact_set_hash(members, version=V1)
    v2_hash = compute_artifact_set_hash(members, version=V2)

    def _run_sql(_sql, params=(), **_kwargs):
        assert stored_v1 in params or v2_hash in params
        return {
            "apk_set_id": 843,
            "artifact_set_hash": stored_v1,
            "artifact_set_hash_version": V1,
        }

    monkeypatch.setattr(install_sets, "run_sql", _run_sql)
    stored = install_sets.lookup_stored_install_set_identity(v1_hash=stored_v1, v2_hash=v2_hash)
    assert stored is not None
    assert stored["artifact_set_hash_version"] == V1
    assert stored["artifact_set_hash"] == stored_v1
    assert stored["apk_set_id"] == "843"


def test_v1_and_v2_handoff_and_plan_preserve_selected_identity() -> None:
    for version in (V1, V2):
        digest = compute_artifact_set_hash(_members(), version=version)
        plan = build_dynamic_plan(_report(version=version, digest=digest), {"baseline": {}})
        identity = plan["run_identity"]
        assert identity["artifact_set_hash_version"] == version
        assert identity["artifact_set_hash"] == digest
        extracted = extract_plan_identity(plan)
        assert extracted["artifact_set_hash_version"] == version
        assert extracted["artifact_set_hash"] == digest


def test_dynamic_session_row_keeps_unknown_when_plan_omits_version() -> None:
    extracted = extract_plan_identity({"package_name": "com.example.app", "run_identity": {}})
    assert extracted.get("artifact_set_hash_version") in {None, ""}


def test_local_apk_set_id_is_not_portable_identity() -> None:
    digest = compute_artifact_set_hash(_members(), version=V2)
    left = build_dynamic_plan(_report(version=V2, digest=digest, apk_set_id=1), {"baseline": {}})
    right = build_dynamic_plan(_report(version=V2, digest=digest, apk_set_id=9999), {"baseline": {}})
    assert left["run_identity"]["artifact_set_hash"] == right["run_identity"]["artifact_set_hash"]
    assert left["run_identity"]["artifact_set_hash_version"] == V2


def test_same_base_sha_different_split_sets_are_distinct() -> None:
    left = _members()
    right = [
        {"role": "base", "split_name": None, "sha256": "a" * 64},
        {"role": "config", "split_name": "config.fr", "sha256": "c" * 64},
    ]
    assert compute_artifact_set_hash(left, version=V2) != compute_artifact_set_hash(right, version=V2)


def test_static_run_lookup_prefers_sar_stored_version(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _run_sql(query, _params=(), **_kwargs):
        captured["query"] = query
        return {
            "static_run_id": 7343,
            "artifact_set_hash": "b" * 64,
            "artifact_set_hash_version": "v1",
        }

    monkeypatch.setattr(
        "scytaledroid.DynamicAnalysis.plans.db_lookup.core_q.run_sql",
        _run_sql,
    )
    row = fetch_static_run_row(7343)
    assert "COALESCE" in str(captured["query"])
    assert "sar.artifact_set_hash_version" in str(captured["query"])
    assert row["artifact_set_hash_version"] == "v1"
