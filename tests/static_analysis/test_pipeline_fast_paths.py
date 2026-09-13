from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree

from scytaledroid.StaticAnalysis.core import pipeline
from scytaledroid.StaticAnalysis.core.manifest_utils import (
    build_permission_occurrence_evidence,
)
from scytaledroid.StaticAnalysis.core.models import (
    ManifestFlags,
    PermissionSummary,
    StaticAnalysisReport,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.indexing.models import (
    IndexedString,
    StringIndex,
)


def test_resolve_hashes_for_analysis_reuses_trusted_canonical_metadata(
    monkeypatch,
    tmp_path: Path,
) -> None:
    apk_path = tmp_path / "trusted.apk"
    apk_path.write_bytes(b"trusted-apk")
    metadata = {
        "md5": "a" * 32,
        "sha1": "b" * 40,
        "sha256": "c" * 64,
        "file_size": apk_path.stat().st_size,
    }

    monkeypatch.setattr(
        pipeline.artifact_store,
        "canonical_apk_path",
        lambda _sha256: apk_path,
    )

    def _unexpected_compute(_path: Path) -> dict[str, str]:
        raise AssertionError("compute_hashes should not be called for trusted canonical metadata")

    monkeypatch.setattr(pipeline, "compute_hashes", _unexpected_compute)

    hashes, meta = pipeline._resolve_hashes_for_analysis(apk_path, metadata)

    assert hashes == {
        "md5": "a" * 32,
        "sha1": "b" * 40,
        "sha256": "c" * 64,
    }
    assert meta["hash_source"] == "trusted_metadata"
    assert meta["hash_recomputed"] is False
    assert meta["hash_provenance_ok"] is True
    assert meta["hash_provenance_reason"] == "canonical_store_verified"


def test_manifest_permission_occurrence_export_separates_requests_and_definitions() -> None:
    manifest = ElementTree.fromstring(
        b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android">
          <uses-permission android:name="android.permission.CAMERA"/>
          <uses-permission-sdk-23 android:name="android.permission.POST_NOTIFICATIONS"/>
          <permission android:name="com.example.permission.PRIVATE"
                      android:protectionLevel="signature|privileged"/>
        </manifest>"""
    )
    records = build_permission_occurrence_evidence(
        manifest,
        artifact_sha256="a" * 64,
        package_name="com.example.app",
        analysis_run_id="run-example",
        producer_version="test",
        observed_at_utc="2026-09-13T12:30:45Z",
    )

    assert [record["occurrence_role"] for record in records] == [
        "MANIFEST_USES_PERMISSION",
        "MANIFEST_USES_PERMISSION_SDK_23",
        "MANIFEST_PERMISSION_DEFINITION",
    ]
    assert records[0]["semantic_claim"] == "PERMISSION_REQUEST"
    assert records[2]["semantic_claim"] == "PERMISSION_DEFINITION"
    assert records[2]["protection_evidence"] == {
        "source_kind": "MANIFEST_PROTECTION_LEVEL_ATTRIBUTE",
        "raw_value": "signature|privileged",
    }
    assert all(record["authority"]["database_mutation_authorized"] is False for record in records)
    assert all(record["identity"]["projected_pi_token"] is None for record in records)
    assert len({record["occurrence_evidence_digest"] for record in records}) == 3

    report = StaticAnalysisReport(
        file_path="/tmp/example.apk",
        relative_path=None,
        file_name="example.apk",
        file_size=1,
        hashes={"sha256": "a" * 64},
        permissions=PermissionSummary(occurrence_evidence=records),
    )
    restored = StaticAnalysisReport.from_dict(report.to_dict())
    assert restored.permissions.occurrence_evidence == records


def test_static_report_loader_tolerates_invalid_permission_sections() -> None:
    report = StaticAnalysisReport(
        file_path="/tmp/example.apk",
        relative_path=None,
        file_name="example.apk",
        file_size=1,
        hashes={"sha256": "a" * 64},
    )

    for invalid_permissions in (None, "invalid", []):
        payload = report.to_dict()
        payload["permissions"] = invalid_permissions
        restored = StaticAnalysisReport.from_dict(payload)
        assert restored.permissions == PermissionSummary()

    payload = report.to_dict()
    payload["permissions"] = {
        "declared": None,
        "dangerous": "android.permission.CAMERA",
        "custom": 42,
    }
    restored = StaticAnalysisReport.from_dict(payload)
    assert restored.permissions == PermissionSummary()


def test_static_report_loader_tolerates_invalid_optional_collections() -> None:
    report = StaticAnalysisReport(
        file_path="/tmp/example.apk",
        relative_path=None,
        file_name="example.apk",
        file_size=1,
        hashes={"sha256": "a" * 64},
    )
    payload = report.to_dict()
    payload.update(
        {
            "hashes": None,
            "components": None,
            "exported_components": "invalid",
            "features": None,
            "libraries": "invalid",
            "signatures": 42,
        }
    )

    restored = StaticAnalysisReport.from_dict(payload)

    assert restored.hashes == {}
    assert restored.components.total() == 0
    assert restored.exported_components.total() == 0
    assert restored.features == ()
    assert restored.libraries == ()
    assert restored.signatures == ()


def test_manifest_permission_occurrence_export_preserves_access_control_roles() -> None:
    manifest = ElementTree.fromstring(
        b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android">
          <application android:permission="com.example.permission.APP_DEFAULT">
            <service android:name=".SyncService"
                     android:permission="com.example.permission.SERVICE"/>
            <provider android:name=".DocumentsProvider"
                      android:authorities="com.example.documents"
                      android:permission="com.example.permission.PROVIDER"
                      android:readPermission="com.example.permission.READ"
                      android:writePermission="com.example.permission.WRITE">
              <path-permission android:pathPrefix="/private"
                               android:readPermission="com.example.permission.PATH_READ"
                               android:writePermission="com.example.permission.PATH_WRITE"/>
            </provider>
          </application>
        </manifest>"""
    )

    records = build_permission_occurrence_evidence(
        manifest,
        artifact_sha256="b" * 64,
        package_name="com.example.app",
        analysis_run_id="run-guards",
        producer_version="test",
        observed_at_utc="2026-09-13T12:30:45Z",
    )

    component_records = [
        record for record in records if record["occurrence_role"] == "MANIFEST_COMPONENT_GUARD"
    ]
    path_records = [
        record
        for record in records
        if record["occurrence_role"] == "MANIFEST_PATH_PERMISSION_GUARD"
    ]
    assert [record["identity"]["raw_token"] for record in component_records] == [
        "com.example.permission.APP_DEFAULT",
        "com.example.permission.SERVICE",
        "com.example.permission.PROVIDER",
        "com.example.permission.READ",
        "com.example.permission.WRITE",
    ]
    assert [record["identity"]["raw_token"] for record in path_records] == [
        "com.example.permission.PATH_READ",
        "com.example.permission.PATH_WRITE",
    ]
    assert all(record["semantic_claim"] == "ACCESS_CONTROL_REFERENCE" for record in records)
    assert len({record["provenance"]["evidence_locator"] for record in records}) == 7
    assert len({record["occurrence_evidence_digest"] for record in records}) == 7


def test_manifest_permission_occurrence_locators_distinguish_parent_components() -> None:
    manifest = ElementTree.fromstring(
        b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android">
          <application>
            <provider android:name=".FirstProvider">
              <path-permission android:path="/first"
                               android:readPermission="com.example.permission.SHARED"/>
            </provider>
            <provider android:name=".SecondProvider">
              <path-permission android:path="/second"
                               android:readPermission="com.example.permission.SHARED"/>
            </provider>
          </application>
        </manifest>"""
    )

    records = build_permission_occurrence_evidence(
        manifest,
        artifact_sha256="c" * 64,
        package_name="com.example.app",
        analysis_run_id="run-repeated-guards",
        producer_version="test",
        observed_at_utc="2026-09-13T12:30:45Z",
    )

    assert [record["provenance"]["evidence_locator"] for record in records] == [
        "/manifest/application[1]/provider[1]/path-permission[1]/@android:readPermission",
        "/manifest/application[1]/provider[2]/path-permission[1]/@android:readPermission",
    ]
    assert len({record["occurrence_evidence_digest"] for record in records}) == 2


def test_resolve_hashes_for_analysis_falls_back_when_metadata_provenance_breaks(
    monkeypatch,
    tmp_path: Path,
) -> None:
    apk_path = tmp_path / "fallback.apk"
    apk_path.write_bytes(b"fallback-apk")
    metadata = {
        "md5": "a" * 32,
        "sha1": "b" * 40,
        "sha256": "c" * 64,
        "file_size": apk_path.stat().st_size + 10,
    }
    expected_hashes = {
        "md5": "d" * 32,
        "sha1": "e" * 40,
        "sha256": "f" * 64,
    }

    monkeypatch.setattr(
        pipeline.artifact_store,
        "canonical_apk_path",
        lambda _sha256: apk_path,
    )
    monkeypatch.setattr(pipeline, "compute_hashes", lambda _path: expected_hashes)

    hashes, meta = pipeline._resolve_hashes_for_analysis(apk_path, metadata)

    assert hashes == expected_hashes
    assert meta["hash_source"] == "computed"
    assert meta["hash_recomputed"] is True
    assert meta["hash_provenance_ok"] is False
    assert meta["hash_provenance_reason"] == "file_size_mismatch"
    assert meta["content_sha256_matches_provenance"] is False


def test_resolve_hashes_accepts_sha256_provenance_without_legacy_digests(
    monkeypatch,
    tmp_path: Path,
) -> None:
    apk_path = tmp_path / "sha256-only.apk"
    apk_path.write_bytes(b"sha256-only")
    computed = {
        "md5": "a" * 32,
        "sha1": "b" * 40,
        "sha256": "c" * 64,
    }
    metadata = {
        "sha256": computed["sha256"],
        "file_size": apk_path.stat().st_size,
    }
    monkeypatch.setattr(pipeline.artifact_store, "canonical_apk_path", lambda _digest: apk_path)
    monkeypatch.setattr(pipeline, "compute_hashes", lambda _path: computed)

    hashes, meta = pipeline._resolve_hashes_for_analysis(apk_path, metadata)

    assert hashes == computed
    assert meta["hash_source"] == "computed"
    assert meta["hash_recomputed"] is True
    assert meta["hash_metadata_digest_set_complete"] is False
    assert meta["content_sha256_matches_provenance"] is True
    assert meta["hash_provenance_ok"] is True
    assert meta["hash_provenance_reason"] == "canonical_store_sha256_verified_after_recompute"


def test_analyze_apk_records_timing_metadata_and_cached_string_payload_for_split_and_base_artifacts(
    monkeypatch,
    tmp_path: Path,
) -> None:
    apk_path = tmp_path / "timed.apk"
    apk_path.write_bytes(b"timed-apk")

    class _FakePermissionCatalog:
        def to_snapshot(self, _declared: tuple[str, ...]) -> dict[str, object]:
            return {}

    class _FakeApk:
        def get_package(self) -> str:
            return "com.example.timed"

        def get_androidversion_name(self) -> str:
            return "1.0"

        def get_androidversion_code(self) -> str:
            return "100"

        def get_min_sdk_version(self) -> str:
            return "24"

        def get_target_sdk_version(self) -> str:
            return "35"

        def get_permissions(self) -> list[str]:
            return []

        def get_declared_permissions(self) -> list[str]:
            return []

        def get_activities(self) -> list[str]:
            return []

        def get_services(self) -> list[str]:
            return []

        def get_receivers(self) -> list[str]:
            return []

        def get_providers(self) -> list[str]:
            return []

        def get_features(self) -> list[str]:
            return []

        def get_libraries(self) -> list[str]:
            return []

        def get_signature_names(self) -> list[str]:
            return []

    fake_artifacts = SimpleNamespace(
        results=(),
        metrics={},
        trace=None,
        summary=None,
        reproducibility_bundle=None,
        matrices={},
        indicators={},
        workload={},
    )

    monkeypatch.setattr(
        pipeline,
        "_resolve_hashes_for_analysis",
        lambda _path, _metadata: (
            {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64},
            {
                "hash_source": "trusted_metadata",
                "hash_recomputed": False,
                "hash_provenance_ok": True,
                "hash_provenance_reason": "canonical_store_verified",
            },
        ),
    )
    monkeypatch.setattr(pipeline, "_load_apk_safely", lambda _path, _meta: _FakeApk())
    monkeypatch.setattr(pipeline, "load_manifest_root", lambda _apk: None)
    monkeypatch.setattr(pipeline, "build_manifest_flags", lambda _root: ManifestFlags())
    monkeypatch.setattr(pipeline, "extract_compile_sdk", lambda _root: None)
    monkeypatch.setattr(pipeline, "_safe_get_app_label", lambda _apk, _pkg, _meta: "Example")
    monkeypatch.setattr(pipeline, "_safe_get_main_activity", lambda _apk, _meta: None)
    monkeypatch.setattr(pipeline, "_safe_permission_details", lambda _apk, _meta: {})
    monkeypatch.setattr(pipeline, "collect_dangerous_permissions", lambda _details: ())
    monkeypatch.setattr(pipeline, "collect_custom_permission_definitions", lambda _root: {})
    monkeypatch.setattr(pipeline, "build_permission_occurrence_evidence", lambda *_a, **_k: ())
    monkeypatch.setattr(pipeline, "collect_exported_components", lambda _root: SimpleNamespace())
    monkeypatch.setattr(pipeline, "load_permission_catalog", lambda: _FakePermissionCatalog())
    monkeypatch.setattr(pipeline, "_safe_tuple", lambda _callable, _meta, _key: ())
    monkeypatch.setattr(pipeline, "extract_network_security_policy", lambda *_a, **_k: None)
    fake_index = StringIndex(
        strings=(
            IndexedString(value="const token", origin="classes.dex", origin_type="code"),
            IndexedString(value="https://example.com", origin="res/values/strings.xml", origin_type="resource"),
            IndexedString(value="libfoo", origin="lib/arm64-v8a/libfoo.so", origin_type="native"),
            IndexedString(value="config-value", origin="assets/config.json", origin_type="asset"),
        ),
        resource_bounds_warnings=("We are out of bound with this complex entry. Count: 65536",),
    )
    monkeypatch.setattr(pipeline, "build_string_index", lambda *_a, **_k: fake_index)

    string_payload_calls: list[dict[str, object]] = []

    def _fake_analyse_strings_from_index(*_args, **kwargs):
        string_payload_calls.append(dict(kwargs))
        return {"counts": {"endpoints": 1}, "samples": {}, "selected_samples": {}}

    monkeypatch.setattr(
        pipeline,
        "_analyse_strings_from_index",
        _fake_analyse_strings_from_index,
    )
    monkeypatch.setattr(pipeline, "build_detector_context", lambda **_kwargs: SimpleNamespace())
    monkeypatch.setattr(pipeline, "run_detector_pipeline", lambda _context: ())
    monkeypatch.setattr(pipeline, "assemble_pipeline_artifacts", lambda _context: fake_artifacts)

    for is_split_member in (False, True):
        report = pipeline.analyze_apk(
            apk_path,
            metadata={"is_split_member": is_split_member},
            storage_root=tmp_path,
        )

        assert report.metadata["hash_seconds"] >= 0.0
        assert report.metadata["string_index_seconds"] >= 0.0
        assert report.metadata["artifact_total_wall_s"] >= 0.0
        assert report.metadata["string_index_total_strings"] == 4
        assert report.metadata["string_index_by_origin_type"] == {
            "code": 1,
            "resource": 1,
            "native": 1,
            "asset": 1,
        }
        assert report.metadata["string_index_code_strings"] == 1
        assert report.metadata["string_index_resource_strings"] == 1
        assert report.metadata["string_index_native_strings"] == 1
        assert report.metadata["string_index_asset_strings"] == 1
        assert report.metadata["resource_bounds_warnings"] == [
            "We are out of bound with this complex entry. Count: 65536"
        ]
        assert report.metadata["parser_provenance"]["resource_bounds_warning_count"] == 1
        assert report.metadata["post_run_string_payload"] == {
            "counts": {"endpoints": 1},
            "samples": {},
            "selected_samples": {},
            "aggregation_scope": "single_artifact",
        }
        assert string_payload_calls[-1]["warnings"] == (
            "We are out of bound with this complex entry. Count: 65536",
        )
