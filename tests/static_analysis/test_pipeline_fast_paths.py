from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.core import pipeline
from scytaledroid.StaticAnalysis.core.models import ManifestFlags


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


def test_analyze_apk_records_timing_metadata_and_cached_base_string_payload(
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
    monkeypatch.setattr(pipeline, "collect_exported_components", lambda _root: SimpleNamespace())
    monkeypatch.setattr(pipeline, "load_permission_catalog", lambda: _FakePermissionCatalog())
    monkeypatch.setattr(pipeline, "_safe_tuple", lambda _callable, _meta, _key: ())
    monkeypatch.setattr(pipeline, "extract_network_security_policy", lambda *_a, **_k: None)
    monkeypatch.setattr(pipeline, "build_string_index", lambda *_a, **_k: SimpleNamespace(strings=[]))
    monkeypatch.setattr(
        pipeline,
        "_analyse_strings_from_index",
        lambda *_a, **_k: {"counts": {"endpoints": 1}, "samples": {}, "selected_samples": {}},
    )
    monkeypatch.setattr(pipeline, "build_detector_context", lambda **_kwargs: SimpleNamespace())
    monkeypatch.setattr(pipeline, "run_detector_pipeline", lambda _context: ())
    monkeypatch.setattr(pipeline, "assemble_pipeline_artifacts", lambda _context: fake_artifacts)

    report = pipeline.analyze_apk(apk_path, metadata={"is_split_member": False}, storage_root=tmp_path)

    assert report.metadata["hash_seconds"] >= 0.0
    assert report.metadata["string_index_seconds"] >= 0.0
    assert report.metadata["artifact_total_wall_s"] >= 0.0
    assert report.metadata["post_run_string_payload"] == {
        "counts": {"endpoints": 1},
        "samples": {},
        "selected_samples": {},
    }
