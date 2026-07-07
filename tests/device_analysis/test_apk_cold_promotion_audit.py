from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from scripts.device_analysis import audit_apk_cold_promotion as audit


def _lineage(*, sha: str, base_sha: str, version_code: str = "1", capture_key: str = "pkg|1|run") -> audit.ReceiptLineage:
    return audit.ReceiptLineage(
        sha256=sha,
        package_name="com.example.app",
        version_code=version_code,
        version_name="1.0",
        session_label="run",
        observed_at="2026-07-01T00:00:00Z",
        split_role="base" if sha == base_sha else "split",
        split_name="base" if sha == base_sha else "split_config.en",
        is_base=sha == base_sha,
        base_sha256=base_sha,
        capture_key=capture_key,
    )


def _deps(**overrides: object) -> audit.DependencyContext:
    defaults = {
        "cohort_key": "research_dataset_beta",
        "cohort_packages": {"com.example.app"},
        "current_installed_versions": {},
        "current_research_base_shas": set(),
        "current_research_capture_keys": set(),
        "paper_base_shas": set(),
        "paper_capture_keys": set(),
        "current_dynamic_base_shas": set(),
        "current_dynamic_capture_keys": set(),
        "active_dynamic_base_shas": set(),
        "active_dynamic_capture_keys": set(),
        "recent_static_base_shas": set(),
        "recent_static_capture_keys": set(),
        "static_by_base_sha": defaultdict(list),
        "dynamic_by_base_sha": defaultdict(list),
        "source_status": {
            "current_research_dataset_beta": "ok",
            "paper_freeze": "ok",
            "current_dynamic": "ok",
            "active_dynamic": "ok",
            "recent_static": "ok",
            "inventory": "ok",
        },
    }
    defaults.update(overrides)
    return audit.DependencyContext(**defaults)


def _classify(tmp_path: Path, *, deps: audit.DependencyContext, lineages: list[audit.ReceiptLineage]) -> audit.ColdPromotionRow:
    sha = lineages[0].sha256
    path = tmp_path / "data" / "store" / "apk" / "sha256" / sha[:2] / f"{sha}.apk"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"apk")
    return audit._classify_blob(
        path=path,
        sha=sha,
        cold_root=tmp_path / "cold",
        lineages=lineages,
        library=audit.LibraryIndex(),
        latest_by_package={},
        dependencies=deps,
    )


def test_current_research_capture_keeps_split_hot(tmp_path: Path) -> None:
    base = "a" * 64
    split = "b" * 64
    capture_key = "com.example.app|1|run"
    row = _classify(
        tmp_path,
        deps=_deps(current_research_base_shas={base}, current_research_capture_keys={capture_key}),
        lineages=[_lineage(sha=split, base_sha=base, capture_key=capture_key)],
    )

    assert row.referenced_by_current_research_dataset_beta == "yes"
    assert row.promotion_class == "KEEP_HOT_CURRENT_RESEARCH_DATASET_BETA"
    assert row.safe_to_promote is False


def test_prior_version_blob_promotes_when_dependencies_known_clear(tmp_path: Path) -> None:
    base = "c" * 64
    row = _classify(
        tmp_path,
        deps=_deps(),
        lineages=[_lineage(sha=base, base_sha=base, version_code="1")],
    )

    assert row.referenced_by_current_research_dataset_beta == "no"
    assert row.referenced_by_current_installed_build == "no"
    assert row.promotion_class == "PROMOTE_COLD_PRIOR_VERSION_CANDIDATE"
    assert row.safe_to_promote is True


def test_unknown_research_status_blocks_promotion(tmp_path: Path) -> None:
    base = "d" * 64
    row = _classify(
        tmp_path,
        deps=_deps(source_status={"current_research_dataset_beta": "unknown", "inventory": "ok"}),
        lineages=[_lineage(sha=base, base_sha=base)],
    )

    assert row.referenced_by_current_research_dataset_beta == "unknown"
    assert row.promotion_class == "BLOCKED_UNKNOWN_RESEARCH_STATUS"
    assert row.safe_to_promote is False


def test_output_writer_creates_expected_files(tmp_path: Path) -> None:
    audit_payload = {
        "mode": "read_only",
        "summary": {},
        "rows": [
            {
                "sha256": "e" * 64,
                "safe_to_promote": True,
                "package_name": "com.example.app",
            }
        ],
        "package_summary": [{"package_name": "com.example.app"}],
        "blocked": [],
    }

    paths = audit.write_outputs(audit_payload, tmp_path / "audit")

    assert Path(paths["summary_json"]).exists()
    assert Path(paths["candidates_csv"]).read_text(encoding="utf-8").startswith("sha256")
    assert Path(paths["package_summary_csv"]).exists()
    assert Path(paths["blocked_csv"]).exists()
