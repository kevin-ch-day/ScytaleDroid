from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.core.findings import Badge
from scytaledroid.StaticAnalysis.detectors.correlation import diffing
from scytaledroid.StaticAnalysis.detectors.correlation import splits
from scytaledroid.StaticAnalysis.detectors.correlation.detector import CorrelationDetector
from scytaledroid.StaticAnalysis.detectors.correlation.models import (
    DiffBundle,
    NetworkDiff,
    NetworkSnapshot,
)
from scytaledroid.StaticAnalysis.persistence.reports import StoredReport


def _dummy_snapshot() -> NetworkSnapshot:
    return NetworkSnapshot(
        base_cleartext=None,
        debug_cleartext=None,
        trust_user_certs=False,
        cleartext_domains=tuple(),
        pinned_domains=tuple(),
        http_hosts=tuple(),
        https_hosts=tuple(),
        policy_hash=None,
    )


def test_correlation_missing_baseline_is_warn_not_fail(monkeypatch):
    # Baseline missing should produce WARN with reason_codes and never FAIL by risk score.
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.detectors.correlation.detector.build_diff_bundle",
        lambda _ctx: DiffBundle(
            previous=None,
            new_exported={},
            new_permissions=tuple(),
            flipped_flags={},
            network_diff=NetworkDiff(),
        ),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.detectors.correlation.detector.current_network_snapshot",
        lambda _ctx: _dummy_snapshot(),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.detectors.correlation.detector.split_findings_and_metrics",
        lambda _ctx, _snap: (tuple(), {}),
    )
    # Force a "Critical" score, which previously caused correlation FAIL by construction.
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.detectors.correlation.detector.risk_score",
        lambda *_args, **_kwargs: {"score": 999, "grade": "Critical"},
    )

    ctx = SimpleNamespace(intermediate_results=tuple(), metadata={})
    result = CorrelationDetector().run(ctx)
    assert result.status is Badge.WARN
    assert "reason_codes" in (result.metrics or {})
    assert "not_applicable:baseline_missing" in (result.metrics or {}).get("reason_codes", [])

    risk = next((f for f in result.findings if f.finding_id == "risk_profile"), None)
    assert risk is not None
    assert risk.status is not Badge.FAIL
    assert risk.title.startswith("Correlation priority")
    assert risk.metrics["is_canonical_app_risk"] is False


def test_correlation_rule_violation_is_fail(monkeypatch, tmp_path):
    dummy_prev = SimpleNamespace(
        path=Path(tmp_path / "baseline.json"),
        report=SimpleNamespace(hashes={"sha256": "abc"}),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.detectors.correlation.detector.build_diff_bundle",
        lambda _ctx: DiffBundle(
            previous=dummy_prev,
            new_exported={},
            new_permissions=tuple(),
            flipped_flags={},
            network_diff=NetworkDiff(cleartext_flip=(False, True)),
        ),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.detectors.correlation.detector.current_network_snapshot",
        lambda _ctx: _dummy_snapshot(),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.detectors.correlation.detector.split_findings_and_metrics",
        lambda _ctx, _snap: (tuple(), {}),
    )
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.detectors.correlation.detector.risk_score",
        lambda *_args, **_kwargs: {"score": 0, "grade": "Informational"},
    )

    ctx = SimpleNamespace(intermediate_results=tuple(), metadata={})
    result = CorrelationDetector().run(ctx)
    assert result.status is Badge.FAIL
    assert "rule_failures" in (result.metrics or {})
    assert "corr_cleartext_enabled" in (result.metrics or {}).get("rule_failures", [])


def test_correlation_exception_is_error(monkeypatch):
    monkeypatch.setattr(
        "scytaledroid.StaticAnalysis.detectors.correlation.detector.build_diff_bundle",
        lambda _ctx: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    ctx = SimpleNamespace(intermediate_results=tuple(), metadata={})
    result = CorrelationDetector().run(ctx)
    assert result.status is Badge.ERROR
    assert "error" in (result.metrics or {})


def test_correlation_split_member_defers_to_base_artifact() -> None:
    ctx = SimpleNamespace(
        intermediate_results=tuple(),
        metadata={
            "is_split_member": True,
            "group_has_base_artifact": True,
            "group_artifact_total": 3,
        },
    )

    result = CorrelationDetector().run(ctx)

    assert result.status is Badge.SKIPPED
    assert "reason_codes" in (result.metrics or {})
    assert "deferred_to_base_artifact" in (result.metrics or {}).get("reason_codes", [])
    assert not result.findings


# =============================================================================
# Former tests/static_analysis/test_split_correlation_capture_boundary.py
# =============================================================================


@dataclass
class _SplitCaptureFakeManifest:
    package_name: str


@dataclass
class _SplitCaptureFakeReport:
    metadata: dict[str, object]
    hashes: dict[str, str]
    manifest: _SplitCaptureFakeManifest


def _split_capture_stored(*, package: str, capture: str, split: int, sha: str) -> StoredReport:
    report = _SplitCaptureFakeReport(
        metadata={
            "package_name": package,
            "session_stamp": capture,
            "split_group_id": split,
        },
        hashes={"sha256": sha},
        manifest=_SplitCaptureFakeManifest(package_name=package),
    )
    return StoredReport(path=Path(f"/tmp/{sha}.json"), report=report)  # type: ignore[arg-type]


def test_collect_related_reports_is_capture_bounded(monkeypatch) -> None:
    reports = [
        _split_capture_stored(package="com.example.app", capture="20260216", split=72, sha="same-capture"),
        _split_capture_stored(package="com.example.app", capture="20260215", split=72, sha="old-capture"),
        _split_capture_stored(package="com.other.app", capture="20260216", split=72, sha="other-package"),
    ]
    monkeypatch.setattr(
        splits,
        "reports_for_package",
        lambda package: [
            report
            for report in reports
            if report.report.manifest.package_name == package
        ],
    )

    related = splits._collect_related_reports(  # noqa: SLF001 - intentional contract test
        context=None,  # type: ignore[arg-type]
        split_id="72",
        current_sha="current-sha",
        package_name="com.example.app",
        capture_id="20260216",
    )

    assert len(related) == 1
    assert related[0].report.hashes["sha256"] == "same-capture"


def test_load_previous_report_ignores_same_session_siblings(monkeypatch, tmp_path: Path) -> None:
    same_session = _split_capture_stored(
        package="com.example.app",
        capture="sess-current",
        split=72,
        sha="1" * 64,
    )
    historical = _split_capture_stored(
        package="com.example.app",
        capture="sess-older",
        split=72,
        sha="2" * 64,
    )
    same_session.report.metadata.update({"version_name": "1.0", "version_code": "100"})
    historical.report.metadata.update({"version_name": "1.0", "version_code": "100"})
    same_session.report.manifest = _SplitCaptureFakeManifest(package_name="com.example.app")  # type: ignore[misc]
    historical.report.manifest = _SplitCaptureFakeManifest(package_name="com.example.app")  # type: ignore[misc]
    same_session.report.manifest.version_name = "1.0"  # type: ignore[attr-defined]
    same_session.report.manifest.version_code = "100"  # type: ignore[attr-defined]
    historical.report.manifest.version_name = "1.0"  # type: ignore[attr-defined]
    historical.report.manifest.version_code = "100"  # type: ignore[attr-defined]

    monkeypatch.setattr(diffing, "reports_for_package", lambda _package: [same_session, historical])

    context = SimpleNamespace(
        manifest_summary=SimpleNamespace(
            package_name="com.example.app",
            version_name="1.0",
            version_code="100",
        ),
        hashes={"sha256": "current" * 10 + "curr"},
        metadata={"session_stamp": "sess-current"},
        runtime_state={},
    )

    previous = diffing.load_previous_report(context)  # type: ignore[arg-type]

    assert previous is historical


def test_collect_related_reports_prefers_runtime_saved_split_cache(monkeypatch, tmp_path: Path) -> None:
    cached = _split_capture_stored(
        package="com.example.app",
        capture="20260216",
        split=72,
        sha="cached-sha",
    )

    def _unexpected_reports_for_package(_package: str):
        raise AssertionError("reports_for_package should not be consulted when runtime split cache is present")

    monkeypatch.setattr(splits, "reports_for_package", _unexpected_reports_for_package)

    context = SimpleNamespace(
        runtime_state={
            "saved_reports_by_split": {
                ("com.example.app", "20260216", "72"): [cached],
            }
        }
    )

    related = splits._collect_related_reports(  # noqa: SLF001 - intentional contract test
        context=context,  # type: ignore[arg-type]
        split_id="72",
        current_sha="different-sha",
        package_name="com.example.app",
        capture_id="20260216",
    )

    assert related == [cached]


def test_split_findings_reuse_cached_group_union_and_snapshots(monkeypatch) -> None:
    related = [
        StoredReport(
            path=Path("/tmp/rel-a.json"),
            report=SimpleNamespace(
                hashes={"sha256": "rel-a"},
                metadata={"artifact": "split_config.en"},
                exported_components=SimpleNamespace(
                    activities=("a.Activity",),
                    services=(),
                    receivers=(),
                    providers=(),
                ),
            ),
        ),
        StoredReport(
            path=Path("/tmp/rel-b.json"),
            report=SimpleNamespace(
                hashes={"sha256": "rel-b"},
                metadata={"artifact": "split_config.xhdpi"},
                exported_components=SimpleNamespace(
                    activities=(),
                    services=(),
                    receivers=(),
                    providers=(),
                ),
            ),
        ),
    ]

    snapshot_calls: list[str] = []
    snapshots = {
        "/tmp/rel-a.json": NetworkSnapshot(
            base_cleartext=None,
            debug_cleartext=None,
            trust_user_certs=False,
            cleartext_domains=tuple(),
            pinned_domains=tuple(),
            http_hosts=("a.example.com",),
            https_hosts=tuple(),
            policy_hash=None,
        ),
        "/tmp/rel-b.json": NetworkSnapshot(
            base_cleartext=None,
            debug_cleartext=None,
            trust_user_certs=False,
            cleartext_domains=("clear.example.com",),
            pinned_domains=tuple(),
            http_hosts=("b.example.com",),
            https_hosts=tuple(),
            policy_hash=None,
        ),
    }

    monkeypatch.setattr(splits, "_collect_related_reports", lambda *_a, **_k: related)

    def _fake_cached_previous(runtime_state, *, report_key: str, report):
        snapshot_calls.append(report_key)
        return snapshots[report_key]

    monkeypatch.setattr(splits, "cached_previous_network_snapshot", _fake_cached_previous)

    context = SimpleNamespace(
        metadata={
            "split_group_id": "72",
            "session_stamp": "sess-1",
            "artifact": "base",
        },
        hashes={"sha256": "current"},
        manifest_summary=SimpleNamespace(package_name="com.example.app"),
        exported_components=SimpleNamespace(
            activities=tuple(),
            services=tuple(),
            receivers=tuple(),
            providers=tuple(),
            total=lambda: 0,
        ),
        apk_path=Path("/tmp/current.apk"),
        runtime_state={},
    )
    current_snapshot = NetworkSnapshot(
        base_cleartext=None,
        debug_cleartext=None,
        trust_user_certs=False,
        cleartext_domains=tuple(),
        pinned_domains=tuple(),
        http_hosts=tuple(),
        https_hosts=tuple(),
        policy_hash=None,
    )

    findings_a, metrics_a = splits.split_findings_and_metrics(context, current_snapshot)
    findings_b, metrics_b = splits.split_findings_and_metrics(context, current_snapshot)

    assert len(snapshot_calls) == 2
    assert sorted(metrics_a["union_http_hosts"]) == ["a.example.com", "b.example.com"]
    assert sorted(metrics_b["union_http_hosts"]) == ["a.example.com", "b.example.com"]
    assert any(f.finding_id == "split_http_union" for f in findings_a)
    assert any(f.finding_id == "split_http_union" for f in findings_b)
