from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from scytaledroid.StaticAnalysis.core.findings import Badge
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
    monkeypatch.setattr(splits, "list_reports", lambda: reports)

    related = splits._collect_related_reports(  # noqa: SLF001 - intentional contract test
        context=None,  # type: ignore[arg-type]
        split_id="72",
        current_sha="current-sha",
        package_name="com.example.app",
        capture_id="20260216",
    )

    assert len(related) == 1
    assert related[0].report.hashes["sha256"] == "same-capture"
