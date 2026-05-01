from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scytaledroid.StaticAnalysis.detectors.correlation import splits
from scytaledroid.StaticAnalysis.persistence.reports import StoredReport


@dataclass
class _FakeManifest:
    package_name: str


@dataclass
class _FakeReport:
    metadata: dict[str, object]
    hashes: dict[str, str]
    manifest: _FakeManifest


def _stored(*, package: str, capture: str, split: int, sha: str) -> StoredReport:
    report = _FakeReport(
        metadata={
            "package_name": package,
            "session_stamp": capture,
            "split_group_id": split,
        },
        hashes={"sha256": sha},
        manifest=_FakeManifest(package_name=package),
    )
    return StoredReport(path=Path(f"/tmp/{sha}.json"), report=report)  # type: ignore[arg-type]


def test_collect_related_reports_is_capture_bounded(monkeypatch) -> None:
    reports = [
        _stored(package="com.example.app", capture="20260216", split=72, sha="same-capture"),
        _stored(package="com.example.app", capture="20260215", split=72, sha="old-capture"),
        _stored(package="com.other.app", capture="20260216", split=72, sha="other-package"),
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
