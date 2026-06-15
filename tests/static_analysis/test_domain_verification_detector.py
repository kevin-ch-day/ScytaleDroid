from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree

from scytaledroid.StaticAnalysis.core.findings import Badge
from scytaledroid.StaticAnalysis.detectors.domain_verification import DomainVerificationDetector

_MANIFEST_NS = "http://schemas.android.com/apk/res/android"


def _manifest_root(manifest_body: str) -> ElementTree.Element:
    return ElementTree.fromstring(
        f'<manifest xmlns:android="{_MANIFEST_NS}" package="com.example.app">{manifest_body}</manifest>'
    )


def test_domain_verification_detector_reports_clean_when_no_deep_links() -> None:
    detector = DomainVerificationDetector()
    context = SimpleNamespace(
        apk_path=Path("dummy.apk"),
        manifest_root=_manifest_root(
            """
            <application>
              <activity android:name=".MainActivity" />
            </application>
            """
        ),
    )

    result = detector.run(context)  # type: ignore[arg-type]

    assert result.status is Badge.OK
    assert result.findings == ()
    assert result.metrics["Filter counts"]["web_link_filters"] == 0


def test_domain_verification_detector_warns_when_web_links_lack_autoverify() -> None:
    detector = DomainVerificationDetector()
    context = SimpleNamespace(
        apk_path=Path("dummy.apk"),
        manifest_root=_manifest_root(
            """
            <application>
              <activity android:name=".NewsActivity">
                <intent-filter>
                  <action android:name="android.intent.action.VIEW" />
                  <category android:name="android.intent.category.DEFAULT" />
                  <category android:name="android.intent.category.BROWSABLE" />
                  <data android:scheme="https" android:host="news.example.com" />
                </intent-filter>
              </activity>
            </application>
            """
        ),
    )

    result = detector.run(context)  # type: ignore[arg-type]

    assert result.status is Badge.WARN
    ids = {finding.finding_id for finding in result.findings}
    assert "domain_verification_missing_autoverify" in ids
    assert result.metrics["Filter counts"]["web_link_filters"] == 1
    assert "news.example.com" in result.metrics["Hosts"]


def test_domain_verification_detector_warns_for_misconfigured_autoverify_and_uppercase_manifest_values() -> None:
    detector = DomainVerificationDetector()
    context = SimpleNamespace(
        apk_path=Path("dummy.apk"),
        manifest_root=_manifest_root(
            """
            <application>
              <activity android:name=".DeepLinkActivity">
                <intent-filter android:autoVerify="true">
                  <action android:name="android.intent.action.VIEW" />
                  <category android:name="android.intent.category.BROWSABLE" />
                  <data android:scheme="HTTPS" android:host="News.Example.com" />
                </intent-filter>
              </activity>
            </application>
            """
        ),
    )

    result = detector.run(context)  # type: ignore[arg-type]

    ids = {finding.finding_id for finding in result.findings}
    assert result.status is Badge.WARN
    assert "domain_verification_misconfigured_autoverify" in ids
    assert "domain_verification_case_sensitive_manifest_values" in ids
    assert any("case-sensitive" in note for note in result.notes)


def test_domain_verification_detector_reports_verified_host_candidates() -> None:
    detector = DomainVerificationDetector()
    context = SimpleNamespace(
        apk_path=Path("dummy.apk"),
        manifest_root=_manifest_root(
            """
            <application>
              <activity android:name=".VerifiedLinkActivity">
                <intent-filter android:autoVerify="true">
                  <action android:name="android.intent.action.VIEW" />
                  <category android:name="android.intent.category.DEFAULT" />
                  <category android:name="android.intent.category.BROWSABLE" />
                  <data android:scheme="https" android:host="mobile.example.com" />
                  <data android:scheme="http" />
                </intent-filter>
              </activity>
            </application>
            """
        ),
    )

    result = detector.run(context)  # type: ignore[arg-type]

    assert result.status is Badge.INFO
    assert result.metrics["Filter counts"]["eligible_verified_filters"] == 1
    assert result.metrics["surface"]["eligible_verified_hosts"] == ["mobile.example.com"]
    assert any("Digital Asset Links" in note for note in result.notes)
