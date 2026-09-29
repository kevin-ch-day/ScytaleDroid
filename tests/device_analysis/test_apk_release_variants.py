from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from scripts.device_analysis import report_apk_release_variants as release_variants


def _write_report(
    data_root: Path,
    *,
    package_name: str,
    version_code: str,
    content: bytes,
) -> tuple[str, Path]:
    digest = sha256(content).hexdigest()
    apk_path = data_root / "store" / "apk" / "sha256" / digest[:2] / f"{digest}.apk"
    apk_path.parent.mkdir(parents=True, exist_ok=True)
    apk_path.write_bytes(content)
    report_path = data_root / "static_analysis" / "reports" / "latest" / f"{digest}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(
            {
                "metadata": {
                    "artifact": "base",
                    "canonical_store_path": apk_path.relative_to(data_root.parent).as_posix(),
                    "package_name": package_name,
                    "sha256": digest,
                    "version_code": version_code,
                }
            }
        ),
        encoding="utf-8",
    )
    return digest, apk_path


def test_same_signer_distinct_bytes_are_multiple_release_variants(
    tmp_path: Path, monkeypatch
) -> None:
    data_root = tmp_path / "repo" / "data"
    first_digest, _ = _write_report(
        data_root,
        package_name="com.example.app",
        version_code="42",
        content=b"first apk",
    )
    second_digest, _ = _write_report(
        data_root,
        package_name="com.example.app",
        version_code="42",
        content=b"second apk",
    )
    monkeypatch.setattr(
        "scytaledroid.DeviceAnalysis.apk_signing.extract_apk_cert_sha256",
        lambda _path, *, device_sdk: "a" * 64,
    )

    report = release_variants.build_report(data_root=data_root, write_outputs=False)

    assert report["summary"]["repeated_release_group_count"] == 1
    assert report["summary"]["disposition_counts"] == {"MULTIPLE_RELEASE_VARIANTS": 1}
    assert report["groups"] == [
        {
            "package_name": "com.example.app",
            "version_code": "42",
            "distinct_apk_count": 2,
            "distinct_signer_count": 1,
            "disposition": "MULTIPLE_RELEASE_VARIANTS",
            "sha256_values": sorted([first_digest, second_digest]),
            "signer_sha256_values": ["a" * 64],
        }
    ]
    assert all(row["byte_status"] == "verified" for row in report["artifacts"])


def test_different_signers_require_review_and_package_filter_excludes_other_groups(
    tmp_path: Path, monkeypatch
) -> None:
    data_root = tmp_path / "repo" / "data"
    first_digest, _ = _write_report(
        data_root,
        package_name="com.example.target",
        version_code="7",
        content=b"target one",
    )
    second_digest, _ = _write_report(
        data_root,
        package_name="com.example.target",
        version_code="7",
        content=b"target two",
    )
    _write_report(
        data_root,
        package_name="com.example.other",
        version_code="1",
        content=b"other one",
    )
    _write_report(
        data_root,
        package_name="com.example.other",
        version_code="1",
        content=b"other two",
    )
    signers = {first_digest: "1" * 64, second_digest: "2" * 64}

    def signer(path: Path, *, device_sdk: int) -> str:
        assert device_sdk == 36
        return signers[path.stem]

    monkeypatch.setattr(
        "scytaledroid.DeviceAnalysis.apk_signing.extract_apk_cert_sha256", signer
    )

    report = release_variants.build_report(
        data_root=data_root,
        package_name="com.example.target",
        version_code="7",
        device_sdk=36,
        write_outputs=False,
    )

    assert report["summary"]["repeated_release_group_count"] == 1
    assert report["summary"]["disposition_counts"] == {"SIGNER_DIVERGENCE_REVIEW": 1}
    assert report["groups"][0]["distinct_signer_count"] == 2


def test_missing_blob_is_fail_closed(tmp_path: Path, monkeypatch) -> None:
    data_root = tmp_path / "repo" / "data"
    _write_report(
        data_root,
        package_name="com.example.app",
        version_code="42",
        content=b"present apk",
    )
    missing_digest = "f" * 64
    report_path = data_root / "static_analysis" / "reports" / "latest" / f"{missing_digest}.json"
    report_path.write_text(
        json.dumps(
            {
                "metadata": {
                    "artifact": "base",
                    "package_name": "com.example.app",
                    "sha256": missing_digest,
                    "version_code": "42",
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "scytaledroid.DeviceAnalysis.apk_signing.extract_apk_cert_sha256",
        lambda _path, *, device_sdk: "a" * 64,
    )

    report = release_variants.build_report(data_root=data_root, write_outputs=False)

    assert report["groups"][0]["disposition"] == "BYTE_EVIDENCE_INCOMPLETE"
    assert {row["byte_status"] for row in report["artifacts"]} == {"missing", "verified"}
