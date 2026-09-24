from __future__ import annotations

from scytaledroid.DeviceAnalysis.apk_label import parse_application_label
from scytaledroid.DeviceAnalysis.apk_signing import (
    extract_apk_cert_sha256,
    parse_apksigner_cert_sha256,
)


def test_parse_apksigner_prefers_numbered_signer_one() -> None:
    text = """
Signer #1 certificate DN: CN=Android
Signer #1 certificate SHA-256 digest: 521bf5ce7c981faba4ebd86d23f778885537cad021bc107d8915d005e99f4a12
Source Stamp Signer certificate SHA-256 digest: 3257d599a49d2c961a471ca9843f59d341a405884583fc087df4237b733bbd6d
"""
    assert (
        parse_apksigner_cert_sha256(text)
        == "521bf5ce7c981faba4ebd86d23f778885537cad021bc107d8915d005e99f4a12"
    )


def test_parse_apksigner_uses_lineage_signer_covering_device_sdk() -> None:
    text = """
Signer (minSdkVersion=33, maxSdkVersion=2147483647) certificate SHA-256 digest: 911d604446084ca7f4760b775bfc160fa8702441240a7258645d7a72c4312d27
Signer (minSdkVersion=24, maxSdkVersion=32) certificate SHA-256 digest: e3f9e1e0cf99d0e56a055ba65e241b3399f7cea524326b0cdd6ec1327ed0fdc1
Source Stamp Signer certificate SHA-256 digest: 3257d599a49d2c961a471ca9843f59d341a405884583fc087df4237b733bbd6d
"""
    assert (
        parse_apksigner_cert_sha256(text, device_sdk=35)
        == "911d604446084ca7f4760b775bfc160fa8702441240a7258645d7a72c4312d27"
    )


def test_parse_apksigner_prefers_lineage_over_numbered_signer_one() -> None:
    text = """
Signer #1 certificate SHA-256 digest: e3f9e1e0cf99d0e56a055ba65e241b3399f7cea524326b0cdd6ec1327ed0fdc1
Signer (minSdkVersion=33, maxSdkVersion=2147483647) certificate SHA-256 digest: 911d604446084ca7f4760b775bfc160fa8702441240a7258645d7a72c4312d27
Signer (minSdkVersion=24, maxSdkVersion=32) certificate SHA-256 digest: e3f9e1e0cf99d0e56a055ba65e241b3399f7cea524326b0cdd6ec1327ed0fdc1
"""
    assert (
        parse_apksigner_cert_sha256(text, device_sdk=35)
        == "911d604446084ca7f4760b775bfc160fa8702441240a7258645d7a72c4312d27"
    )


def test_extract_apk_cert_sha256_skips_non_zip(tmp_path) -> None:
    junk = tmp_path / "not.apk"
    junk.write_bytes(b"apk-bytes")
    assert extract_apk_cert_sha256(junk) is None


def test_parse_application_label_prefers_unlocalized_and_rejects_package() -> None:
    text = """
package: name='com.example.app' versionCode='1'
application-label:'Example'
application-label-en:'Example EN'
"""
    assert parse_application_label(text, package_name="com.example.app") == "Example"
    assert (
        parse_application_label(
            "application-label:'com.example.app'", package_name="com.example.app"
        )
        is None
    )
