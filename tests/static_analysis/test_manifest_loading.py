from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock
from xml.etree import ElementTree

import pytest
from scytaledroid.StaticAnalysis.core import pipeline
from scytaledroid.StaticAnalysis.core.errors import StaticAnalysisError
from scytaledroid.StaticAnalysis.core.manifest_utils import load_manifest_root


def test_missing_decoded_manifest_is_an_explicit_analysis_failure() -> None:
    apk = SimpleNamespace(get_android_manifest_xml=lambda: None)

    with pytest.raises(StaticAnalysisError, match="Decoded AndroidManifest.xml unavailable"):
        load_manifest_root(apk)


@pytest.mark.parametrize(
    "xml",
    [
        '<manifest package="example"><application /></manifest>',
        b'<manifest package="example"><application /></manifest>',
        bytearray(b'<manifest package="example"><application /></manifest>'),
        ElementTree.fromstring('<manifest package="example"><application /></manifest>'),
    ],
)
def test_available_manifest_keeps_its_parsed_content(xml) -> None:
    root = load_manifest_root(SimpleNamespace(get_android_manifest_xml=lambda: xml))

    assert root.tag == "manifest"
    assert root.get("package") == "example"
    assert root.find("application") is not None


@pytest.mark.parametrize("xml", [b"", b"<manifest>"])
def test_malformed_manifest_remains_a_parse_failure(xml: bytes) -> None:
    with pytest.raises(StaticAnalysisError, match="Malformed AndroidManifest.xml") as failure:
        load_manifest_root(SimpleNamespace(get_android_manifest_xml=lambda: xml))

    assert isinstance(failure.value.__cause__, ElementTree.ParseError)


def test_missing_decoded_manifest_stops_before_string_collection(monkeypatch, tmp_path) -> None:
    apk_path = tmp_path / "inert.apk"
    apk_path.write_bytes(b"inert test input")
    monkeypatch.setattr(
        pipeline, "_resolve_hashes_for_analysis", lambda *_: ({"sha256": "a" * 64}, {})
    )
    monkeypatch.setattr(pipeline, "configure_third_party_loggers", lambda **_: None)
    monkeypatch.setattr(pipeline, "_resolve_toolchain_versions", lambda: {})
    monkeypatch.setattr(
        pipeline,
        "_load_apk_safely",
        lambda *_: SimpleNamespace(get_android_manifest_xml=lambda: None),
    )
    collector = Mock(side_effect=AssertionError("unavailable manifest must stop the pipeline"))
    monkeypatch.setattr(pipeline, "build_string_index", collector)

    with pytest.raises(StaticAnalysisError, match="Decoded AndroidManifest.xml unavailable"):
        pipeline.analyze_apk(apk_path)

    collector.assert_not_called()
