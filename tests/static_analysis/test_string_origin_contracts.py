from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scytaledroid.StaticAnalysis.detectors.native import NativeHardeningDetector
from scytaledroid.StaticAnalysis.modules.string_analysis import (
    IndexedString,
    StringIndex,
    build_string_index,
    extract_endpoints,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.indexing.sources import (
    classify_origin_type,
)
from scytaledroid.StaticAnalysis.modules.string_analysis.indexing.utils import StringFragment


def test_classify_origin_type_uses_canonical_labels() -> None:
    assert classify_origin_type("classes.dex") == "code"
    assert classify_origin_type("res/raw/config.json") == "raw"
    assert classify_origin_type("resources.arsc") == "resource"
    assert classify_origin_type("assets/index.android.bundle") == "rn_bundle"


def test_string_index_search_accepts_legacy_dex_alias() -> None:
    index = StringIndex(
        strings=(
            IndexedString(
                value="Authorization: Bearer abc123",
                origin="classes.dex",
                origin_type="dex",
            ),
        )
    )

    hits = index.search("Bearer", origin_types=("code",))

    assert len(hits) == 1
    assert hits[0].origin_type == "code"


def test_extract_endpoints_keeps_multiple_urls_from_same_literal() -> None:
    index = StringIndex(
        strings=(
            IndexedString(
                value="https://a.example/api https://b.example/pixel",
                origin="classes.dex",
                origin_type="code",
            ),
        )
    )

    matches = extract_endpoints(index)

    assert [match.url for match in matches] == [
        "https://a.example/api",
        "https://b.example/pixel",
    ]


class _FakeResources:
    def get_resolved_strings(self):
        return {
            "com.example.app": {
                "DEFAULT": {
                    1: "Hello from resources",
                    2: "https://api.example.test/v1",
                }
            }
        }


class _FakeApk:
    filename = "fake.apk"
    split_name = "base"

    def get_files(self):
        return ()

    def get_buff(self):
        return b"fake-apk"

    def get_android_resources(self):
        return _FakeResources()


class _WarningResources:
    def get_resolved_strings(self):
        print("We are out of bound with this complex entry. Count: 65536")
        return {
            "com.example.app": {
                "DEFAULT": {
                    1: "warning resource string",
                }
            }
        }


class _WarningApk(_FakeApk):
    filename = "warning.apk"

    def get_android_resources(self):
        return _WarningResources()


class _WarningContextApk(_WarningApk):
    filename = "warning-context.apk"


def test_build_string_index_enriches_resolved_resource_strings() -> None:
    index = build_string_index(_FakeApk(), include_resources=True)

    values = {entry.value for entry in index.strings}
    assert "Hello from resources" in values
    assert "https://api.example.test/v1" in values
    assert all(entry.origin_type == "resource" for entry in index.strings)
    assert all(entry.apk_offset_kind == "resource_table" for entry in index.strings)


def test_build_string_index_preserves_resource_bounds_warnings() -> None:
    index = build_string_index(_WarningApk(), include_resources=True)

    assert index.resource_bounds_warnings == (
        "We are out of bound with this complex entry. Count: 65536",
    )


def test_build_string_index_logs_resource_bounds_warning_context() -> None:
    with patch(
        "scytaledroid.StaticAnalysis.modules.string_analysis.indexing.builder.log.warning"
    ) as warning:
        build_string_index(
            _WarningContextApk(),
            include_resources=True,
            log_context={
                "execution_id": "exec-1",
                "session_stamp": "session-1",
                "package_name": "com.example.app",
                "sha256": "a" * 64,
            },
        )

    warning.assert_called_once()
    extra = warning.call_args.kwargs["extra"]
    assert extra["event"] == "strings.resource_bounds_warning"
    assert extra["execution_id"] == "exec-1"
    assert extra["session_stamp"] == "session-1"
    assert extra["package_name"] == "com.example.app"
    assert extra["sha256"] == "a" * 64


def test_build_string_index_respects_include_resources_false() -> None:
    index = build_string_index(_FakeApk(), include_resources=False)

    assert index.is_empty()


class _RawOnlyFakeApk:
    filename = "fake-raw.apk"
    split_name = "base"

    def get_files(self):
        return ("res/raw/config.json",)

    def get_file(self, name: str):
        assert name == "res/raw/config.json"
        return b'{"endpoint":"https://api.example.test/v1"}'

    def get_buff(self):
        return b"fake-raw-apk"

    def get_android_resources(self):
        return _FakeResources()


def test_build_string_index_include_resources_false_keeps_raw_file_entries() -> None:
    index = build_string_index(_RawOnlyFakeApk(), include_resources=False)

    values = {entry.value for entry in index.strings}
    origins = {entry.origin_type for entry in index.strings}

    assert any("https://api.example.test/v1" in value for value in values)
    assert "raw" in origins
    assert "resource" not in origins


class _SplitAwareFakeApk:
    filename = "split_config.arm64_v8a.apk"
    split_name = "split_config.arm64_v8a"

    def __init__(self) -> None:
        self._files = {
            "lib/arm64-v8a/libfoo.so": b"\x00native-token\x00unused-secret\x00",
            "assets/blob.bin": b"\x00binary-noise\x00not-text\x01\x02",
            "assets/config.json": b'{"endpoint":"https://api.example.test/v1"}',
        }

    def get_files(self):
        return tuple(self._files)

    def get_file(self, name: str):
        return self._files[name]

    def get_buff(self):
        return b"fake-split-apk"

    def get_android_resources(self):
        return _FakeResources()


def test_build_string_index_split_lightweight_skips_native_binary_and_resources() -> None:
    apk = _SplitAwareFakeApk()

    def _binary_fragments(_blob: bytes):
        return (StringFragment(value="native-token", start=1, end=13),)

    with patch(
        "scytaledroid.StaticAnalysis.modules.string_analysis.indexing.sources.strings_from_binary",
        side_effect=_binary_fragments,
    ):
        index = build_string_index(
            apk,
            include_resources=True,
            is_split_member=True,
            split_member_policy="lightweight",
        )

    values = {entry.value for entry in index.strings}
    origins = {entry.origin for entry in index.strings}

    assert "native-token" not in values
    assert "Hello from resources" not in values
    assert any("https://api.example.test/v1" in value for value in values)
    assert "binary-noise" not in values
    assert "lib/arm64-v8a/libfoo.so" not in origins


def test_build_string_index_base_apk_keeps_full_native_and_resource_path() -> None:
    apk = _SplitAwareFakeApk()

    def _binary_fragments(_blob: bytes):
        return (StringFragment(value="native-token", start=1, end=13),)

    with patch(
        "scytaledroid.StaticAnalysis.modules.string_analysis.indexing.sources.strings_from_binary",
        side_effect=_binary_fragments,
    ):
        index = build_string_index(
            apk,
            include_resources=True,
            is_split_member=False,
            split_member_policy="lightweight",
        )

    values = {entry.value for entry in index.strings}

    assert "native-token" in values
    assert "Hello from resources" in values


class _NativeDetectorFakeApk:
    def __init__(self, blob: bytes) -> None:
        self._blob = blob

    def get_files(self):
        return ("lib/arm64-v8a/libtarget.so",)

    def get_file(self, name: str):
        if name != "lib/arm64-v8a/libtarget.so":
            raise FileNotFoundError(name)
        return self._blob


def test_native_detector_uses_string_index_for_suspicious_hits() -> None:
    detector = NativeHardeningDetector()
    context = SimpleNamespace(
        apk=_NativeDetectorFakeApk(b"A" * 32768),
        apk_path=Path("/tmp/example.apk"),
        string_index=StringIndex(
            strings=(
                IndexedString(
                    value="frida detection enabled",
                    origin="lib/arm64-v8a/libtarget.so",
                    origin_type="native",
                ),
            )
        ),
    )

    result = detector.run(context)

    assert result.metrics["suspicious_hits"] == 1
    assert result.metrics["suspicious_scan_source"] == "string_index"
    assert result.findings


def test_native_detector_falls_back_to_sample_scan_without_string_index() -> None:
    detector = NativeHardeningDetector()
    context = SimpleNamespace(
        apk=_NativeDetectorFakeApk(b"prefix-frida-suffix" * 4096),
        apk_path=Path("/tmp/example.apk"),
        string_index=None,
    )

    result = detector.run(context)

    assert result.metrics["suspicious_hits"] >= 1
    assert result.metrics["suspicious_scan_source"] == "binary_fallback"
    assert result.findings
