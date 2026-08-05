"""Cross-cutting infra contracts (merged from former tiny ``tests/unit`` modules).

Former files: ``test_db_transient_errno``, ``test_numpy_percentile_wrapper``,
``test_api_runtime_require_key``, ``test_toolchain_versions``,
``test_publication_ordering_lookup``.
"""

from __future__ import annotations

import pytest
from scytaledroid.Api import runtime
from scytaledroid.Database.db_core import db_engine

# --- db_engine transient errno ---


def test_transient_errno_includes_mysql_disconnect_timeouts() -> None:
    assert 2013 in db_engine.TRANSIENT_ERRNOS
    assert 2014 in db_engine.TRANSIENT_ERRNOS


# --- numpy percentile wrapper ---


def test_numpy_percentile_wrapper_matches_explicit_method() -> None:
    import numpy as np
    from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as config
    from scytaledroid.DynamicAnalysis.ml.numpy_percentile import percentile

    arr = np.asarray([0.0, 1.0, 2.0, 3.0, 100.0], dtype=float)
    want = np.percentile(arr, 95.0, method=config.NP_PERCENTILE_METHOD)
    got = percentile(arr, 95.0, method=config.NP_PERCENTILE_METHOD)
    assert float(got) == float(want)


# --- API runtime key ---


def test_require_api_key_configured_returns_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SCYTALEDROID_API_AUTH_DISABLED", raising=False)
    monkeypatch.setenv("SCYTALEDROID_API_KEY", "test-secret")
    assert runtime._require_api_key_configured() == "test-secret"


def test_require_api_key_configured_raises_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SCYTALEDROID_API_AUTH_DISABLED", raising=False)
    monkeypatch.delenv("SCYTALEDROID_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SCYTALEDROID_API_KEY is required"):
        runtime._require_api_key_configured()


def test_direct_api_tls_requires_existing_cert_and_key_files(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    certfile = tmp_path / "api.crt"
    keyfile = tmp_path / "api.key"
    certfile.write_text("certificate", encoding="utf-8")
    keyfile.write_text("key", encoding="utf-8")
    monkeypatch.setenv("SCYTALEDROID_API_TLS_CERTFILE", str(certfile))
    monkeypatch.setenv("SCYTALEDROID_API_TLS_KEYFILE", str(keyfile))

    assert runtime._resolve_tls_options("0.0.0.0") == {
        "ssl_certfile": str(certfile),
        "ssl_keyfile": str(keyfile),
    }

    keyfile.unlink()
    with pytest.raises(RuntimeError, match="TLS file"):
        runtime._resolve_tls_options("0.0.0.0")


# --- toolchain versions ---


def test_gather_toolchain_versions_shape() -> None:
    from scytaledroid.Utils.toolchain_versions import gather_toolchain_versions

    tc = gather_toolchain_versions()
    assert isinstance(tc, dict)
    assert "python" in tc
    assert "packages" in tc
    assert "tools" in tc
    assert "platform" in tc
    assert isinstance(tc["packages"], dict)
    # numpy should be present in the environment for this project.
    assert tc["packages"].get("numpy")


# --- publication / profile ordering ---


def test_profile_v2_ordering_prefers_publication_and_falls_back(monkeypatch) -> None:
    from scytaledroid.DynamicAnalysis.tools.evidence import menu as evidence_menu

    responses = {
        "publication": ["com.example.publication"],
        "paper2": ["com.example.legacy"],
    }

    monkeypatch.setattr(
        "scytaledroid.Database.db_func.apps.app_ordering.fetch_ordering",
        lambda key: responses.get(key, []),
    )

    assert evidence_menu._fetch_profile_v2_ordering_db() == ["com.example.publication"]

    responses["publication"] = []
    assert evidence_menu._fetch_profile_v2_ordering_db() == ["com.example.legacy"]
