from __future__ import annotations

import pytest

from scytaledroid.Api import runtime


def test_require_api_key_configured_returns_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCYTALEDROID_API_KEY", "test-secret")
    assert runtime._require_api_key_configured() == "test-secret"


def test_require_api_key_configured_raises_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SCYTALEDROID_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SCYTALEDROID_API_KEY is required"):
        runtime._require_api_key_configured()
