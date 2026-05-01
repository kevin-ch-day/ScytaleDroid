from __future__ import annotations

import importlib.util

import pytest


def require_fastapi_testclient():
    """Return FastAPI testclient module or skip when optional deps are missing."""
    if importlib.util.find_spec("httpx") is None:
        pytest.skip("httpx is required for fastapi.testclient")
    return pytest.importorskip("fastapi.testclient")
