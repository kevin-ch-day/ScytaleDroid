from __future__ import annotations

import pathlib
import sys

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scytaledroid.Utils.DisplayUtils import colors


@pytest.fixture()
def force_color(monkeypatch):
    """Force ANSI colour output within tests that inspect styled strings."""

    monkeypatch.setenv("FORCE_COLOR", "1")
    colors.colors_enabled(force_refresh=True)
    yield
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    colors.colors_enabled(force_refresh=True)
