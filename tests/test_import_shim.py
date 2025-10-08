from __future__ import annotations
import importlib.util as u
import pathlib
import sys
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

def _has_androguard() -> bool:
    return u.find_spec("androguard") is not None

@pytest.mark.skipif(not _has_androguard(), reason="androguard not installed")
def test_shim_and_pipeline_imports():
    top = u.find_spec("scytaledroid.StaticAnalysis._androguard")
    assert top is not None, "Canonical shim spec should resolve"

    core = u.find_spec("scytaledroid.StaticAnalysis.core._androguard")
    assert core is None, "No shim should exist under core/"

    from scytaledroid.StaticAnalysis._androguard import APK, FileNotPresent  # noqa: F401
    import scytaledroid.StaticAnalysis.core.pipeline as pipeline  # noqa: F401
