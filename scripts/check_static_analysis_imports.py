"""Quick sanity checks for static-analysis import wiring."""

from __future__ import annotations

from pathlib import Path
import sys


def main() -> None:
    """Ensure shim and pipeline modules can be imported together."""

    project_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(project_root))

    from scytaledroid.StaticAnalysis import _androguard
    from scytaledroid.StaticAnalysis.core import pipeline

    assert hasattr(_androguard, "APK"), "APK missing from androguard shim"
    assert hasattr(pipeline, "APK"), "APK not re-exported in pipeline scope"


if __name__ == "__main__":
    main()
