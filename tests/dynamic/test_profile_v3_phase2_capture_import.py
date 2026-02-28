from __future__ import annotations


def test_profile_v3_phase2_capture_import_has_path() -> None:
    # Regression test: guided capture must not crash due to missing imports.
    from pathlib import Path as _Path

    import scytaledroid.DynamicAnalysis.controllers.profile_v3_phase2_capture as mod

    assert hasattr(mod, "run_profile_v3_capture_menu")
    # Path should be importable in the module namespace (defensive against NameError regressions).
    assert getattr(mod, "Path") is _Path

