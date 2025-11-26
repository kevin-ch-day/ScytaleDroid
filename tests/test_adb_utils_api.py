from scytaledroid.DeviceAnalysis import adb_utils


def test_run_shell_exists():
    run_shell = getattr(adb_utils, "run_shell", None)
    assert callable(run_shell)
