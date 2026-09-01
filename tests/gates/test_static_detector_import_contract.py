from __future__ import annotations

import subprocess
import sys

import pytest

pytestmark = [pytest.mark.gate, pytest.mark.tier3]


def test_sdk_detector_imports_in_clean_interpreter() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from scytaledroid.StaticAnalysis.detectors.sdks "
                "import SdkInventoryDetector; print(SdkInventoryDetector.detector_id)"
            ),
        ],
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip() == "sdk_inventory"
