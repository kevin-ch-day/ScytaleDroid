from __future__ import annotations

import json
import subprocess


def test_import_latency_under_threshold():
    cp = subprocess.run(["./run.sh", "--diag", "--json"], capture_output=True, text=True)
    assert cp.returncode == 0, cp.stderr or cp.stdout
    payload = json.loads(cp.stdout)

    timings = payload.get("timings", {})
    import_ms = timings.get("import_ms", 0)
    menu_init_ms = timings.get("menu_init_ms", 0)

    assert import_ms < 1500, f"import too slow: {import_ms}ms"
    assert menu_init_ms < 800, f"menu init too slow: {menu_init_ms}ms"
